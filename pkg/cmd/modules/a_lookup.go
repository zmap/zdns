/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package modules

import (
	"errors"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"
	"net"
	"strings"
)

// DoTargetedLookup performs a lookup of the given domain name against the given nameserver, looking up both IPv4 and IPv6 addresses
// Will follow CNAME records as well as A/AAAA records to get IP addresses
func DoTargetedLookup(r *zdns.Resolver, name, nameServer string, lookupIpv4 bool, lookupIpv6 bool) (*zdns.IPResult, zdns.Trace, zdns.Status, error) {
	name = strings.ToLower(name)
	res := zdns.IPResult{}
	candidateSet := map[string][]zdns.Answer{}
	cnameSet := map[string][]zdns.Answer{}
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace zdns.Trace
	var ipv6Trace zdns.Trace
	var ipv4status zdns.Status
	var ipv6status zdns.Status

	if lookupIpv4 {
		ipv4, ipv4Trace, ipv4status, _ = recursiveIPLookup(r, name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0)
		if len(ipv4) > 0 {
			ipv4 = zdns.Unique(ipv4)
			res.IPv4Addresses = make([]string, len(ipv4))
			copy(res.IPv4Addresses, ipv4)
		}
	}
	candidateSet = map[string][]zdns.Answer{}
	cnameSet = map[string][]zdns.Answer{}
	if lookupIpv6 {
		ipv6, ipv6Trace, ipv6status, _ = recursiveIPLookup(r, name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0)
		if len(ipv6) > 0 {
			ipv6 = zdns.Unique(ipv6)
			res.IPv6Addresses = make([]string, len(ipv6))
			copy(res.IPv6Addresses, ipv6)
		}
	}

	combinedTrace := append(ipv4Trace, ipv6Trace...)

	// In case we get no IPs and a non-NOERROR status from either
	// IPv4 or IPv6 lookup, we return that status.
	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		if lookupIpv4 && !zdns.SafeStatus(ipv4status) {
			return nil, combinedTrace, ipv4status, nil
		} else if lookupIpv6 && !zdns.SafeStatus(ipv6status) {
			return nil, combinedTrace, ipv6status, nil
		} else {
			return &res, combinedTrace, zdns.STATUS_NOERROR, nil
		}
	}
	return &res, combinedTrace, zdns.STATUS_NOERROR, nil
}

// recursiveIPLookup helper fn that recursively follows both A/AAAA records and CNAME records to find IP addresses
// returns an array of IP addresses, a trace of the lookups, a status, and an error
func recursiveIPLookup(r *zdns.Resolver, name string, nameServer string, dnsType uint16, candidateSet map[string][]zdns.Answer, cnameSet map[string][]zdns.Answer, origName string, depth int) ([]string, zdns.Trace, zdns.Status, error) {
	// avoid infinite loops
	if name == origName && depth != 0 {
		return nil, make(zdns.Trace, 0), zdns.STATUS_ERROR, errors.New("infinite redirection loop")
	}
	if depth > 10 {
		return nil, make(zdns.Trace, 0), zdns.STATUS_ERROR, errors.New("max recursion depth reached")
	}
	// check if the record is already in our cache. if not, perform normal A lookup and
	// see what comes back. Then iterate over results and if needed, perform further lookups
	var trace zdns.Trace
	var result *zdns.SingleQueryResult
	garbage := map[string][]zdns.Answer{}
	if _, ok := candidateSet[name]; !ok {
		var status zdns.Status
		var err error
		result, trace, status, err = r.Lookup(&zdns.Question{Name: name, Type: dnsType}, net.IP(nameServer))
		if status != zdns.STATUS_NOERROR || err != nil {
			return nil, trace, status, err
		}

		zdns.PopulateResults(result.Answers, dnsType, candidateSet, cnameSet, garbage)
		zdns.PopulateResults(result.Additional, dnsType, candidateSet, cnameSet, garbage)
	}
	// our cache should now have any data that exists about the current name
	if res, ok := candidateSet[name]; ok && len(res) > 0 {
		// we have IP addresses to hand back to the user. let's make an easy-to-use array of strings
		var ips []string
		for _, answer := range res {
			ips = append(ips, answer.Answer)
		}
		return ips, trace, zdns.STATUS_NOERROR, nil
	} else if res, ok = cnameSet[name]; ok && len(res) > 0 {
		// we have a CNAME and need to further recurse to find IPs
		shortName := strings.ToLower(strings.TrimSuffix(res[0].Answer, "."))
		res, secondTrace, status, err := recursiveIPLookup(r, shortName, nameServer, dnsType, candidateSet, cnameSet, origName, depth+1)
		trace = append(trace, secondTrace...)
		return res, trace, status, err
	} else if res, ok = garbage[name]; ok && len(res) > 0 {
		return nil, trace, zdns.STATUS_ERROR, errors.New("unexpected record type received")
	} else {
		// we have no data whatsoever about this name. return an empty recordset to the user
		var ips []string
		return ips, trace, zdns.STATUS_NOERROR, nil
	}
}
