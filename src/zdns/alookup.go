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
package zdns

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/zmap/dns"
)

// DoTargetedLookup performs a lookup of the given domain name against the given nameserver, looking up both IPv4 and IPv6 addresses
// Will follow CNAME records as well as A/AAAA records to get IP addresses
func (r *Resolver) DoTargetedLookup(name, nameServer string, ipMode IPVersionMode, isIterative bool) (*IPResult, Trace, Status, error) {
	lookupIPv4 := ipMode == IPv4Only || ipMode == IPv4OrIPv6
	lookupIPv6 := ipMode == IPv6Only || ipMode == IPv4OrIPv6
	name = strings.ToLower(name)
	res := IPResult{}
	candidateSet := map[string][]Answer{}
	cnameSet := map[string][]Answer{}
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace Trace
	var ipv6Trace Trace
	var ipv4status Status
	var ipv6status Status

	if lookupIPv4 {
		ipv4, ipv4Trace, ipv4status, _ = recursiveIPLookup(r, name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0, isIterative)
		if len(ipv4) > 0 {
			ipv4 = Unique(ipv4)
			res.IPv4Addresses = make([]string, len(ipv4))
			copy(res.IPv4Addresses, ipv4)
		}
	}
	candidateSet = map[string][]Answer{}
	cnameSet = map[string][]Answer{}
	if lookupIPv6 {
		ipv6, ipv6Trace, ipv6status, _ = recursiveIPLookup(r, name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0, isIterative)
		if len(ipv6) > 0 {
			ipv6 = Unique(ipv6)
			res.IPv6Addresses = make([]string, len(ipv6))
			copy(res.IPv6Addresses, ipv6)
		}
	}

	combinedTrace := append(ipv4Trace, ipv6Trace...)

	// In case we get no IPs and a non-NOERROR status from either
	// IPv4 or IPv6 lookup, we return that status.
	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		if lookupIPv4 && !SafeStatus(ipv4status) {
			return nil, combinedTrace, ipv4status, nil
		} else if lookupIPv6 && !SafeStatus(ipv6status) {
			return nil, combinedTrace, ipv6status, nil
		} else {
			return &res, combinedTrace, StatusNoError, nil
		}
	}
	return &res, combinedTrace, StatusNoError, nil
}

// recursiveIPLookup helper fn that recursively follows both A/AAAA records and CNAME records to find IP addresses
// returns an array of IP addresses, a trace of the lookups, a status, and an error
func recursiveIPLookup(r *Resolver, name, nameServer string, dnsType uint16, candidateSet map[string][]Answer, cnameSet map[string][]Answer, origName string, depth int, isIterative bool) ([]string, Trace, Status, error) {
	// avoid infinite loops
	if name == origName && depth != 0 {
		return nil, make(Trace, 0), StatusError, errors.New("infinite redirection loop")
	}
	if depth > 10 {
		return nil, make(Trace, 0), StatusError, errors.New("max recursion depth reached")
	}
	// check if the record is already in our cache. if not, perform normal A lookup and
	// see what comes back. Then iterate over results and if needed, perform further lookups
	var trace Trace
	var result *SingleQueryResult
	garbage := map[string][]Answer{}
	if _, ok := candidateSet[name]; !ok {
		var status Status
		var err error
		if isIterative {
			result, trace, status, err = r.IterativeLookup(&Question{Name: name, Type: dnsType, Class: dns.ClassINET})
		} else {
			result, trace, status, err = r.ExternalLookup(&Question{Name: name, Type: dnsType, Class: dns.ClassINET}, nameServer)
		}

		if status != StatusNoError || err != nil {
			return nil, trace, status, err
		}

		populateResults(result.Answers, dnsType, candidateSet, cnameSet, garbage)
		populateResults(result.Additional, dnsType, candidateSet, cnameSet, garbage)
	}
	// our cache should now have any data that exists about the current name
	if res, ok := candidateSet[name]; ok && len(res) > 0 {
		// we have IP addresses to hand back to the user. let's make an easy-to-use array of strings
		var ips []string
		for _, answer := range res {
			ips = append(ips, answer.Answer)
		}
		return ips, trace, StatusNoError, nil
	} else if res, ok = cnameSet[name]; ok && len(res) > 0 {
		// we have a CNAME and need to further recurse to find IPs
		shortName := strings.ToLower(strings.TrimSuffix(res[0].Answer, "."))
		res, secondTrace, status, err := recursiveIPLookup(r, shortName, nameServer, dnsType, candidateSet, cnameSet, origName, depth+1, isIterative)
		trace = append(trace, secondTrace...)
		return res, trace, status, err
	} else if res, ok = garbage[name]; ok && len(res) > 0 {
		return nil, trace, StatusError, errors.New("unexpected record type received")
	} else {
		// we have no data whatsoever about this name. return an empty recordset to the user
		var ips []string
		return ips, trace, StatusNoError, nil
	}
}

// populateResults is a helper function to populate the candidateSet, cnameSet, and garbage maps as recursiveIPLookup
// follows CNAME and A/AAAA records to get all IPs for a given domain
func populateResults(records []interface{}, dnsType uint16, candidateSet map[string][]Answer, cnameSet map[string][]Answer, garbage map[string][]Answer) {
	for _, a := range records {
		// filter only valid answers of requested type or CNAME (#163)
		if ans, ok := a.(Answer); ok {
			lowerCaseName := strings.ToLower(strings.TrimSuffix(ans.Name, "."))
			// Verify that the answer type matches requested type
			if VerifyAddress(ans.Type, ans.Answer) {
				ansType := dns.StringToType[ans.Type]
				if dnsType == ansType {
					candidateSet[lowerCaseName] = append(candidateSet[lowerCaseName], ans)
				} else if ok && dns.TypeCNAME == ansType {
					cnameSet[lowerCaseName] = append(cnameSet[lowerCaseName], ans)
				} else {
					garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
				}
			} else {
				garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
			}
		}
	}
}
