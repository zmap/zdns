/*
 * ZDNS Copyright 2016 Regents of the University of Michigan
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

package alookup

import (
	"errors"
	"net"
	"strings"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/miekg"
	"github.com/zmap/zdns/pkg/zdns"
)

type Result struct {
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func (s *Lookup) DoLookup(name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if nameServer == "" {
		nameServer = s.Factory.Factory.RandomNameServer()
	}
	return s.DoTargetedLookup(name, nameServer)
}

// Verify that A record is indeed IPv4 and AAAA is IPv6
func verifyAddress(ansType string, ip string) bool {
	isIpv4 := false
	isIpv6 := false
	if net.ParseIP(ip) != nil {
		isIpv6 = strings.Contains(ip, ":")
		isIpv4 = !isIpv6
	}
	if ansType == "A" {
		return isIpv4
	} else if ansType == "AAAA" {
		return isIpv6
	}
	return !isIpv4 && !isIpv6
}

func populateResults(records []interface{}, dnsType uint16, candidateSet map[string][]miekg.Answer, cnameSet map[string][]miekg.Answer, garbage map[string][]miekg.Answer) {
	for _, a := range records {
		// filter only valid answers of requested type or CNAME (#163)
		if ans, ok := a.(miekg.Answer); ok {
			lowerCaseName := strings.ToLower(ans.Name)
			// Verify that the answer type matches requested type
			if verifyAddress(ans.Type, ans.Answer) {
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

func (s *Lookup) doLookupProtocol(name, nameServer string, dnsType uint16, candidateSet map[string][]miekg.Answer, cnameSet map[string][]miekg.Answer, origName string, depth int) ([]string, []interface{}, zdns.Status, error) {
	// avoid infinite loops
	if name == origName && depth != 0 {
		return nil, make([]interface{}, 0), zdns.STATUS_ERROR, errors.New("infinite redirection loop")
	}
	if depth > 10 {
		return nil, make([]interface{}, 0), zdns.STATUS_ERROR, errors.New("max recursion depth reached")
	}
	// check if the record is already in our cache. if not, perform normal A lookup and
	// see what comes back. Then iterate over results and if needed, perform further lookups
	var trace []interface{}
	garbage := map[string][]miekg.Answer{}
	if _, ok := candidateSet[name]; !ok {
		var miekgResult interface{}
		var status zdns.Status
		var err error
		miekgResult, trace, status, err = s.DoMiekgLookup(miekg.Question{Name: name, Type: dnsType}, nameServer)
		if status != zdns.STATUS_NOERROR || err != nil {
			return nil, trace, status, err
		}

		populateResults(miekgResult.(miekg.Result).Answers, dnsType, candidateSet, cnameSet, garbage)
		populateResults(miekgResult.(miekg.Result).Additional, dnsType, candidateSet, cnameSet, garbage)
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
		shortName := strings.ToLower(res[0].Answer[0 : len(res[0].Answer)-1])
		res, secondTrace, status, err := s.doLookupProtocol(shortName, nameServer, dnsType, candidateSet, cnameSet, origName, depth+1)
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

func safeStatus(status zdns.Status) bool {
	return status == zdns.STATUS_NOERROR
}

func (s *Lookup) DoTargetedLookup(name, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	res := Result{}
	candidateSet := map[string][]miekg.Answer{}
	cnameSet := map[string][]miekg.Answer{}
	lookupIpv4 := s.Factory.Factory.IPv4Lookup || !s.Factory.Factory.IPv6Lookup
	lookupIpv6 := s.Factory.Factory.IPv6Lookup
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace []interface{}
	var ipv6Trace []interface{}
	var ipv4status zdns.Status
	var ipv6status zdns.Status
	if lookupIpv4 {
		ipv4, ipv4Trace, ipv4status, _ = s.doLookupProtocol(name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0)
		res.IPv4Addresses = make([]string, len(ipv4))
		copy(res.IPv4Addresses, ipv4)
	}
	candidateSet = map[string][]miekg.Answer{}
	cnameSet = map[string][]miekg.Answer{}
	if lookupIpv6 {
		ipv6, ipv6Trace, ipv6status, _ = s.doLookupProtocol(name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0)
		res.IPv6Addresses = make([]string, len(ipv6))
		copy(res.IPv6Addresses, ipv6)
	}

	combinedTrace := append(ipv4Trace, ipv6Trace...)

	// alookup is only expected to return IP addresses. Hence irrespective of the
	// status returned from miekgdns, we return NO_ANSWER in case of missing IPs
	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		if lookupIpv4 && !safeStatus(ipv4status) {
			return nil, combinedTrace, ipv4status, nil
		} else if lookupIpv6 && !safeStatus(ipv6status) {
			return nil, combinedTrace, ipv6status, nil
		} else {
			return nil, combinedTrace, zdns.STATUS_NOERROR, nil
		}
	}
	return res, combinedTrace, zdns.STATUS_NOERROR, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	miekg.RoutineLookupFactory
	Factory *GlobalLookupFactory
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	nameServer := s.Factory.RandomNameServer()
	a.Initialize(nameServer, dns.TypeA, dns.ClassINET, &s.RoutineLookupFactory)
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	miekg.GlobalLookupFactory
	IPv4Lookup bool
	IPv6Lookup bool
}

func (s *GlobalLookupFactory) SetFlags(f zdns.ModuleFlags) {
	s.IPv4Lookup = f.Ipv4Lookup
	s.IPv6Lookup = f.Ipv6Lookup
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) MakeRoutineFactory(threadID int) (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Factory = s
	r.RoutineLookupFactory.Factory = &s.GlobalLookupFactory
	r.Initialize(s.GlobalConf)
	r.ThreadID = threadID
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("ALOOKUP", s)
}
