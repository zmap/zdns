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
	"flag"
	"strings"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
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

func (s *Lookup) DoLookup(name string, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	if nameServer == "" {
		nameServer = s.Factory.Factory.RandomNameServer()
	}
	return s.DoTargetedLookup(name, nameServer)
}

func (s *Lookup) doLookupProtocol(name string, nameServer string, dnsType uint16, candidateSet map[string][]miekg.Answer, cnameSet map[string][]miekg.Answer, origName string, depth int) ([]string, []interface{}, zdns.Status, error) {
	// avoid infinite loops
	if name == origName && depth != 0 {
		return nil, make([]interface{}, 0), zdns.STATUS_ERROR, errors.New("Infinite redirection loop")
	}
	if depth > 10 {
		return nil, make([]interface{}, 0), zdns.STATUS_ERROR, errors.New("Max recursion depth reached")
	}
	// check if the record is already in our cache. if not, perform normal A lookup and
	// see what comes back. Then iterate over results and if needed, perform further lookups
	var trace []interface{}
	garbage := map[string][]miekg.Answer{}
	if _, ok := candidateSet[name]; !ok {
		var miekgResult interface{}
		var status zdns.Status
		var err error
		miekgResult, trace, status, err = s.DoTypedMiekgLookup(name, dnsType, nameServer)
		if status != zdns.STATUS_NOERROR || err != nil {
			return nil, trace, status, err
		}
		for _, a := range miekgResult.(miekg.Result).Answers {
			ans, ok := a.(miekg.Answer)
			// filter only valid answers of requested type or CNAME (#163)
			if ok {
				lowerCaseName := strings.ToLower(ans.Name)
				ansType := dns.StringToType[ans.Type]
				if dnsType == ansType {
					candidateSet[lowerCaseName] = append(candidateSet[lowerCaseName], ans)
				} else if ok && dns.TypeCNAME == ansType {
					cnameSet[lowerCaseName] = append(cnameSet[lowerCaseName], ans)
				} else {
					garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
				}
			}
		}
		for _, a := range miekgResult.(miekg.Result).Additional {
			ans, ok := a.(miekg.Answer)
			// filter only valid answers of requested type or CNAME (#163)
			if ok {
				lowerCaseName := strings.ToLower(ans.Name)
				ansType := dns.StringToType[ans.Type]
				if dnsType == ansType {
					candidateSet[lowerCaseName] = append(candidateSet[lowerCaseName], ans)
				} else if ok && dns.TypeCNAME == ansType {
					cnameSet[lowerCaseName] = append(cnameSet[lowerCaseName], ans)
				} else {
					garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
				}
			}
		}
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
		return nil, trace, zdns.STATUS_ERROR, errors.New("Unexpected record type received")
	} else {
		// we have no data whatsoever about this name. return an empty recordset to the user
		var ips []string
		return ips, trace, zdns.STATUS_NO_ANSWER, nil
	}
}

func (s *Lookup) DoTargetedLookup(name string, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	res := Result{}
	candidateSet := map[string][]miekg.Answer{}
	cnameSet := map[string][]miekg.Answer{}
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace []interface{}
	var ipv6Trace []interface{}
	if s.Factory.Factory.IPv4Lookup || !s.Factory.Factory.IPv6Lookup {
		ipv4, ipv4Trace, _, _ = s.doLookupProtocol(name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0)
		res.IPv4Addresses = make([]string, len(ipv4))
		copy(res.IPv4Addresses, ipv4)
	}
	candidateSet = map[string][]miekg.Answer{}
	cnameSet = map[string][]miekg.Answer{}
	if s.Factory.Factory.IPv6Lookup {
		ipv6, ipv6Trace, _, _ = s.doLookupProtocol(name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0)
		res.IPv6Addresses = make([]string, len(ipv6))
		copy(res.IPv6Addresses, ipv6)
	}

	ipv4Trace = append(ipv4Trace, ipv6Trace...)

	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		return nil, ipv4Trace, zdns.STATUS_NO_ANSWER, nil
	}
	return res, ipv4Trace, zdns.STATUS_NOERROR, nil
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

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.IPv4Lookup, "ipv4-lookup", false, "perform A lookups for each server")
	f.BoolVar(&s.IPv6Lookup, "ipv6-lookup", false, "perform AAAA record lookups for each server")
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
