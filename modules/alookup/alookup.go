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
	IPv4Addresses []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	nameServer := s.Factory.Factory.RandomNameServer()
	return s.DoTargetedLookup(name, nameServer)
}

func (s *Lookup) doLookupProtocol(name string, nameServer string, dnsType uint16, searchSet map[string][]miekg.Answer, origName string, depth int) ([]string, zdns.Status, error) {
	// avoid infinite loops
	if name == origName && depth != 0 {
		return nil, zdns.STATUS_ERROR, errors.New("Infinite redirection loop")
	}
	if depth > 10 {
		return nil, zdns.STATUS_ERROR, errors.New("Max recursion depth reached")
	}
	// check if the record is already in our cache. if not, perform normal A lookup and
	// see what comes back. Then iterate over results and if needed, perform further lookups
	if _, ok := searchSet[name]; !ok {
		miekgResult, status, err := miekg.DoLookup(s.Factory.Client, s.Factory.TCPClient, nameServer, dnsType, name)
		if status != zdns.STATUS_NOERROR || err != nil {
			return nil, status, err
		}
		for _, a := range miekgResult.(miekg.Result).Answers {
			ans, ok := a.(miekg.Answer)
			if !ok {
				continue
			}
			searchSet[ans.Name] = append(searchSet[ans.Name], ans)
		}
		for _, a := range miekgResult.(miekg.Result).Additional {
			ans, ok := a.(miekg.Answer)
			if !ok {
				continue
			}
			searchSet[ans.Name] = append(searchSet[ans.Name], ans)
		}
	}
	// our cache should now have any data that exists about the current name
	res, ok := searchSet[name]
	if !ok || len(res) == 0 {
		// we have no data whatsoever about this name. return an empty recordset to the user
		var ips []string
		return ips, zdns.STATUS_NO_ANSWER, nil
	} else if res[0].Type == dns.Type(dnsType).String() {
		// we have IP addresses to hand back to the user. let's make an easy-to-use array of strings
		var ips []string
		for _, answer := range res {
			ips = append(ips, answer.Answer)
		}
		return ips, zdns.STATUS_NOERROR, nil
	} else if res[0].Type == dns.Type(dns.TypeCNAME).String() {
		// we have a CNAME and need to further recurse to find IPs
		shortName := strings.ToLower(res[0].Answer[0 : len(res[0].Answer)-1])
		return s.doLookupProtocol(shortName, nameServer, dnsType, searchSet, origName, depth+1)
	} else {
		return nil, zdns.STATUS_ERROR, errors.New("Unexpected record type received")
	}
}

func (s *Lookup) DoTargetedLookup(name string, nameServer string) (interface{}, zdns.Status, error) {
	res := Result{}
	searchSet := map[string][]miekg.Answer{}
	if s.Factory.Factory.IPv4Lookup {
		ipv4, _, _ := s.doLookupProtocol(name, nameServer, dns.TypeA, searchSet, name, 0)
		res.IPv4Addresses = make([]string, len(ipv4))
		copy(res.IPv4Addresses, ipv4)
	}
	searchSet = map[string][]miekg.Answer{}
	if s.Factory.Factory.IPv6Lookup {
		ipv6, _, _ := s.doLookupProtocol(name, nameServer, dns.TypeAAAA, searchSet, name, 0)
		res.IPv6Addresses = make([]string, len(ipv6))
		copy(res.IPv6Addresses, ipv6)
	}
	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		return nil, zdns.STATUS_NO_ANSWER, nil
	}
	return res, zdns.STATUS_NOERROR, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	miekg.RoutineLookupFactory
	Factory *GlobalLookupFactory
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
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

func (s *GlobalLookupFactory) MakeRoutineFactory() (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Factory = s
	r.Initialize(s.GlobalConf.Timeout)
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("ALOOKUP", s)
}
