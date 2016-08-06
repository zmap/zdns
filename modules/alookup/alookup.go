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
	"flag"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
)

// result to be returned by scan of host
type ALOOKUPRecord struct {
	Name          string   `json:"name"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
}

type Result struct {
	Servers []ALOOKUPRecord `json:"exchanges"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	nameServer := s.Factory.Factory.RandomNameServer()
	requests := []uint16{}
	if s.Factory.Factory.IPv6Lookup {
		requests = append(requests, dns.TypeAAAA)
	}
	if s.Factory.Factory.IPv4Lookup {
		requests = append(requests, dns.TypeA)
	}
	res := Result{}
	for _, dnsType := range requests {
		miekgResult, status, err := miekg.DoLookup(s.Factory.Client, s.Factory.TCPClient, nameServer, dnsType, name)
		if status != zdns.STATUS_SUCCESS || err != nil {
			return nil, status, err
		}
		nameRecord := ALOOKUPRecord{name, []string{}, []string{}}
		res.Servers = append(res.Servers, nameRecord)
		names := map[string]*ALOOKUPRecord{name: &res.Servers[len(res.Servers)-1]}
		searchSet := []miekg.Answer{}
		searchSet = append(searchSet, miekgResult.(miekg.Result).Additional...)
		searchSet = append(searchSet, miekgResult.(miekg.Result).Answers...)
		for _, add := range searchSet {
			if add.Type == "CNAME" {
				if _, ok := names[add.Name]; ok {
					nameRecord := ALOOKUPRecord{add.Answer, []string{}, []string{}}
					res.Servers = append(res.Servers, nameRecord)
					names[add.Answer] = &res.Servers[len(res.Servers)-1]
				}
			}
		}
		for _, add := range searchSet {
			if add.Type == dns.Type(dnsType).String() {
				if rec, ok := names[add.Name]; ok {
					if add.Type == dns.Type(dns.TypeA).String() {
						rec.IPv4Addresses = append(rec.IPv4Addresses, add.Answer)
					}
					if add.Type == dns.Type(dns.TypeAAAA).String() {
						rec.IPv6Addresses = append(rec.IPv6Addresses, add.Answer)
					}
				}
			}
		}
	}
	return res, zdns.STATUS_SUCCESS, nil
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
