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

package mx

import (
	"flag"
	"strings"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
)

// result to be returned by scan of host

type MXRecord struct {
	Name          string `json:"name"`
	Priority      int    `json:"priority"`
	IPv4Addresses string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses string `json:"ipv6_addresses,omitempty"`
}

type Result struct {
	Servers []MXRecord `json:"servers"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func getAddresses(name string, ipv4 bool, ipv6 bool) ([]string, []string) {

	var ipv4Out *[]string
	var ipv6Out *[]string
	if ipv4 {

	}
	if ipv6 {

	}
	return ipv4Out, ipv6Out
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	// get a name server to use for this connection
	nameServer := s.Factory.Factory.RandomNameServer()
	// this is where we do scanning
	res := Result{Servers: []MXRecord{}}

	m := new(dns.Msg)
	m.SetQuestion(dotName(name), dns.TypeMX)
	m.RecursionDesired = true

	r, _, err := s.Factory.Client.Exchange(m, nameServer)
	if err != nil {
		return nil, zdns.STATUS_ERROR, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, zdns.STATUS_BAD_RCODE, nil
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.MX); ok {
			//res.Addresses = append(res.Addresses, a.A.String())
			// call getAddresses
		}
	}
	return &res, zdns.STATUS_SUCCESS, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	Factory *GlobalLookupFactory
	Client  *dns.Client
}

func (s *RoutineLookupFactory) Initialize(f *GlobalLookupFactory) {
	s.Factory = f
	s.Client = new(dns.Client)
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
	CacheSize  int
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.IPv4Lookup, "ipv4-lookup", false, "perform A lookups for each MX server")
	f.BoolVar(&s.IPv6Lookup, "ipv6-lookup", false, "perform AAAA record lookups for each MX server")
	f.IntVar(&s.CacheSize, "cache-size", false, "number of records to store in MX -> A/AAAA cache")
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) MakeRoutineFactory() (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Initialize(s)
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("A", s)
}
