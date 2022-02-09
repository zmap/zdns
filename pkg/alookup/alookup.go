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
	"github.com/spf13/pflag"
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

// This LookupClient is created to call the actual implementation of DoMiekgLookup
type LookupClient struct{}

func (lc LookupClient) ProtocolLookup(s *miekg.Lookup, q miekg.Question, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	return s.DoMiekgLookup(q, nameServer)
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
	l := LookupClient{}
	if lookupIpv4 {
		ipv4, ipv4Trace, ipv4status, _ = s.DoProtocolLookup(l, name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0)
		res.IPv4Addresses = make([]string, len(ipv4))
		copy(res.IPv4Addresses, ipv4)
	}
	candidateSet = map[string][]miekg.Answer{}
	cnameSet = map[string][]miekg.Answer{}
	if lookupIpv6 {
		ipv6, ipv6Trace, ipv6status, _ = s.DoProtocolLookup(l, name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0)
		res.IPv6Addresses = make([]string, len(ipv6))
		copy(res.IPv6Addresses, ipv6)
	}

	combinedTrace := append(ipv4Trace, ipv6Trace...)

	// In case we get no IPs and a non-NOERROR status from either
	// IPv4 or IPv6 lookup, we return that status.
	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		if lookupIpv4 && !miekg.SafeStatus(ipv4status) {
			return nil, combinedTrace, ipv4status, nil
		} else if lookupIpv6 && !miekg.SafeStatus(ipv6status) {
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

func (s *GlobalLookupFactory) SetFlags(f *pflag.FlagSet) {
	// If there's an error, panic is appropriate since we should at least be getting the default here.
	var err error
	s.IPv4Lookup, err = f.GetBool("ipv4-lookup")
	if err != nil {
		panic(err)
	}
	s.IPv6Lookup, err = f.GetBool("ipv6-lookup")
	if err != nil {
		panic(err)
	}
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
