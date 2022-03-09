/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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

package nsalookup

import (
	"log"
	"net"

	"github.com/spf13/pflag"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/miekg"
	"github.com/zmap/zdns/pkg/nslookup"
	"github.com/zmap/zdns/pkg/zdns"
)

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	nslookup.Lookup
}

// This LookupClient is created to call the actual implementation of DoMiekgLookup
type LookupClient struct{}

func (lc LookupClient) ProtocolLookup(s *miekg.Lookup, q miekg.Question, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	return s.DoMiekgLookup(q, nameServer)
}

// For the nameservers, return the IP and name
type NameServer struct {
	Name string `json:"name" groups:"short,normal,long,trace"`
	IP   string `json:"ip" groups:"short,normal,long,trace"`
}

// Each of the records in the final result
type ARecord struct {
	NameServer    NameServer  `json:"name_server" groups:"short,normal,long,trace"`
	Status        zdns.Status `json:"status" groups:"short,normal,long,trace"`
	IPv4Addresses []string    `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string    `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
}

// Final result to be returned by DoLookup
type Result struct {
	ARecords []ARecord `json:"ip_records,omitempty" groups:"short,normal,long,trace"`
}

func (s *Lookup) DoLookup(name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	var retv Result
	l := LookupClient{}
	var curServer string

	if nameServer == "" {
		nameServer = s.Factory.Factory.RandomNameServer()
	}

	// Lookup both ipv4 and ipv6 addresses of nameservers.
	nsResults, nsTrace, nsStatus, nsError := s.DoNSLookup(name, true, true, nameServer)

	if nsStatus != zdns.STATUS_NOERROR {
		return nil, nsTrace, nsStatus, nsError
	}

	// IPv4Lookup and IPv6Lookup determine whether to lookup IPv4 or IPv6 addresses for the domain
	lookupIpv4 := s.Factory.Factory.IPv4Lookup || !s.Factory.Factory.IPv6Lookup
	lookupIpv6 := s.Factory.Factory.IPv6Lookup

	var fullTrace zdns.Trace = nsTrace

	// Iterate over all the namesevers
	for _, nserver := range nsResults.Servers {
		// Use all the ipv4 and ipv6 addresses of each nameserver
		ips := append(nserver.IPv4Addresses, nserver.IPv6Addresses...)
		for _, ip := range ips {
			curServer = net.JoinHostPort(ip, "53")
			// Do ipv4 or ipv6 lookup or both depending on the flags set.
			aResult, aTrace, aStatus, _ := s.DoTargetedLookup(l, name, curServer, lookupIpv4, lookupIpv6)

			var ipv4s []string
			var ipv6s []string

			if aResult != nil {
				ipv4s = aResult.(miekg.IpResult).IPv4Addresses
				ipv6s = aResult.(miekg.IpResult).IPv6Addresses
			}

			fullTrace = append(fullTrace, aTrace)
			aRecord := ARecord{
				NameServer:    NameServer{Name: nserver.Name, IP: ip},
				Status:        aStatus,
				IPv4Addresses: ipv4s,
				IPv6Addresses: ipv6s,
			}

			retv.ARecords = append(retv.ARecords, aRecord)
		}
	}
	return retv, nil, zdns.STATUS_NOERROR, nil
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

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	if c.IterativeResolution {
		log.Fatal("NSA module does not support iterative resolution")
	}
	return nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("NSALOOKUP", s)
}
