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

package nslookup

import (
	"flag"
	"strings"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
)

// result to be returned by scan of host

type NSRecord struct {
	Name          string   `json:"name" groups:"short,normal,long,trace"`
	Type          string   `json:"type" groups:"short,normal,long,trace"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
	TTL           uint32   `json:"ttl" groups:"normal,long,trace"`
}

type Result struct {
	Servers []NSRecord `json:"servers,omitempty" groups:"short,normal,long,trace"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func (s *Lookup) lookupIPs(name string, dnsType uint16, nameServer string) ([]string, zdns.Trace) {
	var addresses []string
	res, trace, status, _ := s.DoMiekgLookup(miekg.Question{Name: name, Type: dnsType}, nameServer)
	if status == zdns.STATUS_NOERROR {
		if cast, ok := res.(miekg.Result); ok {
			for _, innerRes := range cast.Answers {
				if castInnerRes, ok := innerRes.(miekg.Answer); ok {
					addresses = append(addresses, castInnerRes.Answer)
				}
			}
		}
	}
	return addresses, trace
}

func (s *Lookup) DoNSLookup(name string, lookupIPv4, lookupIPv6 bool, nameServer string) (Result, zdns.Trace, zdns.Status, error) {
	var retv Result
	res, trace, status, err := s.DoMiekgLookup(miekg.Question{Name: name, Type: dns.TypeNS}, nameServer)
	if status != zdns.STATUS_NOERROR || err != nil {
		return retv, trace, status, nil
	}
	ns := res.(miekg.Result)
	ipv4s := make(map[string]string)
	ipv6s := make(map[string]string)
	for _, ans := range ns.Additional {
		a, ok := ans.(miekg.Answer)
		if !ok {
			continue
		}
		if a.Type == "A" {
			ipv4s[a.Name] = a.Answer
		} else if a.Type == "AAAA" {
			ipv6s[a.Name] = a.Answer
		}
	}
	for _, ans := range ns.Answers {
		a, ok := ans.(miekg.Answer)
		if !ok {
			continue
		}

		if a.Type != "NS" {
			continue
		}
		var rec NSRecord
		rec.Type = a.Type
		rec.Name = strings.TrimSuffix(a.Answer, ".")
		rec.TTL = a.Ttl
		if lookupIPv4 || !lookupIPv6 {
			var secondTrace []interface{}
			rec.IPv4Addresses, secondTrace = s.lookupIPs(rec.Name, dns.TypeA, nameServer)
			trace = append(trace, secondTrace...)
		} else if ip, ok := ipv4s[rec.Name]; ok {
			rec.IPv4Addresses = []string{ip}
		} else {
			rec.IPv4Addresses = []string{}
		}
		if lookupIPv6 {
			var secondTrace []interface{}
			rec.IPv6Addresses, secondTrace = s.lookupIPs(rec.Name, dns.TypeAAAA, nameServer)
			trace = append(trace, secondTrace...)
		} else if ip, ok := ipv6s[rec.Name]; ok {
			rec.IPv6Addresses = []string{ip}
		} else {
			rec.IPv6Addresses = []string{}
		}
		retv.Servers = append(retv.Servers, rec)
	}
	if len(retv.Servers) == 0 {
		return retv, trace, zdns.STATUS_NO_RECORD, nil
	}

	return retv, trace, zdns.STATUS_NOERROR, nil

}

func (s *Lookup) DoLookup(name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	return s.DoNSLookup(name, s.Factory.Factory.IPv4Lookup, s.Factory.Factory.IPv6Lookup, nameServer)
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
	f.BoolVar(&s.IPv4Lookup, "ipv4-lookup", false, "perform A lookups for each name server")
	f.BoolVar(&s.IPv6Lookup, "ipv6-lookup", false, "perform AAAA record lookups for each name server")
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) MakeRoutineFactory(threadID int) (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.RoutineLookupFactory.Factory = &s.GlobalLookupFactory
	r.Factory = s
	r.ThreadID = threadID
	r.Initialize(s.GlobalConf)
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("NSLOOKUP", s)
}
