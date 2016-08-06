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
	"sync"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/cachehash"
	"github.com/zmap/zdns/modules/miekg"
)

// result to be returned by scan of host

type NSRecord struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
	TTL           uint32   `json:"ttl"`
}

type Result struct {
	Servers []NSRecord `json:"servers"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func lookupIPs(name string, dnsType uint16, nameServer string, client *dns.Client, tcpClient *dns.Client) []string {
	var addresses []string
	res, status, _ := miekg.DoLookup(client, tcpClient, nameServer, dnsType, name)
	if status == zdns.STATUS_SUCCESS {
		cast, _ := res.(miekg.Result)
		for _, innerRes := range cast.Answers {
			addresses = append(addresses, innerRes.Answer)
		}
	}
	return addresses
}

func DoNSLookup(name string, nameServer string, client *dns.Client, tcpClient *dns.Client, lookupIPv4 bool, lookupIPv6 bool) (interface{}, zdns.Status, error) {
	res, status, err := miekg.DoLookup(client, tcpClient, nameServer, dns.TypeNS, name)
	if status != zdns.STATUS_SUCCESS || err != nil {
		return res, status, nil
	}
	ns := res.(miekg.Result)
	ipv4s := make(map[string]string)
	ipv6s := make(map[string]string)
	for _, a := range ns.Additional {
		if a.Type == "A" {
			ipv4s[a.Name] = a.Answer
		} else if a.Type == "AAAA" {
			ipv6s[a.Name] = a.Answer
		}
	}
	var retv Result
	for _, a := range ns.Answers {
		if a.Type != "NS" {
			continue
		}
		var rec NSRecord
		rec.Type = a.Type
		rec.Name = strings.TrimSuffix(a.Answer, ".")
		rec.TTL = a.Ttl
		if lookupIPv4 {
			rec.IPv4Addresses = lookupIPs(rec.Name, dns.TypeA, nameServer, client, tcpClient)
		} else if ip, ok := ipv4s[rec.Name]; ok {
			rec.IPv4Addresses = []string{ip}
		} else {
			rec.IPv4Addresses = []string{}
		}
		if lookupIPv6 {
			rec.IPv6Addresses = lookupIPs(rec.Name, dns.TypeAAAA, nameServer, client, tcpClient)
		} else if ip, ok := ipv6s[rec.Name]; ok {
			rec.IPv6Addresses = []string{ip}
		} else {
			rec.IPv6Addresses = []string{}
		}
		retv.Servers = append(retv.Servers, rec)
	}
	return retv, zdns.STATUS_SUCCESS, nil

}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	nameServer := s.Factory.Factory.RandomNameServer()
	return DoNSLookup(name, nameServer, s.Factory.Client, s.Factory.TCPClient, s.Factory.Factory.IPv4Lookup, s.Factory.Factory.IPv6Lookup)
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
	CacheSize  int
	CacheHash  *cachehash.CacheHash
	CHmu       sync.Mutex
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.IPv4Lookup, "ipv4-lookup", false, "perform A lookups for each MX server")
	f.BoolVar(&s.IPv6Lookup, "ipv6-lookup", false, "perform AAAA record lookups for each MX server")
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	return nil
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) MakeRoutineFactory() (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Initialize(s.GlobalConf.Timeout)
	r.Factory = s
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("NSLOOKUP", s)
}
