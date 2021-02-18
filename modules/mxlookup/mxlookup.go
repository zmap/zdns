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

package mxlookup

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

type CachedAddresses struct {
	IPv4Addresses []string
	IPv6Addresses []string
}

type MXRecord struct {
	Name          string   `json:"name" groups:"short,normal,long,trace"`
	Type          string   `json:"type" groups:"short,normal,long,trace"`
	Class         string   `json:"class" groups:"normal,long,trace"`
	Preference    uint16   `json:"preference" groups:"short,normal,long,trace"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
	TTL           uint32   `json:"ttl" groups:"ttl,normal,long,trace"`
}

type Result struct {
	Servers []MXRecord `json:"exchanges" groups:"short,normal,long,trace"`
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

func (s *Lookup) LookupIPs(name, nameServer string) (CachedAddresses, zdns.Trace) {
	s.Factory.Factory.CHmu.Lock()
	// XXX this should be changed to a miekglookup
	res, found := s.Factory.Factory.CacheHash.Get(name)
	s.Factory.Factory.CHmu.Unlock()
	if found {
		return res.(CachedAddresses), make([]interface{}, 0)
	}
	var retv CachedAddresses
	trace := make([]interface{}, 0)
	// ipv4
	if s.Factory.Factory.IPv4Lookup || !s.Factory.Factory.IPv6Lookup {
		res, secondTrace, status, _ := s.DoMiekgLookup(miekg.Question{Name: name, Type: dns.TypeA}, nameServer)
		trace = append(trace, secondTrace...)
		if status == zdns.STATUS_NOERROR {
			cast, _ := res.(miekg.Result)
			for _, innerRes := range cast.Answers {
				castInnerRes, ok := innerRes.(miekg.Answer)
				if !ok {
					continue
				}
				retv.IPv4Addresses = append(retv.IPv4Addresses, castInnerRes.Answer)
			}
		}
	}
	// ipv6
	if s.Factory.Factory.IPv6Lookup {
		res, secondTrace, status, _ := s.DoMiekgLookup(miekg.Question{Name: name, Type: dns.TypeAAAA}, nameServer)
		trace = append(trace, secondTrace...)
		if status == zdns.STATUS_NOERROR {
			cast, _ := res.(miekg.Result)
			for _, innerRes := range cast.Answers {
				castInnerRes, ok := innerRes.(miekg.Answer)
				if !ok {
					continue
				}
				retv.IPv6Addresses = append(retv.IPv6Addresses, castInnerRes.Answer)
			}
		}
	}
	s.Factory.Factory.CHmu.Lock()
	s.Factory.Factory.CacheHash.Add(name, retv)
	s.Factory.Factory.CHmu.Unlock()
	return retv, trace
}

func (s *Lookup) DoLookup(name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	retv := Result{Servers: []MXRecord{}}
	res, trace, status, err := s.DoMiekgLookup(miekg.Question{Name: name, Type: dns.TypeMX}, nameServer)
	if status != zdns.STATUS_NOERROR {
		return retv, trace, status, err
	}
	r, ok := res.(miekg.Result)
	if !ok {
		panic("could not cast correctly")
	}
	for _, ans := range r.Answers {
		if mxAns, ok := ans.(miekg.PrefAnswer); ok {
			name = strings.TrimSuffix(mxAns.Answer.Answer, ".")
			rec := MXRecord{TTL: mxAns.Ttl, Type: mxAns.Type, Class: mxAns.Class, Name: name, Preference: mxAns.Preference}
			ips, secondTrace := s.LookupIPs(name, nameServer)
			rec.IPv4Addresses = ips.IPv4Addresses
			rec.IPv6Addresses = ips.IPv6Addresses
			retv.Servers = append(retv.Servers, rec)
			trace = append(trace, secondTrace...)
		}
	}
	return retv, trace, zdns.STATUS_NOERROR, nil
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
	a.Initialize(nameServer, dns.TypeMX, dns.ClassINET, &s.RoutineLookupFactory)
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	miekg.GlobalLookupFactory
	IPv4Lookup  bool
	IPv6Lookup  bool
	MXCacheSize int
	CacheHash   *cachehash.CacheHash
	CHmu        sync.Mutex
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.IPv4Lookup, "ipv4-lookup", false, "perform A lookups for each MX server")
	f.BoolVar(&s.IPv6Lookup, "ipv6-lookup", false, "perform AAAA record lookups for each MX server")
	f.IntVar(&s.MXCacheSize, "mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalLookupFactory.Initialize(c)
	s.GlobalConf = c
	s.CacheHash = new(cachehash.CacheHash)
	s.CacheHash.Init(s.MXCacheSize)
	return nil
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
	zdns.RegisterLookup("MXLOOKUP", s)
}
