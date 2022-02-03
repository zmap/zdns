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
	"errors"
	"flag"
	"strings"
	"sync"

	"github.com/zmap/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/cachehash"
	"github.com/zmap/zdns/modules/common"
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

func populateResults(records []interface{}, dnsType uint16, candidateSet map[string][]miekg.Answer, cnameSet map[string][]miekg.Answer, garbage map[string][]miekg.Answer) {
	for _, a := range records {
		// filter only valid answers of requested type or CNAME (#163)
		if ans, ok := a.(miekg.Answer); ok {
			lowerCaseName := strings.ToLower(strings.TrimSuffix(ans.Name, "."))
			// Verify that the answer type matches requested type
			if common.VerifyAddress(ans.Type, ans.Answer) {
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

func (s *Lookup) LookupIPs(name, nameServer string) (CachedAddresses, zdns.Trace) {
	s.Factory.Factory.CHmu.Lock()
	// XXX this should be changed to a miekglookup
	res, found := s.Factory.Factory.CacheHash.Get(name)
	s.Factory.Factory.CHmu.Unlock()
	if found {
		return res.(CachedAddresses), make([]interface{}, 0)
	}
	var retv CachedAddresses

	candidateSet := map[string][]miekg.Answer{}
	cnameSet := map[string][]miekg.Answer{}
	lookupIpv4 := s.Factory.Factory.IPv4Lookup || !s.Factory.Factory.IPv6Lookup
	lookupIpv6 := s.Factory.Factory.IPv6Lookup
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace []interface{}
	var ipv6Trace []interface{}
	if lookupIpv4 {
		ipv4, ipv4Trace, _, _ = s.doLookupProtocol(name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0)
		retv.IPv4Addresses = ipv4
	}
	candidateSet = map[string][]miekg.Answer{}
	cnameSet = map[string][]miekg.Answer{}
	if lookupIpv6 {
		ipv6, ipv6Trace, _, _ = s.doLookupProtocol(name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0)
		retv.IPv6Addresses = ipv6
	}

	combinedTrace := append(ipv4Trace, ipv6Trace...)

	s.Factory.Factory.CHmu.Lock()
	s.Factory.Factory.CacheHash.Add(name, retv)
	s.Factory.Factory.CHmu.Unlock()
	return retv, combinedTrace
}

func (s *Lookup) DoLookup(name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	retv := Result{Servers: []MXRecord{}}
	res, trace, status, err := s.DoMiekgLookup(miekg.Question{Name: name, Type: dns.TypeMX}, nameServer)
	if status != zdns.STATUS_NOERROR || err != nil {
		return nil, trace, status, err
	}
	r, ok := res.(miekg.Result)
	if !ok {
		return nil, trace, status, err
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
