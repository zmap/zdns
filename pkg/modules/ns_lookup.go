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

package modules

import (
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"
	"strings"
)

// result to be returned by scan of host

type NSRecord struct {
	Name          string   `json:"name" groups:"short,normal,long,trace"`
	Type          string   `json:"type" groups:"short,normal,long,trace"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
	TTL           uint32   `json:"ttl" groups:"normal,long,trace"`
}

type NSResult struct {
	Servers []NSRecord `json:"servers,omitempty" groups:"short,normal,long,trace"`
}

func DoNSLookup(r *zdns.Resolver, name string, lookupIpv4 bool, lookupIpv6 bool, nameServer string) (NSResult, zdns.Trace, zdns.Status, error) {
	var retv NSResult
	ns, trace, status, err := r.Lookup(&zdns.Question{Name: name, Type: dns.TypeNS}, nameServer)

	if status != zdns.STATUS_NOERROR || err != nil {
		return retv, trace, status, err
	}
	ipv4s := make(map[string][]string)
	ipv6s := make(map[string][]string)
	for _, ans := range ns.Additional {
		a, ok := ans.(zdns.Answer)
		if !ok {
			continue
		}
		recName := strings.TrimSuffix(a.Name, ".")
		if zdns.VerifyAddress(a.Type, a.Answer) {
			if a.Type == "A" {
				ipv4s[recName] = append(ipv4s[recName], a.Answer)
			} else if a.Type == "AAAA" {
				ipv6s[recName] = append(ipv6s[recName], a.Answer)
			}
		}
	}
	for _, ans := range ns.Answers {
		a, ok := ans.(zdns.Answer)
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

		var findIpv4 = false
		var findIpv6 = false

		if lookupIpv4 {
			if ips, ok := ipv4s[rec.Name]; ok {
				rec.IPv4Addresses = ips
			} else {
				findIpv4 = true
			}
		}
		if lookupIpv6 {
			if ips, ok := ipv6s[rec.Name]; ok {
				rec.IPv6Addresses = ips
			} else {
				findIpv6 = true
			}
		}
		if findIpv4 || findIpv6 {
			res, nextTrace, _, _ := DoTargetedLookup(r, rec.Name, nameServer, findIpv4, findIpv6)
			if res != nil {
				if findIpv4 {
					rec.IPv4Addresses = res.IPv4Addresses
				}
				if findIpv6 {
					rec.IPv6Addresses = res.IPv6Addresses
				}
			}
			trace = append(trace, nextTrace...)
		}

		retv.Servers = append(retv.Servers, rec)
	}
	return retv, trace, zdns.STATUS_NOERROR, nil
}

//func (r *Resolver) doLookupAllNameservers(q Question, nameServer string) (*CombinedResults, Trace, Status, error) {
//	var retv CombinedResults
//	var curServer string
//
//	// Lookup both ipv4 and ipv6 addresses of nameservers.
//	nsResults, nsTrace, nsStatus, nsError := r.doNSLookup(q.Name, true, true, nameServer)
//
//	// Terminate early if nameserver lookup also failed
//	if nsStatus != STATUS_NOERROR {
//		return nil, nsTrace, nsStatus, nsError
//	}
//
//	// fullTrace holds the complete trace including all lookups
//	var fullTrace Trace = nsTrace
//	var tmpRes SingleQueryResult
//
//	for _, nserver := range nsResults.Servers {
//		// Use all the ipv4 and ipv6 addresses of each nameserver
//		nameserver := nserver.Name
//		ips := append(nserver.IPv4Addresses, nserver.IPv6Addresses...)
//		for _, ip := range ips {
//			curServer = net.JoinHostPort(ip, "53")
//			res, trace, status, err := r.lookupClient.DoSingleNameserverLookup(r, q, curServer)
//
//			fullTrace = append(fullTrace, trace...)
//			tmpRes = SingleQueryResult{}
//			if err == nil {
//				tmpRes = res
//			}
//			extendedResult := ExtendedResult{
//				Res:        tmpRes,
//				Status:     status,
//				Nameserver: nameserver,
//				Trace:      trace,
//			}
//			retv.Results = append(retv.Results, extendedResult)
//		}
//	}
//	return &retv, fullTrace, STATUS_NOERROR, nil
//}

// TODO Phillip remove: leaving for now to make sure the tests work
//func (s *Lookup) DoLookup(name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
//	l := LookupClient{}
//	lookupIpv4 := s.Factory.Factory.IPv4Lookup || !s.Factory.Factory.IPv6Lookup
//	lookupIpv6 := s.Factory.Factory.IPv6Lookup
//	return s.doNSLookup(l, name, lookupIpv4, lookupIpv6, nameServer)
//}
//j
//func (s *RoutineLookupFactory) MakeLookuper() (zdns.Lookuper, error) {
//	a := Lookup{Factory: s}
//	nameServer := s.Factory.RandomNameServer()
//	a.Initialize(nameServer, dns.TypeA, dns.ClassINET, &s.RoutineLookupFactory)
//	return &a, nil
//}

//func (s *GlobalLookupFactory) SetFlags(f *pflag.FlagSet) {
//	// If there's an error, panic is appropriate since we should at least be getting the default here.
//	var err error
//	s.IPv4Lookup, err = f.GetBool("ipv4-lookup")
//	if err != nil {
//		panic(err)
//	}
//	s.IPv6Lookup, err = f.GetBool("ipv6-lookup")
//	if err != nil {
//		panic(err)
//	}
//}
