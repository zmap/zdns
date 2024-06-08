/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
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
package zdns

import (
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
)

/*
It's unfortunate that we need this nslookup functionality in the main zdns package, but it's necessary to be able to
easily lookup NS records in zdns without encountering circular dependencies within the modules.
*/

// NSRecord result to be returned by scan of host
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

// DoNSLookup performs a DNS NS lookup on the given name against the given name server.
func (r *Resolver) DoNSLookup(lookupName, nameServer string, isIterative bool) (*NSResult, Trace, Status, error) {
	if !isIterative && len(nameServer) == 0 {
		nameServer = r.randomExternalNameServer()
		log.Info("no name server provided for external NS lookup, using random external name server: ", nameServer)
	}
	if len(lookupName) == 0 {
		return nil, nil, "", errors.New("no name provided for NS lookup")
	}

	var trace Trace
	var ns *SingleQueryResult
	var status Status
	var err error
	if isIterative {
		ns, trace, status, err = r.IterativeLookup(&Question{Name: lookupName, Type: dns.TypeNS, Class: dns.ClassINET})
	} else {
		ns, trace, status, err = r.ExternalLookup(&Question{Name: lookupName, Type: dns.TypeNS, Class: dns.ClassINET}, nameServer)

	}

	var retv NSResult
	if status != StatusNoError || err != nil {
		return &retv, trace, status, err
	}
	ipv4s := make(map[string][]string)
	ipv6s := make(map[string][]string)
	for _, ans := range ns.Additional {
		a, ok := ans.(Answer)
		if !ok {
			continue
		}
		recName := strings.TrimSuffix(a.Name, ".")
		if VerifyAddress(a.Type, a.Answer) {
			if a.Type == "A" {
				ipv4s[recName] = append(ipv4s[recName], a.Answer)
			} else if a.Type == "AAAA" {
				ipv6s[recName] = append(ipv6s[recName], a.Answer)
			}
		}
	}
	for _, ans := range ns.Answers {
		a, ok := ans.(Answer)
		if !ok {
			continue
		}

		if a.Type != "NS" {
			continue
		}

		var rec NSRecord
		rec.Type = a.Type
		rec.Name = strings.TrimSuffix(a.Answer, ".")
		rec.TTL = a.TTL

		var findIpv4 = false
		var findIpv6 = false

		lookupIPv4 := r.ipVersionMode == IPv4Only || r.ipVersionMode == IPv4OrIPv6
		lookupIPv6 := r.ipVersionMode == IPv6Only || r.ipVersionMode == IPv4OrIPv6

		if lookupIPv4 {
			if ips, ok := ipv4s[rec.Name]; ok {
				rec.IPv4Addresses = ips
			} else {
				findIpv4 = true
			}
		}
		if lookupIPv6 {
			if ips, ok := ipv6s[rec.Name]; ok {
				rec.IPv6Addresses = ips
			} else {
				findIpv6 = true
			}
		}
		if findIpv4 || findIpv6 {
			res, nextTrace, _, _ := r.DoTargetedLookup(rec.Name, nameServer, r.ipVersionMode, false)
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
	return &retv, trace, StatusNoError, nil
}
