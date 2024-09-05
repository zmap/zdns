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

	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/internal/util"
)

// DoTargetedLookup performs a lookup of the given domain name against the given nameserver, looking up both IPv4 and IPv6 addresses
// Will follow CNAME records as well as A/AAAA records to get IP addresses
func (r *Resolver) DoTargetedLookup(name string, nameServer *NameServer, isIterative, lookupA, lookupAAAA bool) (*IPResult, Trace, Status, error) {
	name = strings.ToLower(name)
	res := IPResult{}
	singleQueryRes := &SingleQueryResult{}
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace Trace
	var ipv6Trace Trace
	var ipv4status Status
	var ipv6status Status
	var err error

	if lookupA && isIterative {
		singleQueryRes, ipv4Trace, ipv4status, err = r.IterativeLookup(&Question{Name: name, Type: dns.TypeA, Class: dns.ClassINET})
	} else if lookupA {
		singleQueryRes, ipv4Trace, ipv4status, err = r.ExternalLookup(&Question{Name: name, Type: dns.TypeA, Class: dns.ClassINET}, nameServer)
	}
	ipv4, _ = getIPAddressesFromQueryResult(singleQueryRes, "A", name)
	if len(ipv4) > 0 {
		ipv4 = Unique(ipv4)
		res.IPv4Addresses = make([]string, len(ipv4))
		copy(res.IPv4Addresses, ipv4)
	}
	singleQueryRes = &SingleQueryResult{} // reset result
	if lookupAAAA && isIterative {
		singleQueryRes, ipv6Trace, ipv6status, _ = r.IterativeLookup(&Question{Name: name, Type: dns.TypeAAAA, Class: dns.ClassINET})
	} else if lookupAAAA {
		singleQueryRes, ipv6Trace, ipv6status, _ = r.ExternalLookup(&Question{Name: name, Type: dns.TypeAAAA, Class: dns.ClassINET}, nameServer)
	}
	ipv6, _ = getIPAddressesFromQueryResult(singleQueryRes, "AAAA", name)
	if len(ipv6) > 0 {
		ipv6 = Unique(ipv6)
		res.IPv6Addresses = make([]string, len(ipv6))
		copy(res.IPv6Addresses, ipv6)
	}

	combinedTrace := util.Concat(ipv4Trace, ipv6Trace)

	// In case we get no IPs and a non-NOERROR status from either
	// IPv4 or IPv6 lookup, we return that status.
	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		if lookupA && !SafeStatus(ipv4status) {
			return nil, combinedTrace, ipv4status, err
		} else if lookupAAAA && !SafeStatus(ipv6status) {
			return nil, combinedTrace, ipv6status, err
		} else {
			return &res, combinedTrace, StatusNoError, nil
		}
	}
	return &res, combinedTrace, StatusNoError, nil
}

func getIPAddressesFromQueryResult(res *SingleQueryResult, queryType, name string) ([]string, error) {
	if res == nil {
		return nil, errors.New("nil SingleQueryResult")
	}
	ips := make([]string, 0, len(res.Answers)+len(res.Additional))
	for _, ans := range res.Answers {
		if a, ok := ans.(Answer); ok {
			if a.Type == queryType {
				ips = append(ips, a.Answer)
			}
		}
	}
	for _, ans := range res.Additional {
		if a, ok := ans.(Answer); ok {
			if a.Type == queryType {
				ips = append(ips, a.Answer)
			}
		}
	}
	return ips, nil
}
