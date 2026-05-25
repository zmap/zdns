/*
* ZDNS Copyright 2026 Regents of the University of Michigan
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
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/zmap/dns"
)

// extractNameServersFromLayerResults
// extracts unique nameservers from Additionals/Authorities.
// If ipMode == IPv4Only or IPv6 Only, only extracts A or AAAA records only, respectively. Otherwise, extracts both
// If allNSAllIPs is true, will extract all IPs for all nameservers, de-duplicated across ns.name + ns.IP
// If allNSAllIPs is false, will extract one A and one AAAA for each name-server, only de-duplicating across ns.name.
func extractNameServersFromLayerResults(layerResults []ExtendedResult, ipMode IPVersionMode, allNSAllIPs bool) ([]NameServer, error) {
	uniqueAnswers, uniqueAdditionals, uniqueAuthorities := extractUniqueAnswersAdditionalsAuthorities(layerResults)
	// We have a map of unique additional and authority records. Now we need to extract the nameservers from them.
	v4NameServers := make(map[string]NameServer)
	v6NameServers := make(map[string]NameServer)
	for _, authorities := range uniqueAuthorities {
		if authorities.RrType == dns.TypeNS {
			v4NameServers[strings.TrimSuffix(authorities.Answer, ".")] = NameServer{DomainName: strings.TrimSuffix(authorities.Answer, ".")}
			v6NameServers[strings.TrimSuffix(authorities.Answer, ".")] = NameServer{DomainName: strings.TrimSuffix(authorities.Answer, ".")}
		}
	}
	for _, additionals := range uniqueAdditionals {
		additionals.Name = strings.TrimSuffix(additionals.Name, ".")
		if additionals.RrType == dns.TypeA {
			if ns, ok := v4NameServers[additionals.Name]; ok {
				ns.IP = net.ParseIP(additionals.Answer)
				v4NameServers[additionals.Name] = ns
			}
		}
		if additionals.RrType == dns.TypeAAAA {
			if ns, ok := v6NameServers[additionals.Name]; ok {
				ns.IP = net.ParseIP(additionals.Answer)
				v6NameServers[additionals.Name] = ns
			}
		}
	}
	uniqNameServersSet := make(map[string]NameServer)
	if ipMode != IPv6Only {
		for _, ns := range v4NameServers {
			key := ns.DomainName + ns.IP.String()
			if _, ok := uniqNameServersSet[key]; !ok {
				uniqNameServersSet[key] = ns

			}
		}
	}
	if ipMode != IPv4Only {
		for _, ns := range v6NameServers {
			key := ns.DomainName + ns.IP.String()
			if _, ok := uniqNameServersSet[key]; !ok {
				uniqNameServersSet[key] = ns
			}
		}
	}
	// append any NS answers too
	for _, answer := range uniqueAnswers {
		ns := NameServer{
			DomainName: strings.TrimSuffix(answer.Answer, "."),
		}
		key := ns.DomainName
		if _, ok := uniqNameServersSet[key]; !ok {
			uniqNameServersSet[key] = ns
		}
	}
	return slices.Collect(maps.Values(uniqNameServersSet)), nil
}

func extractUniqueAnswersAdditionalsAuthorities(layerResults []ExtendedResult) (answers, additionals, authorities []Answer) {
	type mapKey struct {
		Type   uint16
		Name   string
		Answer string
	}
	uniqueAdditionals := make(map[mapKey]Answer)
	uniqueAuthorities := make(map[mapKey]Answer)
	uniqueAnswers := make(map[mapKey]Answer)
	for _, res := range layerResults {
		if res.Status != StatusNoError {
			continue
		}
		for _, ans := range res.Res.Additionals {
			if a, ok := ans.(Answer); ok {
				uniqueAdditionals[mapKey{Type: a.RrType, Name: a.Name, Answer: a.Answer}] = a
			}
		}
		for _, ans := range res.Res.Authorities {
			if a, ok := ans.(Answer); ok {
				uniqueAuthorities[mapKey{Type: a.RrType, Name: a.Name, Answer: a.Answer}] = a
			}
		}
		for _, ans := range res.Res.Answers {
			if a, ok := ans.(Answer); ok {
				if a.RrType == dns.TypeNS {
					uniqueAnswers[mapKey{Type: a.RrType, Name: a.Name, Answer: a.Answer}] = a
				}
			}
		}
	}
	answers = slices.Collect(maps.Values(uniqueAnswers))
	authorities = slices.Collect(maps.Values(uniqueAuthorities))
	additionals = slices.Collect(maps.Values(uniqueAdditionals))
	return
}