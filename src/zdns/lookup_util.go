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

	// Determine which DNS record types are relevant given the IP mode
	wantRRType := func(rrType uint16) bool {
		switch rrType {
		case dns.TypeA:
			return ipMode != IPv6Only
		case dns.TypeAAAA:
			return ipMode != IPv4Only
		default:
			return false
		}
	}

	// Dedup key: name-only for allNSAllIPs=false, name+IP otherwise
	dedupKey := func(ns NameServer) string {
		if allNSAllIPs && ns.IP != nil {
			return ns.DomainName + "\x00" + ns.IP.String()
		}
		return ns.DomainName
	}

	// Seed the NS name set from authority records
	nsNames := make(map[string]struct{})
	for _, auth := range uniqueAuthorities {
		if auth.RrType == dns.TypeNS {
			nsNames[strings.TrimSuffix(auth.Answer, ".")] = struct{}{}
		}
	}

	// Build NameServer entries from glue records in additionals, filtered by ipMode
	uniq := make(map[string]NameServer)
	for _, add := range uniqueAdditionals {
		if !wantRRType(add.RrType) {
			continue
		}
		name := strings.TrimSuffix(add.Name, ".")
		if _, known := nsNames[name]; !known {
			continue
		}
		ns := NameServer{
			DomainName: name,
			IP:         net.ParseIP(add.Answer),
		}
		key := dedupKey(ns)
		if _, exists := uniq[key]; !exists {
			uniq[key] = ns
		}
	}

	// Include any NS-type answer records (typically no glue IP available)
	for _, answer := range uniqueAnswers {
		if answer.RrType != dns.TypeNS {
			continue
		}
		ns := NameServer{DomainName: strings.TrimSuffix(answer.Answer, ".")}
		key := dedupKey(ns)
		if _, exists := uniq[key]; !exists {
			uniq[key] = ns
		}
	}

	return slices.Collect(maps.Values(uniq)), nil
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