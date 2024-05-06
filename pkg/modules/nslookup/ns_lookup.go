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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zmap/zdns/pkg/cmd"
	"github.com/zmap/zdns/pkg/modules/alookup"
	"strings"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"
)

func init() {
	ns := new(NSLookupModule)
	cmd.RegisterLookupModule("NS", ns)
}

type NSLookupModule struct {
	cmd.BasicLookupModule
	IPv4Lookup bool
	IPv6Lookup bool
}

// CLIInit initializes the NSLookupModule with the given parameters, used to call NSLookup from the command line
func (ns *NSLookupModule) CLIInit(gc *cmd.CLIConf, resolverConf *zdns.ResolverConfig, f *pflag.FlagSet) {
	ipv4Lookup, err := f.GetBool("ipv4-lookup")
	if err != nil {
		panic(err)
	}
	ipv6Lookup, err := f.GetBool("ipv6-lookup")
	if err != nil {
		panic(err)
	}
	ns.BasicLookupModule.CLIInit(gc, resolverConf, f)
	ns.Init(ipv4Lookup, ipv6Lookup)
}

// Init initializes the NSLookupModule with the given parameters, used to call NSLookup programmatically
func (ns *NSLookupModule) Init(ipv4Lookup bool, ipv6Lookup bool) {
	ns.IPv4Lookup = ipv4Lookup
	ns.IPv6Lookup = ipv6Lookup
}

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

func (nsConfig *NSLookupModule) Lookup(r *zdns.Resolver, lookupName string, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if nsConfig.IsIterative && nameServer != "" {
		log.Warn("iterative lookup requested with lookupName server, ignoring lookupName server")
	}

	var trace zdns.Trace
	var ns *zdns.SingleQueryResult
	var status zdns.Status
	var err error
	if nsConfig.IsIterative {
		ns, trace, status, err = r.IterativeLookup(&zdns.Question{Name: lookupName, Type: dns.TypeNS, Class: dns.ClassINET})
	} else {
		ns, trace, status, err = r.ExternalLookup(&zdns.Question{Name: lookupName, Type: dns.TypeNS, Class: dns.ClassINET}, nameServer)
	}

	var retv NSResult
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

		lookupIPv4 := nsConfig.IPv4Lookup
		lookupIPv6 := nsConfig.IPv6Lookup
		ipMode := zdns.GetIPVersionMode(lookupIPv4, lookupIPv6)
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
			res, nextTrace, _, _ := alookup.DoTargetedLookup(r, rec.Name, nameServer, ipMode)
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

// Help returns the module's help string
func (ns *NSLookupModule) Help() string {
	return ""
}
