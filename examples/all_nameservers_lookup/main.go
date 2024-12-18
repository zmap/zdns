/* ZDNS Copyright 2024 Regents of the University of Michigan
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

package main

import (
	"net"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/examples/utils"
	"github.com/zmap/zdns/src/zdns"
)

func main() {
	// Perform the lookup
	domain := "google.com"
	dnsQuestion := &zdns.Question{Name: domain, Type: dns.TypeA, Class: dns.ClassINET}
	resolver := initializeResolver()
	// LookupAllNameserversIterative will query all root nameservers, and then all TLD nameservers, and then all authoritative nameservers for the domain.
	result, _, status, err := resolver.LookupAllNameserversIterative(dnsQuestion, nil)
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	log.Warnf("Result: %v", result)
	log.Warnf("Status: %v", status)
	log.Info("We can also specify which root nameservers to use by setting the argument.")

	result, _, status, err = resolver.LookupAllNameserversIterative(dnsQuestion, []zdns.NameServer{{IP: net.ParseIP("198.41.0.4"), Port: 53}}) // a.root-servers.net
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	log.Warnf("Result: %v", result)
	log.Warnf("Status: %v", status)

	log.Info("You can query multiple recursive resolvers as well")

	externalResult, _, status, err := resolver.LookupAllNameserversExternal(dnsQuestion, []zdns.NameServer{{IP: net.ParseIP("1.1.1.1"), Port: 53}, {IP: net.ParseIP("8.8.8.8"), Port: 53}}) // Cloudflare and Google recursive resolvers, respectively
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	log.Warnf("Result: %v", externalResult)
	log.Warnf("Status: %v", status)
	resolver.Close()
}

func initializeResolver() *zdns.Resolver {
	localAddr, err := utils.GetLocalIPByConnecting()
	if err != nil {
		log.Fatal("Error getting local IP: ", err)
	}
	// Create a ResolverConfig object
	resolverConfig := zdns.NewResolverConfig()
	// Set any desired options on the ResolverConfig object
	resolverConfig.LogLevel = log.InfoLevel
	resolverConfig.LocalAddrsV4 = []net.IP{localAddr}
	resolverConfig.ExternalNameServersV4 = []zdns.NameServer{{IP: net.ParseIP("1.1.1.1"), Port: 53}}
	resolverConfig.RootNameServersV4 = zdns.RootServersV4
	resolverConfig.IPVersionMode = zdns.IPv4Only
	resolverConfig.Timeout = time.Minute
	resolverConfig.IterativeTimeout = time.Minute
	// Create a new Resolver object with the ResolverConfig object, it will retain all settings set on the ResolverConfig object
	resolver, err := zdns.InitResolver(resolverConfig)
	if err != nil {
		log.Fatal("Error initializing resolver: ", err)
	}
	return resolver
}
