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
	"context"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/v2/src/zdns"
)

func main() {
	// Setup
	domain := "google.com"
	dnsQuestion := &zdns.Question{Name: domain, Type: dns.TypeA, Class: dns.ClassINET}
	resolverConfig := zdns.NewResolverConfig()
	resolver, err := zdns.InitResolver(resolverConfig)
	if err != nil {
		log.Fatal("Error initializing resolver: ", err)
	}
	defer resolver.Close()
	// LookupAllNameserversIterative will query all root nameservers, and then all TLD nameservers, and then all authoritative nameservers for the domain.
	result, _, status, err := resolver.LookupAllNameserversIterative(context.Background(), dnsQuestion, nil)
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	log.Warnf("Result: %v", result)
	log.Warnf("Status: %v", status)
	log.Info("We can also specify which root nameservers to use by setting the argument.")

	result, _, status, err = resolver.LookupAllNameserversIterative(context.Background(), dnsQuestion, []zdns.NameServer{{IP: net.ParseIP("198.41.0.4"), Port: 53}}) // a.root-servers.net
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	log.Warnf("Result: %v", result)
	log.Warnf("Status: %v", status)

	log.Info("You can query multiple recursive resolvers as well")

	externalResult, _, status, err := resolver.LookupAllNameserversExternal(context.Background(), dnsQuestion, []zdns.NameServer{{IP: net.ParseIP("1.1.1.1"), Port: 53}, {IP: net.ParseIP("8.8.8.8"), Port: 53}}) // Cloudflare and Google recursive resolvers, respectively
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	log.Warnf("Result: %v", externalResult)
	log.Warnf("Status: %v", status)
}
