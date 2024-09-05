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
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/examples/utils"
	"github.com/zmap/zdns/src/zdns"
)

func main() {
	// Create a shared cache
	cache := zdns.Cache{}
	cache.Init(10000)
	// Initialize the resolvers with the cache
	resolver1 := initializeResolver(&cache)
	resolver2 := initializeResolver(&cache)

	// Perform the lookup
	domain1 := "google.com"
	domain2 := "facebook.com"

	dnsQuestion1 := &zdns.Question{Name: domain1, Type: dns.TypeA, Class: dns.ClassINET}
	dnsQuestion2 := &zdns.Question{Name: domain2, Type: dns.TypeA, Class: dns.ClassINET}

	// create a wait group, then run each lookup in a thread, printing the results at the end
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		result1, _, _, err1 := resolver1.IterativeLookup(dnsQuestion1)
		if err1 != nil {
			log.Fatal("Error looking up domain: ", err1)
		}
		log.Warnf("Result: %v", result1)
	}()
	go func() {
		defer wg.Done()
		result2, _, _, err2 := resolver2.IterativeLookup(dnsQuestion2)
		if err2 != nil {
			log.Fatal("Error looking up domain: ", err2)
		}
		log.Warnf("Result: %v", result2)
	}()
	wg.Wait()
	log.Warn("All lookups complete")
	resolver1.Close()
	resolver2.Close()
}

// initializeResolver
// To ensure performant lookups, all resolvers should share the same cache. The cache is thread-safe and sharded to allow for concurrent lookups.
// If you don't do this, each resolver will create its own cache, leading to increased memory usage and redundant lookups
func initializeResolver(cache *zdns.Cache) *zdns.Resolver {
	// Create a ResolverConfig object
	resolverConfig := zdns.NewResolverConfig()
	localAddr, err := utils.GetLocalIPByConnecting()
	if err != nil {
		log.Fatal("Error getting local IP: ", err)
	}
	resolverConfig.LocalAddrsV4 = []net.IP{localAddr}
	resolverConfig.ExternalNameServersV4 = []zdns.NameServer{{IP: net.ParseIP("1.1.1.1"), Port: 53}}
	resolverConfig.RootNameServersV4 = []zdns.NameServer{{IP: net.ParseIP("198.41.0.4"), Port: 53}}
	resolverConfig.IPVersionMode = zdns.IPv4Only
	// Set any desired options on the ResolverConfig object
	resolverConfig.Cache = cache
	// Create a new Resolver object with the ResolverConfig object, it will retain all settings set on the ResolverConfig object
	resolver, err := zdns.InitResolver(resolverConfig)
	if err != nil {
		log.Fatal("Error initializing resolver: ", err)
	}
	return resolver
}
