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
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/v2/src/zdns"
)

func main() {
	// Create a shared cache
	// Create a ResolverConfig object
	resolverConfig := zdns.NewResolverConfig()
	// Initialize the resolvers with the config
	resolver1, err := zdns.InitResolver(resolverConfig)
	if err != nil {
		log.Fatal("Error initializing resolver: ", err)
	}
	resolver2, err := zdns.InitResolver(resolverConfig)
	if err != nil {
		log.Fatal("Error initializing resolver: ", err)
	}

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
		result1, _, _, err1 := resolver1.IterativeLookup(context.Background(), dnsQuestion1)
		if err1 != nil {
			log.Fatal("Error looking up domain: ", err1)
		}
		log.Warnf("Result: %v", result1)
	}()
	go func() {
		defer wg.Done()
		result2, _, _, err2 := resolver2.IterativeLookup(context.Background(), dnsQuestion2)
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
