package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/zdns"
)

func main() {

	// Perform the lookup
	domain := "google.com"
	dnsQuestion := &zdns.Question{Name: domain, Type: dns.TypeA, Class: dns.ClassINET}
	resolver := initializeResolver()

	result, _, status, err := resolver.ExternalLookup(dnsQuestion, "1.1.1.1:53")
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	// Print the result, use JSON to print the result
	bytes, err := json.Marshal(result)
	if err != nil {
		log.Fatal("Error marshalling result: ", err)
	}
	log.Warnf("Result: %v", string(bytes))
	log.Warnf("Status: %v", status)

	log.Warn("\n\n This lookup just used the Cloudflare recursive resolver, let's run our own recursion.")
	// Iterative Lookups start at the root nameservers and follow the chain of referrals to the authoritative nameservers.
	// For performance, the resolver will populate the cache with the IPs of the root and TLD nameservers.
	result, trace, status, err := resolver.IterativeLookup(&zdns.Question{Name: domain, Type: dns.TypeA, Class: dns.ClassINET})
	if err != nil {
		log.Fatal("Error looking up domain: ", err)
	}
	log.Warnf("Result: %v", result)
	bytes, err = json.MarshalIndent(trace, "", " ")
	if err != nil {
		log.Fatal("Error marshalling trace: ", err)
	}
	log.Warnf("Trace: %v", string(bytes))
	log.Warnf("Status: %v", status)
}

func initializeResolver() *zdns.Resolver {
	// Create a ResolverConfig object
	resolverConfig := zdns.NewResolverConfig()
	// Set any desired options on the ResolverConfig object
	resolverConfig.LogLevel = log.InfoLevel
	// Create a new Resolver object with the ResolverConfig object, it will retain all settings set on the ResolverConfig object
	resolver, err := zdns.InitResolver(resolverConfig)
	if err != nil {
		log.Fatal("Error initializing resolver: ", err)
	}
	return resolver
}
