package main

import (
	"fmt"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"

	log "github.com/sirupsen/logrus"
)

// TODO PHillip, remove this file, just for testing

func main() {
	q := zdns.Question{
		Name:  "www.google.com",
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	}
	q1 := zdns.Question{
		Name:  "www.yahoo.com",
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	}

	config := zdns.NewResolverConfig()
	config.ShouldTrace = true
	config.IsIterative = true

	//config.NameServers = []string{"b.gtld-servers.net"}   <-------  won't work
	config.NameServers = []string{"170.247.170.2:53"}
	iterativeRes, err := zdns.InitResolver(config)
	if err != nil {
		log.Fatal("Error creating iterative zdns: %w", err)
	}

	res, _, _, err := iterativeRes.Lookup(&q, "")
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

	// Multiple resolvers, single cache
	cache := zdns.Cache{}
	cache.Init(10000)

	config = zdns.NewResolverConfig()
	config.NameServers = []string{"1.1.1.1:53"}
	config.IsIterative = false
	externalRes, err := zdns.InitResolver(config)
	if err != nil {
		log.Fatal("Error creating external zdns: %w", err)
	}
	externalRes2, err := zdns.InitResolver(config)
	if err != nil {
		log.Fatal("Error creating external zdns: %w", err)
	}
	go func() {
		res, _, _, err = externalRes.Lookup(&q, "")
		if err != nil {
			log.Fatalf("Error resolving: %w", err)
		}
		fmt.Printf("External: %v\n", res)
	}()
	go func() {
		res, _, _, err = externalRes2.Lookup(&q, "")
		if err != nil {
			log.Fatalf("Error resolving: %w", err)
		}
		fmt.Printf("External: %v\n", res)
	}()

	res, _, _, err = iterativeRes.Lookup(&q1, "")
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

}
