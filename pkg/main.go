package main

import (
	"fmt"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/cmd"
	"github.com/zmap/zdns/pkg/zdns"

	log "github.com/sirupsen/logrus"
)

// TODO PHillip, remove this file, just for testing

func library() {
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

	iterativeRes, err := zdns.InitResolver(config)
	if err != nil {
		log.Fatal("Error creating iterative zdns: %w", err)
	}

	res, _, _, err := iterativeRes.IterativeLookup(&q)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

	// Multiple resolvers, single cache
	cache := zdns.Cache{}
	cache.Init(10000)

	config = zdns.NewResolverConfig()
	config.ExternalNameServers = []string{"1.1.1.1:53"}
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
		res, _, err = externalRes.ExternalLookup(&q, "")
		if err != nil {
			log.Fatalf("Error resolving: %w", err)
		}
		fmt.Printf("External: %v\n", res)
	}()
	go func() {
		res, _, err = externalRes2.ExternalLookup(&q, "")
		if err != nil {
			log.Fatalf("Error resolving: %w", err)
		}
		fmt.Printf("External: %v\n", res)
	}()

	res, _, _, err = iterativeRes.IterativeLookup(&q1)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

}

func cli() {
	cmd.Execute()

}

func main() {
	//library()
	cli()
}
