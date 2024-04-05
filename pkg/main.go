package main

import (
	"fmt"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"

	log "github.com/sirupsen/logrus"
)

// TODO PHillip, remove this file, just for testing

func main() {
	config := zdns.NewResolverConfig()
	config.ShouldTrace = true
	config.IsIterative = true
	iterativeRes, err := zdns.InitResolver(config)
	if err != nil {
		log.Fatal("Error creating iterative zdns: %w", err)
	}
	config = zdns.NewResolverConfig()
	config.NameServers = []string{"1.1.1.1:53"}
	config.IsIterative = false
	externalRes, err := zdns.InitResolver(config)
	//eliminate double constructors
	if err != nil {
		log.Fatal("Error creating external zdns: %w", err)
	}
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
	res, _, _, err := externalRes.Lookup(&q, nil)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("External: %v\n", res)

	res, _, _, err = iterativeRes.Lookup(&q, nil)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

	res, _, _, err = iterativeRes.Lookup(&q1, nil)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

}
