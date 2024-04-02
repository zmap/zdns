package main

import (
	"fmt"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"

	log "github.com/sirupsen/logrus"
)

// TODO PHillip, remove this file, just for testing

func main() {
	iterativeRes, err := zdns.NewResolverBuilder().WithShouldTrace(true).BuildIterativeResolver(nil)
	if err != nil {
		log.Fatal("Error creating iterative resolver: %w", err)
	}
	externalRes, err := zdns.NewResolverBuilder().WithNameServers([]string{"1.1.1.1:53"}).WithShouldTrace(true).BuildExternalResolver()
	if err != nil {
		log.Fatal("Error creating external resolver: %w", err)
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
	res, err := externalRes.Lookup(&q)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("External: %v\n", res)

	res, err = iterativeRes.Lookup(&q)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

	res, err = iterativeRes.Lookup(&q1)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)

}
