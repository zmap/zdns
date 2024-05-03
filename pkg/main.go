package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/cmd"
	"github.com/zmap/zdns/pkg/modules/mxlookup"
	"github.com/zmap/zdns/pkg/zdns"
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

	res, trace, status, err := iterativeRes.IterativeLookup(&q)
	if err != nil {
		log.Fatalf("Error resolving: %w", err)
	}
	fmt.Printf("Iterative: %v\n", res)
	fmt.Printf("trace: %v\n", trace)
	fmt.Printf("status: %v\n", status)

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
		res, _, _, err := externalRes.ExternalLookup(&q, "")
		if err != nil {
			log.Fatalf("Error resolving: %w", err)
		}
		fmt.Printf("External: %v\n", res)
	}()
	go func() {
		res, _, _, err := externalRes2.ExternalLookup(&q, "")
		if err != nil {
			log.Fatalf("Error resolving: %w", err)
		}
		fmt.Printf("External: %v\n", res)
	}()

	go func() {
		res, trace, _, err := iterativeRes.IterativeLookup(&q1)
		if err != nil {
			log.Fatalf("Error resolving: %w", err)
		}
		fmt.Printf("Iterative: %v\n", res)
		fmt.Printf("Iterative trace: %v\n", trace)
	}()
	mx := mxlookup.Init(true, false, 1000)
	mxRes, trace, status, err := mx.DoLookup(iterativeRes, "google.com", "")
	if err != nil {
		log.Fatalf("Error resolving MXLookup: %w", err)
	}
	fmt.Printf("MXLookup: %v\n", mxRes)

}

func cli() {
	cmd.Execute()

}

func main() {
	//library()
	cli()
}
