package main

import (
	"fmt"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"

	log "github.com/sirupsen/logrus"
)

// TODO PHillip, remove this file, just for testing

func main() {
	fmt.Println("Hello, World!")
	r, err := zdns.NewExternalResolver()
	if err != nil {
		log.Fatal("Error creating resolver: %w", err)
	}
	q := zdns.Question{
		Name:  "www.google.com",
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	}
	res, err := r.Lookup(&q)
	if err != nil {
		log.Fatal("Error resolving: %w", err)
	}
	fmt.Println(res)

}
