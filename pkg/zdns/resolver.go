/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
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

package zdns

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/go-iptree/blacklist"
	"math/rand"
	"net"
	"sync"
	"time"
)

type transportMode int

const (
	UDPOrTCP transportMode = iota
	UDPOnly
	TCPOnly
)

func (tm transportMode) isValid() (bool, error) {
	isValid := tm >= 0 && tm <= 2
	if !isValid {
		return false, fmt.Errorf("invalid transport mode: %d", tm)
	}
	return true, nil
}

// Left off trying to integrate this idea: https://refactoring.guru/design-patterns/builder/go/example
// namely that there will be the pattern of
// 1. Get ResolverBuilder
// 2. Set options on ResolverBuilder
// 3. Build External/Iterative Resolver

type Resolver struct {
	cache        *Cache
	lookupClient Lookuper // either a functional or mock Lookuper client for testing

	blacklist *blacklist.Blacklist
	blMu      sync.Mutex

	udpClient *dns.Client
	tcpClient *dns.Client
	conn      *dns.Conn
	localAddr net.IP

	retries     int
	shouldTrace bool
	logLevel    log.Level

	shouldUseIPv4        bool
	shouldUseIPv6        bool
	transportMode        transportMode
	shouldRecycleSockets bool

	isIterative          bool // whether the user desires iterative resolution or recursive
	iterativeTimeout     time.Duration
	timeout              time.Duration // timeout for the network conns
	maxDepth             int
	nameServers          []string
	lookupAllNameServers bool

	dnsSecEnabled    bool
	ednsOptions      []dns.EDNS0
	checkingDisabled bool
}

func (r *Resolver) Lookup(q *Question) (*Result, error) {
	var res interface{}
	var fullTrace Trace
	var status Status
	var err error

	ns := r.randomNameServer()
	if r.lookupAllNameServers {
		res, fullTrace, status, err = r.doLookupAllNameservers(*q, ns)
		if err != nil {
			return nil, fmt.Errorf("error resolving name %v for all name servers based on initial server %v: %w", q.Name, ns, err)
		}
	} else {
		res, fullTrace, status, err = r.lookupClient.DoSingleNameserverLookup(r, *q, ns)
		if err != nil {
			return nil, fmt.Errorf("error resolving name %v for a single name server %v: %w", q.Name, ns, err)
		}
	}
	return &Result{
		Data:   res,
		Trace:  fullTrace,
		Status: string(status),
	}, nil
}

func (r *Resolver) randomNameServer() string {
	if r.nameServers == nil || len(r.nameServers) == 0 {
		log.Fatal("No name servers specified")
	}
	l := len(r.nameServers)
	if l == 0 {
		log.Fatal("No name servers specified")
	}
	return r.nameServers[rand.Intn(l)]
}

func (r *Resolver) VerboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}
