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
	"github.com/zmap/zdns/internal/util"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	googleDNSResolverAddr       = "8.8.8.8:53"
	defaultNameServerConfigFile = "/etc/resolv.conf"

	defaultTimeout   = 15 * time.Second
	defaultCacheSize = 10000

	// TODO Phillip - probably should put all defaults up here from the two constructors and the newResolver function
)

// TODO Phillip - Probably want to rename this
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

	ipv4Lookup bool
	ipv6Lookup bool

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

// NewExternalResolver creates a new Resolver that will perform DNS resolution using an external resolver (ex: 1.1.1.1)
func NewExternalResolver() (*Resolver, error) {
	r, err := newResolver()
	if err != nil {
		return nil, fmt.Errorf("unable to create new resolver: %w", err)
	}

	r.isIterative = false

	// configure the default name servers the OS is using
	ns, err := GetDNSServers(defaultNameServerConfigFile)
	if err != nil {
		ns = util.GetDefaultResolvers()
		log.Warn("Unable to parse resolvers file with error %w. Using ZDNS defaults: ", err, strings.Join(ns, ", "))
	}
	r.nameServers = ns
	log.Info("No name servers specified. will use: ", strings.Join(r.nameServers, ", "))

	return r, nil
}

// NewIterativeResolver creates a new Resolver that will perform iterative DNS resolution using a cache for top-level domains
// If cache is nil, one will be instantiated in this constructor.
func NewIterativeResolver(cache *Cache) (*Resolver, error) {
	r, err := newResolver()
	if err != nil {
		return nil, fmt.Errorf("unable to create new resolver: %w", err)
	}
	if cache != nil {
		// use caller's cache
		r.cache = cache
	} else {
		r.cache = new(Cache)
		r.cache.Init(defaultCacheSize)
	}
	r.isIterative = true
	r.iterativeTimeout = 4 * time.Second
	r.maxDepth = 10
	// use the set of 13 root name servers
	r.nameServers = RootServers[:]
	return r, nil
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

func (r *Resolver) WithNameServers(nameServers []string) *Resolver {
	r.nameServers = nameServers
	return r
}

func (r *Resolver) ShouldTrace(shouldTrace bool) *Resolver {
	r.shouldTrace = shouldTrace
	return r
}

func (r *Resolver) WithLookuper(lu Lookuper) *Resolver {
	r.lookupClient = lu
	return r
}

func (r *Resolver) VerboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}

// newResolver has the common setup for all resolvers
func newResolver() (*Resolver, error) {
	r := &Resolver{
		isIterative:  false,
		lookupClient: LookupClient{},

		blacklist: blacklist.New(),
		blMu:      sync.Mutex{},
		retries:   1,

		ipv4Lookup: false,
		ipv6Lookup: false,
	}
	// TODO - Phillip make this changeable
	log.SetLevel(log.DebugLevel)
	// set-up persistent TCP/UDP connections and conn for UDP socket re-use
	// Step 1: get the local address
	conn, err := net.Dial("udp", googleDNSResolverAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to find default IP address to open socket: %w", err)
	}
	r.localAddr = conn.LocalAddr().(*net.UDPAddr).IP
	// cleanup socket
	if err = conn.Close(); err != nil {
		log.Warn("Unable to close test connection to Google Public DNS: ", err)
	}

	// Step 2: set up the connections and sockets
	if err = r.setupConnectionsAndSockets(defaultTimeout, r.localAddr); err != nil {
		return nil, fmt.Errorf("unable to setup persistent sockets/connections: %w", err)
	}
	return r, nil
}

func (r *Resolver) setupConnectionsAndSockets(timeout time.Duration, localAddr net.IP) error {
	r.udpClient = new(dns.Client)
	r.udpClient.Timeout = timeout
	r.udpClient.Dialer = &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.UDPAddr{IP: localAddr},
	}
	// create Packet Conn for use throughout thread's life
	conn, err := net.ListenUDP("udp", &net.UDPAddr{localAddr, 0, ""})
	if err != nil {
		return fmt.Errorf("unable to create socket: %w", err)
	}
	r.conn = new(dns.Conn)
	r.conn.Conn = conn
	// create a tcp socket for use throughout thread's life
	r.tcpClient = new(dns.Client)
	r.tcpClient.Net = "tcp"
	r.tcpClient.Timeout = timeout
	r.tcpClient.Dialer = &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: localAddr},
	}
	return nil
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
