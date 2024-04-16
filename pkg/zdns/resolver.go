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
	"github.com/zmap/zdns/internal/util"
	blacklist "github.com/zmap/zdns/pkg/safe_blacklist"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	googleDNSResolverAddr = "8.8.8.8:53"

	defaultTimeout               = 15 * time.Second // timeout for resolving a single name
	defaultIterativeTimeout      = 4 * time.Second  // timeout for single iteration in an iterative query
	defaultTransportMode         = UDPOrTCP
	defaultShouldRecycleSockets  = true
	defaultLogVerbosity          = 3 // 1 = lowest, 5 = highest
	defaultRetries               = 1
	defaultMaxDepth              = 10
	defaultCheckingDisabledBit   = false // Sends DNS packets with the CD bit set
	defaultNameServerModeEnabled = false // Treats input as nameservers to query with a static query rather than queries to send to a static name server
	defaultCacheSize             = 10000
	defaultShouldTrace           = false
	defaultDNSSECEnabled         = false
	defaultIPVersionMode         = IPv4OrIPv6
	defaultNameServerConfigFile  = "/etc/resolv.conf"
	defaultLookupAllNameServers  = false
)

// ResolverConfig is a struct that holds all the configuration options for a Resolver. It is used to create a new Resolver.
type ResolverConfig struct {
	Cache        *Cache
	CacheSize    int      // don't use both cache and cacheSize
	LookupClient Lookuper // either a functional or mock Lookuper client for testing

	Blacklist *blacklist.SafeBlacklist

	LocalAddr net.IP

	Retries     int
	ShouldTrace bool
	LogLevel    log.Level

	TransportMode        transportMode
	IPVersionMode        ipVersionMode
	ShouldRecycleSockets bool

	IsIterative         bool
	IterativeTimeout    time.Duration
	Timeout             time.Duration // timeout for the network conns
	MaxDepth            int
	ExternalNameServers []string // name servers used for external lookups
	//LookupAllNameServers bool // TODO Phillip - this should probably be a specific API call rather than a Config option

	DNSSecEnabled       bool
	EdnsOptions         []dns.EDNS0
	CheckingDisabledBit bool
}

func (rc *ResolverConfig) isValid() (bool, string) {
	if isValid, reason := rc.TransportMode.isValid(); !isValid {
		return false, reason
	}
	if isValid, reason := rc.IPVersionMode.isValid(); !isValid {
		return false, reason
	}
	if rc.Cache != nil && rc.CacheSize != 0 {
		return false, "cannot use both cache and cacheSize"
	}
	return true, ""
}

func NewResolverConfig() *ResolverConfig {
	c := new(Cache)
	c.Init(defaultCacheSize)
	return &ResolverConfig{
		LookupClient: LookupClient{},
		Cache:        c,

		Blacklist: blacklist.New(),

		TransportMode:        defaultTransportMode,
		IPVersionMode:        defaultIPVersionMode,
		ShouldRecycleSockets: defaultShouldRecycleSockets,

		Retries:     defaultRetries,
		ShouldTrace: defaultShouldTrace,
		LogLevel:    defaultLogVerbosity,

		Timeout:          defaultTimeout,
		IterativeTimeout: defaultIterativeTimeout,
		MaxDepth:         defaultMaxDepth,

		DNSSecEnabled:       defaultDNSSECEnabled,
		CheckingDisabledBit: defaultCheckingDisabledBit,
	}
}

type Resolver struct {
	cache        *Cache
	lookupClient Lookuper // either a functional or mock Lookuper client for testing

	blacklist *blacklist.SafeBlacklist

	udpClient *dns.Client
	tcpClient *dns.Client
	conn      *dns.Conn
	localAddr net.IP

	retries int
	// TODO Phillip - IMO the caller can use the trace or not, it's up to them to decide
	//shouldTrace bool
	logLevel log.Level

	transportMode        transportMode
	ipVersionMode        ipVersionMode
	shouldRecycleSockets bool

	iterativeTimeout     time.Duration
	timeout              time.Duration // timeout for the network conns
	maxDepth             int
	externalNameServers  []string // name servers used by external lookups (either OS or user specified)
	rootNameServers      []string // root servers used for iterative lookups
	lookupAllNameServers bool

	dnsSecEnabled       bool
	ednsOptions         []dns.EDNS0
	checkingDisabledBit bool
}

func InitResolver(config *ResolverConfig) (*Resolver, error) {
	if isValid, notValidReason := config.isValid(); !isValid {
		return nil, fmt.Errorf("invalid resolver config: %s", notValidReason)
	}
	var c *Cache
	if config.CacheSize != 0 {
		c = new(Cache)
		c.Init(config.CacheSize)
	} else if config.Cache != nil {
		c = config.Cache
	} else {
		c = new(Cache)
		c.Init(defaultCacheSize)
	}
	// copy relevent all values from config to resolver
	r := &Resolver{
		cache:        c,
		lookupClient: config.LookupClient,

		blacklist: config.Blacklist,

		localAddr: config.LocalAddr,

		retries:  config.Retries,
		logLevel: config.LogLevel,

		transportMode:        config.TransportMode,
		ipVersionMode:        config.IPVersionMode,
		shouldRecycleSockets: config.ShouldRecycleSockets,

		timeout: config.Timeout,

		dnsSecEnabled:       config.DNSSecEnabled,
		ednsOptions:         config.EdnsOptions,
		checkingDisabledBit: config.CheckingDisabledBit,
	}
	log.SetLevel(r.logLevel)
	if len(r.localAddr) == 0 {
		// localAddr not set, so we need to find the default IP address
		conn, err := net.Dial("udp", googleDNSResolverAddr)
		if err != nil {
			return nil, fmt.Errorf("unable to find default IP address to open socket: %w", err)
		}
		r.localAddr = conn.LocalAddr().(*net.UDPAddr).IP
		// cleanup socket
		if err = conn.Close(); err != nil {
			log.Error("unable to close test connection to Google public DNS: ", err)
		}
	}
	if r.shouldRecycleSockets {
		// create persistent connection
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: r.localAddr})
		if err != nil {
			return nil, fmt.Errorf("unable to create UDP connection: %w", err)
		}
		r.conn = new(dns.Conn)
		r.conn.Conn = conn
	}

	usingUDP := r.transportMode == UDPOrTCP || r.transportMode == UDPOnly
	if usingUDP {
		r.udpClient = new(dns.Client)
		r.udpClient.Timeout = r.timeout
		r.udpClient.Dialer = &net.Dialer{
			Timeout:   r.timeout,
			LocalAddr: &net.UDPAddr{IP: r.localAddr},
		}
	}
	usingTCP := r.transportMode == UDPOrTCP || r.transportMode == TCPOnly
	if usingTCP {
		r.tcpClient = new(dns.Client)
		r.tcpClient.Net = "tcp"
		r.tcpClient.Timeout = r.timeout
		r.tcpClient.Dialer = &net.Dialer{
			Timeout:   config.Timeout,
			LocalAddr: &net.TCPAddr{IP: r.localAddr},
		}
	}
	// TODO - Phillip double-check that this is a deep copy
	r.externalNameServers = make([]string, len(config.ExternalNameServers))
	elemsCopied := copy(r.externalNameServers, config.ExternalNameServers)
	if elemsCopied != len(config.ExternalNameServers) {
		log.Fatal("failed to copy entire name servers list from config")
	}
	r.iterativeTimeout = config.IterativeTimeout
	r.maxDepth = config.MaxDepth
	// r.lookupAllNameServers = config.LookupAllNameServers// TODO Phillip - this should probably be a specific API call rather than a Config option
	// use the set of 13 root name servers
	r.rootNameServers = RootServers[:]
	if r.externalNameServers == nil || len(r.externalNameServers) == 0 {
		// client did not specify name servers, so use the default from the OS
		ns, err := GetDNSServers(defaultNameServerConfigFile)
		if err != nil {
			ns = util.GetDefaultResolvers()
			log.Warn("Unable to parse resolvers file with error %w. Using ZDNS defaults: ", err, strings.Join(ns, ", "))
		}
		r.externalNameServers = ns
		log.Info("No name servers specified. will use: ", strings.Join(r.externalNameServers, ", "))
	}
	return r, nil
}

// TODO Phillip comment
func (r *Resolver) ExternalLookup(q *Question, dstServer string) (*SingleQueryResult, Status, error) {
	if dstServer == "" {
		dstServer = r.randomExternalNameServer()
	}
	lookup, _, status, err := r.lookupClient.DoSingleDstServerLookup(r, *q, dstServer, false)
	return lookup, status, err
}

// TODO Phillip comment
func (r *Resolver) IterativeLookup(q *Question) (*SingleQueryResult, Trace, Status, error) {
	return r.lookupClient.DoSingleDstServerLookup(r, *q, r.randomRootNameServer(), true)
}

func (r *Resolver) LookupAllNameservers(q *Question) (interface{}, error) {
	// TODO implement
	return nil, nil
	/*

		// DoLookupAllNameservers - lookup all nameservers at a given level, then perform a Loookup on each nameserver in that level
		func DoLookupAllNameservers(r *zdns.Resolver, q zdns.Question, nameServer string) (*zdns.CombinedResults, zdns.Trace, zdns.Status, error) {
			var retv zdns.CombinedResults
			var curServer string

			// Lookup both ipv4 and ipv6 addresses of nameservers.
			nsResults, nsTrace, nsStatus, nsError := DoNSLookup(r, q.Name, true, true, nameServer)

			// Terminate early if nameserver lookup also failed
			if nsStatus != zdns.STATUS_NOERROR {
				return nil, nsTrace, nsStatus, nsError
			}

			// fullTrace holds the complete trace including all lookups
			var fullTrace zdns.Trace = nsTrace
			var tmpRes zdns.SingleQueryResult

			for _, nserver := range nsResults.Servers {
				// Use all the ipv4 and ipv6 addresses of each nameserver
				nameserver := nserver.Name
				ips := append(nserver.IPv4Addresses, nserver.IPv6Addresses...)
				for _, ip := range ips {
					curServer = net.JoinHostPort(ip, "53")
					res, trace, status, err := r.Lookup(&q, curServer)

					fullTrace = append(fullTrace, trace...)
					tmpRes = zdns.SingleQueryResult{}
					if err == nil {
						tmpRes = *res
					}
					extendedResult := zdns.ExtendedResult{
						Res:        tmpRes,
						Status:     status,
						Nameserver: nameserver,
						Trace:      trace,
					}
					retv.Results = append(retv.Results, extendedResult)
				}
			}
			return &retv, fullTrace, zdns.STATUS_NOERROR, nil
		}
	*/
}

// Close cleans up any resources used by the resolver. This should be called when the resolver is no longer needed.
// Lookup will panic if called after Close.
func (r *Resolver) Close() {
	if r.conn != nil {
		if err := r.conn.Close(); err != nil {
			log.Errorf("error closing connection: %v", err)
		}
	}
}

func (r *Resolver) randomExternalNameServer() string {
	l := len(r.externalNameServers)
	if r.externalNameServers == nil || l == 0 {
		log.Fatal("no external name servers specified")
	}
	return r.externalNameServers[rand.Intn(l)]
}

func (r *Resolver) randomRootNameServer() string {
	l := len(r.rootNameServers)
	if r.rootNameServers == nil || l == 0 {
		log.Fatal("no root name servers specified")
	}
	return r.externalNameServers[rand.Intn(l)]
}

func (r *Resolver) verboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}
