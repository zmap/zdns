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
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	blacklist "github.com/zmap/zdns/src/internal/safeblacklist"
	"github.com/zmap/zdns/src/internal/util"
)

const (
	// TODO - we'll need to update this when we add IPv6 support
	LoopbackAddrString    = "127.0.0.1"
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
	defaultFollowCNAMEs          = true  // Follow CNAMEs/DNAMEs in iterative queries
	defaultCacheSize             = 10000
	defaultShouldTrace           = false
	defaultDNSSECEnabled         = false
	defaultIPVersionMode         = IPv4Only
	DefaultNameServerConfigFile  = "/etc/resolv.conf"
	defaultLookupAllNameServers  = false
)

// ResolverConfig is a struct that holds all the configuration options for a Resolver. It is used to create a new Resolver.
type ResolverConfig struct {
	Cache        *Cache
	CacheSize    int      // don't use both cache and cacheSize
	LookupClient Lookuper // either a functional or mock Lookuper client for testing

	Blacklist *blacklist.SafeBlacklist

	LocalAddrs []net.IP // local addresses to use for connections, one will be selected at random for the resolver

	Retries  int
	LogLevel log.Level

	TransportMode        transportMode
	IPVersionMode        IPVersionMode
	ShouldRecycleSockets bool

	IterativeTimeout     time.Duration // applicable to iterative queries only, timeout for a single iteration step
	Timeout              time.Duration // timeout for the resolution of a single name
	MaxDepth             int
	ExternalNameServers  []string // name servers used for external lookups
	LookupAllNameServers bool     // perform the lookup via all the nameservers for the domain
	FollowCNAMEs         bool     // whether iterative lookups should follow CNAMEs/DNAMEs
	DNSConfigFilePath    string   // path to the DNS config file, ex: /etc/resolv.conf

	DNSSecEnabled       bool
	EdnsOptions         []dns.EDNS0
	CheckingDisabledBit bool
}

// PopulateAndValidate checks if the ResolverConfig is valid and populates any missing fields with default values.
func (rc *ResolverConfig) PopulateAndValidate() error {
	// populate any missing values in resolver config
	if err := rc.populateResolverConfig(); err != nil {
		return errors.Wrap(err, "could not populate resolver config")
	}

	// Potentially, a name-server could be listed multiple times by either the user or in the OS's respective /etc/resolv.conf
	// De-dupe
	rc.ExternalNameServers = util.RemoveDuplicates(rc.ExternalNameServers)

	if isValid, reason := rc.TransportMode.isValid(); !isValid {
		return fmt.Errorf("invalid transport mode: %s", reason)
	}
	if isValid, reason := rc.IPVersionMode.IsValid(); !isValid {
		return fmt.Errorf("invalid IP version mode: %s", reason)
	}
	if rc.Cache != nil && rc.CacheSize != 0 {
		return errors.New("cannot use both cache and cacheSize")
	}

	// Check that all nameservers/local addresses are valid
	for _, ns := range rc.ExternalNameServers {
		if _, _, err := net.SplitHostPort(ns); err != nil {
			return fmt.Errorf("invalid name server: %s", ns)
		}
	}
	for _, addr := range rc.LocalAddrs {
		if addr == nil {
			return errors.New("local address cannot be nil")
		}
		if addr.To4() == nil && addr.To16() == nil {
			// Attempting to cast the LocalAddr to both IPv4/IPv6 has failed, so it's not a valid IP address
			return fmt.Errorf("invalid local address: %v", addr)
		}
	}

	if err := rc.validateLoopbackConsistency(); err != nil {
		return errors.Wrap(err, "could not validate loopback consistency")
	}

	return nil
}

func (rc *ResolverConfig) populateResolverConfig() error {
	// Nameservers
	if len(rc.ExternalNameServers) == 0 {
		// if nameservers aren't set, use OS' default
		ns, err := GetDNSServers(rc.DNSConfigFilePath)
		if err != nil {
			ns = util.GetDefaultResolvers()
			log.Warn("Unable to parse resolvers file. Using ZDNS defaults: ", strings.Join(ns, ", "))
		}
		rc.ExternalNameServers = ns
	} else {
		portValidatedNSs := make([]string, 0, len(rc.ExternalNameServers))
		// check that the nameservers have a port and append one if necessary
		for _, ns := range rc.ExternalNameServers {
			portNS, err := util.AddDefaultPortToDNSServerName(ns)
			if err != nil {
				return fmt.Errorf("could not parse name server: %s", ns)
			}
			portValidatedNSs = append(portValidatedNSs, portNS)
		}
		rc.ExternalNameServers = portValidatedNSs
	}
	// TODO - Remove when we add IPv6 support
	ipv4NameServers := make([]string, 0, len(rc.ExternalNameServers))
	for _, ns := range rc.ExternalNameServers {
		ip, _, err := util.SplitHostPort(ns)
		if err != nil {
			return fmt.Errorf("could not split host and port for nameserver: %s", ns)
		}
		if ip.To4() != nil {
			ipv4NameServers = append(ipv4NameServers, ns)
		}
	}
	rc.ExternalNameServers = ipv4NameServers

	// Local Addresses
	if len(rc.LocalAddrs) == 0 {
		// localAddr not set, so we need to find the default IP address
		conn, err := net.Dial("udp", googleDNSResolverAddr)
		if err != nil {
			return fmt.Errorf("unable to find default IP address to open socket: %w", err)
		}
		rc.LocalAddrs = append(rc.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
		// cleanup socket
		if err = conn.Close(); err != nil {
			log.Error("unable to close test connection to Google public DNS: ", err)
		}
	}

	// TODO - Remove when we add IPv6 support
	ipv4LocalAddrs := make([]net.IP, 0, len(rc.LocalAddrs))
	for _, addr := range rc.LocalAddrs {
		if addr.To4() != nil {
			ipv4LocalAddrs = append(ipv4LocalAddrs, addr)
		} else {
			log.Info("ignoring non-IPv4 local address: ", addr)
		}
	}
	rc.LocalAddrs = ipv4LocalAddrs
	return nil
}

// validateLoopbackConsistency checks that the following is true
// - if using a loopback nameserver, all nameservers are loopback and vice-versa
// - if using a loopback local address, all local addresses are loopback and vice-versa
// - either all nameservers AND all local addresses are loopback, or none are
func (rc *ResolverConfig) validateLoopbackConsistency() error {

	// check if all nameservers are loopback or non-loopback
	allNameserversLoopback := true
	noneNameserversLoopback := true
	for _, ns := range rc.ExternalNameServers {
		ip, _, err := util.SplitHostPort(ns)
		if err != nil {
			return errors.Wrapf(err, "could not split host and port for nameserver: %s", ns)
		}
		if ip.IsLoopback() {
			noneNameserversLoopback = false
		} else {
			allNameserversLoopback = false
		}
	}
	loopbackNameserverMismatch := allNameserversLoopback == noneNameserversLoopback
	if len(rc.ExternalNameServers) > 0 && loopbackNameserverMismatch {
		return fmt.Errorf("cannot mix loopback and non-loopback nameservers: %v", rc.ExternalNameServers)
	}

	allLocalAddrsLoopback := true
	noneLocalAddrsLoopback := true
	// check if all local addresses are loopback or non-loopback
	for _, addr := range rc.LocalAddrs {
		if addr.IsLoopback() {
			noneLocalAddrsLoopback = false
		} else {
			allLocalAddrsLoopback = false
		}
	}
	if len(rc.LocalAddrs) > 0 && allLocalAddrsLoopback == noneLocalAddrsLoopback {
		return fmt.Errorf("cannot mix loopback and non-loopback local addresses: %v", rc.LocalAddrs)
	}

	// Both nameservers and local addresses are completely loopback or non-loopback
	// if using loopback nameservers, override local addresses to be loopback and warn user
	if allNameserversLoopback && noneLocalAddrsLoopback {
		log.Warn("nameservers are loopback, setting local address to loopback to match")
		rc.LocalAddrs = []net.IP{net.ParseIP(LoopbackAddrString)}
	} else if noneNameserversLoopback && allLocalAddrsLoopback {
		return errors.New("using loopback local addresses with non-loopback nameservers is not supported. " +
			"Consider setting nameservers to loopback addresses assuming you have a local DNS server")
	}
	return nil
}

func (rc *ResolverConfig) PrintInfo() {
	log.Infof("using local addresses: %v", rc.LocalAddrs)
	log.Infof("for non-iterative lookups, using nameservers: %s", strings.Join(rc.ExternalNameServers, ", "))
}

// NewResolverConfig creates a new ResolverConfig with default values.
func NewResolverConfig() *ResolverConfig {
	c := new(Cache)
	c.Init(defaultCacheSize)
	return &ResolverConfig{
		LookupClient: LookupClient{},
		Cache:        c,

		Blacklist:  blacklist.New(),
		LocalAddrs: nil,

		TransportMode:        defaultTransportMode,
		IPVersionMode:        defaultIPVersionMode,
		ShouldRecycleSockets: defaultShouldRecycleSockets,
		LookupAllNameServers: false,
		FollowCNAMEs:         defaultFollowCNAMEs,

		Retries:  defaultRetries,
		LogLevel: defaultLogVerbosity,

		Timeout:          defaultTimeout,
		IterativeTimeout: defaultIterativeTimeout,
		MaxDepth:         defaultMaxDepth,

		DNSSecEnabled:       defaultDNSSECEnabled,
		CheckingDisabledBit: defaultCheckingDisabledBit,
	}
}

// Resolver is a struct that holds the state of a DNS resolver. It is used to perform DNS lookups.
type Resolver struct {
	cache        *Cache
	lookupClient Lookuper // either a functional or mock Lookuper client for testing

	blacklist *blacklist.SafeBlacklist

	udpClient *dns.Client
	tcpClient *dns.Client
	conn      *dns.Conn
	localAddr net.IP

	retries  int
	logLevel log.Level

	transportMode        transportMode
	ipVersionMode        IPVersionMode
	shouldRecycleSockets bool

	iterativeTimeout     time.Duration
	timeout              time.Duration // timeout for the network conns
	maxDepth             int
	externalNameServers  []string // name servers used by external lookups (either OS or user specified)
	rootNameServers      []string // root servers used for iterative lookups
	lookupAllNameServers bool
	followCNAMEs         bool // whether iterative lookups should follow CNAMEs/DNAMEs

	dnsSecEnabled       bool
	ednsOptions         []dns.EDNS0
	checkingDisabledBit bool
	isClosed            bool // true if the resolver has been closed, lookup will panic if called after Close
}

// InitResolver creates a new Resolver struct using the ResolverConfig. The Resolver is used to perform DNS lookups.
// It is safe to create multiple Resolvers with the same ResolverConfig but each resolver should perform only one lookup at a time.
// Returns a Resolver ptr and any error that occurred
func InitResolver(config *ResolverConfig) (*Resolver, error) {
	if err := config.PopulateAndValidate(); err != nil {
		return nil, fmt.Errorf("invalid resolver config: %w", err)
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
	// copy relevant all values from config to resolver
	r := &Resolver{
		cache:        c,
		lookupClient: config.LookupClient,

		blacklist: config.Blacklist,

		retries:              config.Retries,
		logLevel:             config.LogLevel,
		lookupAllNameServers: config.LookupAllNameServers,

		transportMode:        config.TransportMode,
		ipVersionMode:        config.IPVersionMode,
		shouldRecycleSockets: config.ShouldRecycleSockets,
		followCNAMEs:         config.FollowCNAMEs,

		timeout: config.Timeout,

		dnsSecEnabled:       config.DNSSecEnabled,
		ednsOptions:         config.EdnsOptions,
		checkingDisabledBit: config.CheckingDisabledBit,
	}
	log.SetLevel(r.logLevel)
	r.localAddr = config.LocalAddrs[rand.Intn(len(config.LocalAddrs))]

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
	r.externalNameServers = make([]string, len(config.ExternalNameServers))
	// deep copy external name servers from config to resolver
	elemsCopied := copy(r.externalNameServers, config.ExternalNameServers)
	if elemsCopied != len(config.ExternalNameServers) {
		log.Fatal("failed to copy entire name servers list from config")
	}
	r.iterativeTimeout = config.IterativeTimeout
	r.maxDepth = config.MaxDepth
	// use the set of 13 root name servers
	r.rootNameServers = RootServersV4[:]
	return r, nil
}

// ExternalLookup performs a single lookup of a DNS question, q,  against an external name server.
// dstServer, (ex: '1.1.1.1:53') can be set to over-ride the nameservers defined in the ResolverConfig.
// If dstServer is not  specified (ie. is an empty string), a random external name server will be used from the resolver's list of external name servers.
// Thread-safety note: It is UNSAFE to use the same Resolver object to perform multiple lookups concurrently. If you need to perform
// multiple lookups concurrently, create a new Resolver object for each concurrent lookup.
// Returns the result of the lookup, the trace of the lookup (what each nameserver along the lookup returned), the
// status of the lookup, and any error that occurred.
func (r *Resolver) ExternalLookup(q *Question, dstServer string) (*SingleQueryResult, Trace, Status, error) {
	if r.isClosed {
		log.Fatal("resolver has been closed, cannot perform lookup")
	}

	if dstServer == "" {
		dstServer = r.randomExternalNameServer()
		log.Info("no name server provided for external lookup, using  random external name server: ", dstServer)
	}
	dstServerWithPort, err := util.AddDefaultPortToDNSServerName(dstServer)
	if err != nil {
		return nil, nil, StatusIllegalInput, fmt.Errorf("could not parse name server (%s): %w", dstServer, err)
	}
	if dstServer != dstServerWithPort {
		log.Info("no port provided for external lookup, using default port 53")
	}
	dstServerIP, _, err := util.SplitHostPort(dstServerWithPort)
	if err != nil {
		return nil, nil, StatusIllegalInput, fmt.Errorf("could not parse name server (%s): %w", dstServer, err)
	}
	// check that local address and dstServer's don't have a loopback mismatch
	if r.localAddr.IsLoopback() != dstServerIP.IsLoopback() {
		return nil, nil, StatusIllegalInput, errors.New("cannot mix loopback and non-loopback addresses")

	}
	// dstServer has been validated and has a port
	dstServer = dstServerWithPort
	lookup, trace, status, err := r.lookupClient.DoSingleDstServerLookup(r, *q, dstServer, false)
	return lookup, trace, status, err
}

// IterativeLookup performs a single iterative lookup of a DNS question, q,  against a root name server. Iterative lookups
// follow nameservers from the root to the authoritative nameserver for the query.
// Thread-safety note: It is UNSAFE to use the same Resolver object to perform multiple lookups concurrently. If you need to perform
// multiple lookups concurrently, create a new Resolver object for each concurrent lookup.
// Returns the result of the lookup, the trace of the lookup (what each nameserver along the lookup returned), the
// status of the lookup, and any error that occurred.
func (r *Resolver) IterativeLookup(q *Question) (*SingleQueryResult, Trace, Status, error) {
	if r.isClosed {
		log.Fatal("resolver has been closed, cannot perform lookup")
	}
	return r.lookupClient.DoSingleDstServerLookup(r, *q, r.randomRootNameServer(), true)
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
	return r.rootNameServers[rand.Intn(l)]
}

func (r *Resolver) verboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}
