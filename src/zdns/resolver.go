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
	defaultIterationIPPreference = PreferIPv4
	DefaultNameServerConfigFile  = "/etc/resolv.conf"
	defaultLookupAllNameServers  = false
)

// ResolverConfig is a struct that holds all the configuration options for a Resolver. It is used to create a new Resolver.
type ResolverConfig struct {
	Cache        *Cache
	CacheSize    int      // don't use both cache and cacheSize
	LookupClient Lookuper // either a functional or mock Lookuper client for testing

	Blacklist *blacklist.SafeBlacklist

	LocalAddrsV4 []net.IP // ipv4 local addresses to use for connections, one will be selected at random for the resolver
	LocalAddrsV6 []net.IP // ipv6 local addresses to use for connections, one will be selected at random for the resolver

	Retries  int
	LogLevel log.Level

	TransportMode         transportMode
	IPVersionMode         IPVersionMode
	IterationIPPreference IterationIPPreference // preference for IPv4 or IPv6 lookups in iterative queries
	ShouldRecycleSockets  bool

	IterativeTimeout      time.Duration // applicable to iterative queries only, timeout for a single iteration step
	Timeout               time.Duration // timeout for the resolution of a single name
	MaxDepth              int
	ExternalNameServersV4 []string // v4 name servers used for external lookups
	ExternalNameServersV6 []string // v6 name servers used for external lookups
	RootNameServersV4     []string // v4 root servers used for iterative lookups
	RootNameServersV6     []string // v6 root servers used for iterative lookups
	LookupAllNameServers  bool     // perform the lookup via all the nameservers for the domain
	FollowCNAMEs          bool     // whether iterative lookups should follow CNAMEs/DNAMEs
	DNSConfigFilePath     string   // path to the DNS config file, ex: /etc/resolv.conf

	DNSSecEnabled       bool
	EdnsOptions         []dns.EDNS0
	CheckingDisabledBit bool
}

// Validate checks if the ResolverConfig is valid, returns an error describing the issue if it is not.
// This function should not modify the config
func (rc *ResolverConfig) Validate() error {
	if isValid, reason := rc.TransportMode.isValid(); !isValid {
		return fmt.Errorf("invalid transport mode: %s", reason)
	}
	if isValid, reason := rc.IPVersionMode.IsValid(); !isValid {
		return fmt.Errorf("invalid IP version mode: %s", reason)
	}
	if rc.Cache != nil && rc.CacheSize != 0 {
		return errors.New("cannot use both cache and cacheSize")
	}

	// External Nameservers
	if rc.IPVersionMode != IPv6Only && len(rc.ExternalNameServersV4) == 0 {
		// If IPv4 is supported, we require at least one IPv4 external nameserver
		return errors.New("must have at least one external IPv4 name server if IPv4 mode is enabled")
	}
	if rc.IPVersionMode != IPv4Only && len(rc.ExternalNameServersV6) == 0 {
		// If IPv6 is supported, we require at least one IPv6 external nameserver
		return errors.New("must have at least one external IPv6 name server if IPv6 mode is enabled")
	}

	// Validate all nameservers have ports and are valid IPs
	for _, ns := range util.Concat(rc.ExternalNameServersV4, rc.ExternalNameServersV6) {
		ipString, _, err := net.SplitHostPort(ns)
		if err != nil {
			return fmt.Errorf("could not parse external name server (%s), must be valid IP and have port appended, ex: 1.2.3.4:53 or [::1]:53", ns)
		}
		ip := net.ParseIP(ipString)
		if ip == nil {
			return fmt.Errorf("could not parse external name server (%s), must be valid IP and have port appended, ex: 1.2.3.4:53 or [::1]:53", ns)
		}
	}
	// Root Nameservers
	if rc.IPVersionMode != IPv6Only && len(rc.RootNameServersV4) == 0 {
		// If IPv4 is supported, we require at least one IPv4 root nameserver
		return errors.New("must have at least one root IPv4 name server if IPv4 mode is enabled")
	}
	if rc.IPVersionMode != IPv4Only && len(rc.RootNameServersV6) == 0 {
		// If IPv6 is supported, we require at least one IPv6 root nameserver
		return errors.New("must have at least one root IPv6 name server if IPv6 mode is enabled")
	}

	// Validate all nameservers have ports and are valid IPs
	for _, ns := range util.Concat(rc.RootNameServersV4, rc.RootNameServersV6) {
		ipString, _, err := net.SplitHostPort(ns)
		if err != nil {
			return fmt.Errorf("could not parse root name server (%s), must be valid IP and have port appended, ex: 1.2.3.4:53 or [::1]:53", ns)
		}
		ip := net.ParseIP(ipString)
		if ip == nil {
			return fmt.Errorf("could not parse root name server (%s), must be valid IP and have port appended, ex: 1.2.3.4:53 or [::1]:53", ns)
		}
	}

	// Local Addresses
	if rc.IPVersionMode != IPv6Only && len(rc.LocalAddrsV4) == 0 {
		return errors.New("must have a local IPv4 address to send traffic from")
	}
	if rc.IPVersionMode != IPv4Only && len(rc.LocalAddrsV6) == 0 {
		return errors.New("must have a local IPv6 address to send traffic from")
	}

	// Validate all local addresses are valid IPs
	for _, ip := range util.Concat(rc.LocalAddrsV4, rc.LocalAddrsV6) {
		if ip == nil {
			return errors.New("local address cannot be nil")
		}
		if ip.To4() == nil && ip.To16() == nil {
			return fmt.Errorf("invalid local address: %v", ip)
		}
	}

	// Validate IPv4 local addresses are IPv4
	for _, ip := range rc.LocalAddrsV4 {
		if ip.To4() == nil {
			return fmt.Errorf("local address is not IPv4: %v", ip)
		}
	}

	// Validate IPv6 local addresses are IPv6
	for _, ip := range rc.LocalAddrsV6 {
		if !util.IsIPv6(&ip) {
			return fmt.Errorf("IPv6 local address (%v) is not IPv6", ip)
		}
	}

	// Ensure no IPv6 link-local/multicast local addresses are used
	for _, ip := range rc.LocalAddrsV6 {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("link-local IPv6 local addresses are not supported: %v", ip)
		}
	}

	// Ensure no IPv6 link-local/multicast external/root nameservers are used
	for _, ns := range util.Concat(rc.ExternalNameServersV6, rc.RootNameServersV6) {
		ip, _, err := util.SplitHostPort(ns)
		if err != nil {
			return errors.Wrapf(err, "could not split host and port for nameserver: %s", ns)
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("link-local IPv6 external/root nameservers are not supported: %v", ip)
		}
	}

	if err := rc.validateLoopbackConsistency(); err != nil {
		return errors.Wrap(err, "could not validate loopback consistency")
	}

	return nil
}

// validateLoopbackConsistency checks that the following is true
// - either all nameservers AND all local addresses are loopback, or none are
func (rc *ResolverConfig) validateLoopbackConsistency() error {
	allLocalAddrs := util.Concat(rc.LocalAddrsV4, rc.LocalAddrsV6)
	allExternalNameServers := util.Concat(rc.ExternalNameServersV4, rc.ExternalNameServersV6)
	allRootNameServers := util.Concat(rc.RootNameServersV4, rc.RootNameServersV6)
	allIPsLength := len(allLocalAddrs) + len(allExternalNameServers) + len(allRootNameServers)
	allIPs := make([]net.IP, 0, allIPsLength)
	allIPs = append(allIPs, allLocalAddrs...)
	for _, ns := range util.Concat(allExternalNameServers, allRootNameServers) {
		ip, _, err := util.SplitHostPort(ns)
		if err != nil {
			return errors.Wrapf(err, "could not split host and port for nameserver: %s", ns)
		}
		allIPs = append(allIPs, ip)
	}
	allIPsLoopback := true
	noneIPsLoopback := true
	for _, ip := range allIPs {
		if ip.IsLoopback() {
			noneIPsLoopback = false
		} else {
			allIPsLoopback = false
		}
	}
	if allIPsLoopback == noneIPsLoopback {
		return fmt.Errorf("cannot mix loopback and non-loopback local addresses (%v) and name servers (%v)", allLocalAddrs, util.Concat(allExternalNameServers, allRootNameServers))
	}
	return nil
}

func (rc *ResolverConfig) PrintInfo() {
	log.Infof("using local addresses: %v", util.Concat(rc.LocalAddrsV4, rc.LocalAddrsV6))
	log.Infof("for non-iterative lookups, using external nameservers: %s", strings.Join(util.Concat(rc.ExternalNameServersV4, rc.ExternalNameServersV6), ", "))
	log.Infof("for iterative lookups, using nameservers: %s", strings.Join(util.Concat(rc.RootNameServersV4, rc.RootNameServersV6), ", "))
}

// NewResolverConfig creates a new ResolverConfig with default values.
func NewResolverConfig() *ResolverConfig {
	c := new(Cache)
	c.Init(defaultCacheSize)
	return &ResolverConfig{
		LookupClient: LookupClient{},
		Cache:        c,

		Blacklist:    blacklist.New(),
		LocalAddrsV4: []net.IP{},
		LocalAddrsV6: []net.IP{},

		TransportMode:         defaultTransportMode,
		IPVersionMode:         defaultIPVersionMode,
		IterationIPPreference: defaultIterationIPPreference,
		ShouldRecycleSockets:  defaultShouldRecycleSockets,
		LookupAllNameServers:  false,
		FollowCNAMEs:          defaultFollowCNAMEs,

		Retries:  defaultRetries,
		LogLevel: defaultLogVerbosity,

		Timeout:          defaultTimeout,
		IterativeTimeout: defaultIterativeTimeout,
		MaxDepth:         defaultMaxDepth,

		DNSSecEnabled:       defaultDNSSECEnabled,
		CheckingDisabledBit: defaultCheckingDisabledBit,
	}
}

type ConnectionInfo struct {
	udpClient *dns.Client
	tcpClient *dns.Client
	conn      *dns.Conn
	localAddr net.IP
}

// Resolver is a struct that holds the state of a DNS resolver. It is used to perform DNS lookups.
type Resolver struct {
	cache        *Cache
	lookupClient Lookuper // either a functional or mock Lookuper client for testing

	blacklist *blacklist.SafeBlacklist

	connInfoIPv4 *ConnectionInfo
	connInfoIPv6 *ConnectionInfo

	retries  int
	logLevel log.Level

	transportMode         transportMode
	ipVersionMode         IPVersionMode
	iterationIPPreference IterationIPPreference
	shouldRecycleSockets  bool

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
	if err := config.Validate(); err != nil {
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

		transportMode:         config.TransportMode,
		ipVersionMode:         config.IPVersionMode,
		iterationIPPreference: config.IterationIPPreference,
		shouldRecycleSockets:  config.ShouldRecycleSockets,
		followCNAMEs:          config.FollowCNAMEs,

		timeout: config.Timeout,

		dnsSecEnabled:       config.DNSSecEnabled,
		ednsOptions:         config.EdnsOptions,
		checkingDisabledBit: config.CheckingDisabledBit,
	}
	log.SetLevel(r.logLevel)
	if config.IPVersionMode != IPv6Only {
		// create connection info for IPv4
		connInfo, err := getConnectionInfo(config.LocalAddrsV4, config.TransportMode, config.Timeout, config.ShouldRecycleSockets)
		if err != nil {
			return nil, fmt.Errorf("could not create connection info for IPv4: %w", err)
		}
		r.connInfoIPv4 = connInfo
	}
	if config.IPVersionMode != IPv4Only {
		// create connection info for IPv6
		connInfo, err := getConnectionInfo(config.LocalAddrsV6, config.TransportMode, config.Timeout, config.ShouldRecycleSockets)
		if err != nil {
			return nil, fmt.Errorf("could not create connection info for IPv6: %w", err)
		}
		r.connInfoIPv6 = connInfo
	}
	// need to deep-copy here so we're not reliant on the state of the resolver config post-resolver creation
	r.externalNameServers = make([]string, 0)
	if config.IPVersionMode == IPv4Only || config.IPVersionMode == IPv4OrIPv6 {
		ipv4Nameservers := make([]string, len(config.ExternalNameServersV4))
		// copy over IPv4 nameservers
		elemsCopied := copy(ipv4Nameservers, config.ExternalNameServersV4)
		if elemsCopied != len(config.ExternalNameServersV4) {
			log.Fatal("failed to copy entire IPv4 name servers list from config")
		}
		r.externalNameServers = append(r.externalNameServers, ipv4Nameservers...)
	}
	ipv6Nameservers := make([]string, len(config.ExternalNameServersV6))
	if config.IPVersionMode == IPv6Only || config.IPVersionMode == IPv4OrIPv6 {
		// copy over IPv6 nameservers
		elemsCopied := copy(ipv6Nameservers, config.ExternalNameServersV6)
		if elemsCopied != len(config.ExternalNameServersV6) {
			log.Fatal("failed to copy entire IPv6 name servers list from config")
		}
		r.externalNameServers = append(r.externalNameServers, ipv6Nameservers...)
	}
	// deep copy external name servers from config to resolver
	r.iterativeTimeout = config.IterativeTimeout
	r.maxDepth = config.MaxDepth
	r.rootNameServers = make([]string, 0, len(config.RootNameServersV4)+len(config.RootNameServersV6))
	if r.ipVersionMode != IPv6Only && len(config.RootNameServersV4) == 0 {
		// add IPv4 root servers
		r.rootNameServers = append(r.rootNameServers, RootServersV4...)
	} else if r.ipVersionMode != IPv6Only {
		r.rootNameServers = append(r.rootNameServers, config.RootNameServersV4...)
	}
	if r.ipVersionMode != IPv4Only && len(config.RootNameServersV6) == 0 {
		// add IPv6 root servers
		r.rootNameServers = append(r.rootNameServers, RootServersV6...)
	} else if r.ipVersionMode != IPv4Only {
		r.rootNameServers = append(r.rootNameServers, config.RootNameServersV6...)
	}
	return r, nil
}

func getConnectionInfo(localAddr []net.IP, transportMode transportMode, timeout time.Duration, shouldRecycleSockets bool) (*ConnectionInfo, error) {
	connInfo := &ConnectionInfo{
		localAddr: localAddr[rand.Intn(len(localAddr))],
	}
	if shouldRecycleSockets {
		// create persistent connection
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: connInfo.localAddr})
		if err != nil {
			return nil, fmt.Errorf("unable to create UDP connection: %w", err)
		}
		connInfo.conn = new(dns.Conn)
		connInfo.conn.Conn = conn
	}

	usingUDP := transportMode == UDPOrTCP || transportMode == UDPOnly
	if usingUDP {
		connInfo.udpClient = new(dns.Client)
		connInfo.udpClient.Timeout = timeout
		connInfo.udpClient.Dialer = &net.Dialer{
			Timeout:   timeout,
			LocalAddr: &net.UDPAddr{IP: connInfo.localAddr},
		}
	}
	usingTCP := transportMode == UDPOrTCP || transportMode == TCPOnly
	if usingTCP {
		connInfo.tcpClient = new(dns.Client)
		connInfo.tcpClient.Net = "tcp"
		connInfo.tcpClient.Timeout = timeout
		connInfo.tcpClient.Dialer = &net.Dialer{
			Timeout:   timeout,
			LocalAddr: &net.TCPAddr{IP: connInfo.localAddr},
		}
	}
	return connInfo, nil
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
		return nil, nil, StatusIllegalInput, fmt.Errorf("could not parse name server (%s): %w. Correct format IPv4 1.1.1.1:53 or IPv6 [::1]:53", dstServer, err)
	}
	if dstServer != dstServerWithPort {
		log.Info("no port provided for external lookup, using default port 53")
	}
	dstServerIP, _, err := util.SplitHostPort(dstServerWithPort)
	if err != nil {
		return nil, nil, StatusIllegalInput, fmt.Errorf("could not parse name server (%s): %w. Correct format IPv4 1.1.1.1:53 or IPv6 [::1]:53", dstServer, err)
	}
	if util.IsIPv6(&dstServerIP) && r.connInfoIPv6 == nil {
		return nil, nil, StatusIllegalInput, fmt.Errorf("IPv6 external lookup requested for domain %s but no IPv6 local addresses provided to resolver", q.Name)
	} else if dstServerIP.To4() != nil && r.connInfoIPv4 == nil {
		return nil, nil, StatusIllegalInput, fmt.Errorf("IPv4 external lookup requested for domain %s but no IPv4 local addresses provided to resolver", q.Name)
	}
	// check that local address and dstServer's don't have a loopback mismatch
	if dstServerIP.To4() != nil && r.connInfoIPv4.localAddr.IsLoopback() != dstServerIP.IsLoopback() {
		return nil, nil, StatusIllegalInput, errors.New("cannot mix loopback and non-loopback addresses")
	} else if util.IsIPv6(&dstServerIP) && r.connInfoIPv6.localAddr.IsLoopback() != dstServerIP.IsLoopback() {
		return nil, nil, StatusIllegalInput, errors.New("cannot mix loopback and non-loopback addresses")
	}
	// dstServer has been validated and has a port, continue with lookup
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
	if r.connInfoIPv4.conn != nil {
		if err := r.connInfoIPv4.conn.Close(); err != nil {
			log.Errorf("error closing IPv4 connection: %v", err)
		}
	}
	if r.connInfoIPv6.conn != nil {
		if err := r.connInfoIPv6.conn.Close(); err != nil {
			log.Errorf("error closing IPv6 connection: %v", err)
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
