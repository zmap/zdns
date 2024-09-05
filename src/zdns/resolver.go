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
	DefaultLoopbackIPv4Addr      = "127.0.0.1"
	DefaultLoopbackIPv6Addr      = "[::1]"
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
	ExternalNameServersV4 []NameServer // v4 name servers used for external lookups
	ExternalNameServersV6 []NameServer // v6 name servers used for external lookups
	RootNameServersV4     []NameServer // v4 root servers used for iterative lookups
	RootNameServersV6     []NameServer // v6 root servers used for iterative lookups
	LookupAllNameServers  bool         // perform the lookup via all the nameservers for the domain
	FollowCNAMEs          bool         // whether iterative lookups should follow CNAMEs/DNAMEs
	DNSConfigFilePath     string       // path to the DNS config file, ex: /etc/resolv.conf

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
		if isValid, reason := ns.IsValid(); !isValid {
			return fmt.Errorf("invalid external name server: %s", reason)
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
		if isValid, reason := ns.IsValid(); !isValid {
			return fmt.Errorf("invalid root name server: %s", reason)
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
		if ns.IP.IsLinkLocalUnicast() || ns.IP.IsLinkLocalMulticast() {
			return fmt.Errorf("link-local IPv6 external/root nameservers are not supported: %v", ns.IP)
		}
	}

	return nil
}

func (rc *ResolverConfig) PrintInfo() {
	log.Infof("using local addresses: %v", util.Concat(rc.LocalAddrsV4, rc.LocalAddrsV6))
	externalNameServers := util.Concat(rc.ExternalNameServersV4, rc.ExternalNameServersV6)
	rootNameServers := util.Concat(rc.RootNameServersV4, rc.RootNameServersV6)
	externalNameServerStrings := make([]string, 0, len(externalNameServers))
	rootNameServerStrings := make([]string, 0, len(rootNameServers))
	for _, ns := range externalNameServers {
		externalNameServerStrings = append(externalNameServerStrings, ns.String())
	}
	for _, ns := range rootNameServers {
		rootNameServerStrings = append(rootNameServerStrings, ns.String())
	}
	log.Infof("for non-iterative lookups, using external nameservers: %s", strings.Join(externalNameServerStrings, ", "))
	log.Infof("for iterative lookups, using nameservers: %s", strings.Join(rootNameServerStrings, ", "))
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

	blacklist                   *blacklist.SafeBlacklist
	userPreferredIPv4LocalAddrs []net.IP        // user-supplied local IPv4 addresses, we'll prefer to use these
	userPreferredIPv6LocalAddrs []net.IP        // user-supplied local IPv6 addresses, we'll prefer to use these
	connInfoIPv4Internet        *ConnectionInfo // used for IPv4 lookups to Internet-facing nameservers
	connInfoIPv6Internet        *ConnectionInfo // used for IPv6 lookups to Internet-facing nameservers
	connInfoIPv4Loopback        *ConnectionInfo // used for IPv4 lookups to loopback nameservers
	connInfoIPv6Loopback        *ConnectionInfo // used for IPv6 lookups to loopback nameservers

	retries  int
	logLevel log.Level

	transportMode         transportMode
	ipVersionMode         IPVersionMode
	iterationIPPreference IterationIPPreference
	shouldRecycleSockets  bool

	iterativeTimeout     time.Duration
	timeout              time.Duration // timeout for the network conns
	maxDepth             int
	externalNameServers  []NameServer // name servers used by external lookups (either OS or user specified)
	rootNameServers      []NameServer // root servers used for iterative lookups
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
	// Deep copy local address so Resolver is independent of the config
	r.userPreferredIPv4LocalAddrs = DeepCopyIPs(config.LocalAddrsV4)
	r.userPreferredIPv6LocalAddrs = DeepCopyIPs(config.LocalAddrsV6)
	// need to deep-copy here so we're not reliant on the state of the resolver config post-resolver creation
	r.externalNameServers = make([]NameServer, 0, len(config.ExternalNameServersV4)+len(config.ExternalNameServersV6))
	if config.IPVersionMode == IPv4Only || config.IPVersionMode == IPv4OrIPv6 {
		// copy over IPv4 nameservers
		for _, ns := range config.ExternalNameServersV4 {
			r.externalNameServers = append(r.externalNameServers, *ns.DeepCopy())
		}
	}
	if config.IPVersionMode == IPv6Only || config.IPVersionMode == IPv4OrIPv6 {
		// copy over IPv6 nameservers
		for _, ns := range config.ExternalNameServersV6 {
			r.externalNameServers = append(r.externalNameServers, *ns.DeepCopy())
		}
	}
	r.iterativeTimeout = config.IterativeTimeout
	r.maxDepth = config.MaxDepth
	r.rootNameServers = make([]NameServer, 0, len(config.RootNameServersV4)+len(config.RootNameServersV6))
	if r.ipVersionMode != IPv6Only && len(config.RootNameServersV4) == 0 {
		// add IPv4 root servers
		for _, ns := range RootServersV4 {
			r.rootNameServers = append(r.rootNameServers, *ns.DeepCopy())
		}
	} else if r.ipVersionMode != IPv6Only {
		for _, ns := range config.RootNameServersV4 {
			r.rootNameServers = append(r.rootNameServers, *ns.DeepCopy())
		}
	}
	if r.ipVersionMode != IPv4Only && len(config.RootNameServersV6) == 0 {
		// add IPv4 root servers
		for _, ns := range RootServersV6 {
			r.rootNameServers = append(r.rootNameServers, *ns.DeepCopy())
		}
	} else if r.ipVersionMode != IPv4Only {
		for _, ns := range config.RootNameServersV6 {
			r.rootNameServers = append(r.rootNameServers, *ns.DeepCopy())
		}
	}
	return r, nil
}

// getConnectionInfo uses the name server to determine if a loopback vs. non-loopback or IPv4/v6 connection should be used
// If the Resolver does not have a connection info for the name server, it will create one.
// ConnectionInfo objects are created on an as-needed basis
func (r *Resolver) getConnectionInfo(nameServer *NameServer) (*ConnectionInfo, error) {
	// what local addresses should we use?
	isNSIPv6 := util.IsIPv6(&nameServer.IP)
	isLoopback := nameServer.IP.IsLoopback()
	// check if we have a pre-existing conn info
	if isNSIPv6 && isLoopback && r.connInfoIPv6Loopback != nil {
		return r.connInfoIPv6Loopback, nil
	} else if isNSIPv6 && r.connInfoIPv6Internet != nil {
		return r.connInfoIPv6Internet, nil
	} else if isLoopback && r.connInfoIPv4Loopback != nil {
		return r.connInfoIPv4Loopback, nil
	} else if r.connInfoIPv4Internet != nil {
		// must be IPv4 non-loopback
		return r.connInfoIPv4Internet, nil
	}

	// no existing ConnInfo, create a new one
	// r.localAddrs contain either user-supplied or default local addresses
	// If one satisfying our conditions is available, use it.
	var userIPs []net.IP
	if isNSIPv6 {
		userIPs = r.userPreferredIPv6LocalAddrs
	} else {
		userIPs = r.userPreferredIPv4LocalAddrs
	}
	// Shuffle the slice in random order so that we don't always use the same local address
	rand.Shuffle(len(userIPs), func(i, j int) {
		userIPs[i], userIPs[j] = userIPs[j], userIPs[i]
	})
	var localAddr *net.IP
	for _, ip := range userIPs {
		if isLoopback == ip.IsLoopback() {
			localAddr = &ip
			break
		}
	}

	if localAddr == nil {
		// none of the user-supplied IPs match the conditions, we need to select one
		if isLoopback && isNSIPv6 {
			ip := net.ParseIP(DefaultLoopbackIPv6Addr)
			localAddr = &ip
		} else if isLoopback {
			ip := net.ParseIP(DefaultLoopbackIPv4Addr)
			localAddr = &ip
		} else {
			// non-loopback, attempt to reach the nameserver from the internet and get the local addr. used
			conn, err := net.Dial("udp", nameServer.String())
			if err != nil {
				return nil, fmt.Errorf("unable to find default IP address to open socket: %w", err)
			}
			localAddr = &conn.LocalAddr().(*net.UDPAddr).IP
			// cleanup socket
			if err = conn.Close(); err != nil {
				log.Error("unable to close test connection to Google public DNS: ", err)
			}
		}
		if localAddr != nil {
			log.Infof("none of the user-supplied local addresses could connect to name server %s, using local address %s", nameServer.String(), localAddr.String())
		}
	}
	if localAddr == nil {
		return nil, errors.New("unable to find local address for connection")
	}
	connInfo := &ConnectionInfo{
		localAddr: *localAddr,
	}
	if r.shouldRecycleSockets {
		// create persistent connection
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: connInfo.localAddr})
		if err != nil {
			return nil, fmt.Errorf("unable to create UDP connection: %w", err)
		}
		connInfo.conn = new(dns.Conn)
		connInfo.conn.Conn = conn
	}

	usingUDP := r.transportMode == UDPOrTCP || r.transportMode == UDPOnly
	if usingUDP {
		connInfo.udpClient = new(dns.Client)
		connInfo.udpClient.Timeout = r.timeout
		connInfo.udpClient.Dialer = &net.Dialer{
			Timeout:   r.timeout,
			LocalAddr: &net.UDPAddr{IP: connInfo.localAddr},
		}
	}
	usingTCP := r.transportMode == UDPOrTCP || r.transportMode == TCPOnly
	if usingTCP {
		connInfo.tcpClient = new(dns.Client)
		connInfo.tcpClient.Net = "tcp"
		connInfo.tcpClient.Timeout = r.timeout
		connInfo.tcpClient.Dialer = &net.Dialer{
			Timeout:   r.timeout,
			LocalAddr: &net.TCPAddr{IP: connInfo.localAddr},
		}
	}
	// save the connection info for future use
	if isNSIPv6 && isLoopback {
		r.connInfoIPv6Loopback = connInfo
	} else if isNSIPv6 {
		r.connInfoIPv6Internet = connInfo
	} else if isLoopback {
		r.connInfoIPv4Loopback = connInfo
	} else {
		r.connInfoIPv4Internet = connInfo
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
func (r *Resolver) ExternalLookup(q *Question, dstServer *NameServer) (*SingleQueryResult, Trace, Status, error) {
	if r.isClosed {
		log.Fatal("resolver has been closed, cannot perform lookup")
	}

	if dstServer == nil {
		dstServer = r.randomExternalNameServer()
		log.Info("no name server provided for external lookup, using  random external name server: ", dstServer)
	}
	dstServer.PopulateDefaultPort()
	if isValid, reason := dstServer.IsValid(); !isValid {
		return nil, nil, StatusIllegalInput, fmt.Errorf("destination server %s is invalid: %s", dstServer.String(), reason)
	}
	dstServer.PopulateDefaultPort()
	if isValid, reason := dstServer.IsValid(); !isValid {
		return nil, nil, StatusIllegalInput, fmt.Errorf("could not parse name server (%s): %s", dstServer.String(), reason)
	}
	// dstServer has been validated and has a port, continue with lookup
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
	if r.connInfoIPv4Internet != nil && r.connInfoIPv4Internet.conn != nil {
		if err := r.connInfoIPv4Internet.conn.Close(); err != nil {
			log.Errorf("error closing IPv4 connection: %v", err)
		}
	}
	if r.connInfoIPv6Internet != nil && r.connInfoIPv6Internet.conn != nil {
		if err := r.connInfoIPv6Internet.conn.Close(); err != nil {
			log.Errorf("error closing IPv6 connection: %v", err)
		}
	}
	if r.connInfoIPv4Loopback != nil && r.connInfoIPv4Loopback.conn != nil {
		if err := r.connInfoIPv4Loopback.conn.Close(); err != nil {
			log.Errorf("error closing IPv4 loopback connection: %v", err)
		}
	}
	if r.connInfoIPv6Loopback != nil && r.connInfoIPv6Loopback.conn != nil {
		if err := r.connInfoIPv6Loopback.conn.Close(); err != nil {
			log.Errorf("error closing IPv6 loopback connection: %v", err)
		}
	}
}

func (r *Resolver) randomExternalNameServer() *NameServer {
	l := len(r.externalNameServers)
	if r.externalNameServers == nil || l == 0 {
		log.Fatal("no external name servers specified")
	}
	return &r.externalNameServers[rand.Intn(l)]
}

func (r *Resolver) randomRootNameServer() *NameServer {
	l := len(r.rootNameServers)
	if r.rootNameServers == nil || l == 0 {
		log.Fatal("no root name servers specified")
	}
	return &r.rootNameServers[rand.Intn(l)]
}

func (r *Resolver) verboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}
