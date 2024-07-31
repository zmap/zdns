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
	"sync"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	blacklist "github.com/zmap/zdns/src/internal/safeblacklist"
	"github.com/zmap/zdns/src/internal/util"
)

const (
	LoopbackAddrString      = "127.0.0.1"
	googleDNSResolverAddr   = "8.8.8.8:53"
	googleDNSResolverAddrV6 = "[2001:4860:4860::8888]:53"

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
	sync.Mutex   // lock for populateAndValidate
	Cache        *Cache
	CacheSize    int      // don't use both cache and cacheSize
	LookupClient Lookuper // either a functional or mock Lookuper client for testing

	Blacklist *blacklist.SafeBlacklist

	LocalAddrsV4 []net.IP // ipv4 local addresses to use for connections, one will be selected at random for the resolver
	LocalAddrsV6 []net.IP // ipv6 local addresses to use for connections, one will be selected at random for the resolver

	Retries  int
	LogLevel log.Level

	TransportMode        transportMode
	IPVersionMode        IPVersionMode
	ShouldRecycleSockets bool

	IterativeTimeout      time.Duration // applicable to iterative queries only, timeout for a single iteration step
	Timeout               time.Duration // timeout for the resolution of a single name
	MaxDepth              int
	ExternalNameServersV4 []string // v4 name servers used for external lookups
	ExternalNameServersV6 []string // v6 name servers used for external lookups
	LookupAllNameServers  bool     // perform the lookup via all the nameservers for the domain
	FollowCNAMEs          bool     // whether iterative lookups should follow CNAMEs/DNAMEs
	DNSConfigFilePath     string   // path to the DNS config file, ex: /etc/resolv.conf

	DNSSecEnabled       bool
	EdnsOptions         []dns.EDNS0
	CheckingDisabledBit bool
}

// PopulateAndValidate checks if the ResolverConfig is valid and populates any missing fields with default values.
func (rc *ResolverConfig) PopulateAndValidate() error {
	// This is called in every InitResolver while re-using the config, so it needs to be thread-safe
	rc.Lock()
	defer rc.Unlock()
	// populate any missing values in resolver config
	if err := rc.populateResolverConfig(); err != nil {
		return errors.Wrap(err, "could not populate resolver config")
	}

	// Potentially, a name-server could be listed multiple times by either the user or in the OS's respective /etc/resolv.conf
	// De-dupe
	rc.ExternalNameServersV4 = util.RemoveDuplicates(rc.ExternalNameServersV4)
	rc.ExternalNameServersV6 = util.RemoveDuplicates(rc.ExternalNameServersV6)

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
	for _, ns := range append(rc.ExternalNameServersV4, rc.ExternalNameServersV6...) {
		if _, _, err := net.SplitHostPort(ns); err != nil {
			return fmt.Errorf("invalid name server: %s", ns)
		}
	}
	for _, addr := range append(rc.LocalAddrsV4, rc.LocalAddrsV6...) {
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

	// If we're using IPv6, we need both a local IPv6 address and an IPv6 nameserver
	if rc.IPVersionMode != IPv4Only && (len(rc.LocalAddrsV6) == 0 || len(rc.ExternalNameServersV6) == 0) {
		if rc.IPVersionMode == IPv6Only {
			return errors.New("IPv6 only mode requires both local IPv6 addresses and IPv6 nameservers")
		}
		log.Info("cannot use IPv6 mode without both local IPv6 addresses and IPv6 nameservers, defaulting to IPv4 only")
		rc.IPVersionMode = IPv4Only
	}
	// If we're using IPv4, we need both a local IPv4 address and an IPv4 nameserver
	if rc.IPVersionMode != IPv6Only && (len(rc.LocalAddrsV4) == 0 || len(rc.ExternalNameServersV4) == 0) {
		if rc.IPVersionMode == IPv4Only {
			return errors.New("IPv4 only mode requires both local IPv4 addresses and IPv4 nameservers")
		}
		log.Info("cannot use IPv4 mode without both local IPv4 addresses and IPv4 nameservers, defaulting to IPv6 only")
		rc.IPVersionMode = IPv6Only
	}

	return nil
}

func (rc *ResolverConfig) populateResolverConfig() error {
	if err := rc.populateNameServers(); err != nil {
		return errors.Wrap(err, "could not populate name servers")
	}
	if err := rc.populateLocalAddrs(); err != nil {
		return errors.Wrap(err, "could not populate local addresses")
	}
	// if there is no IPv6 local addresses, we should not use IPv6
	if len(rc.LocalAddrsV6) == 0 && rc.IPVersionMode != IPv4Only {
		log.Warn("no IPv6 local addresses found, only using IPv4")
		rc.IPVersionMode = IPv4Only
	}

	return rc.populateLocalAddrs()
}

// populateLocalAddrs populates/validates the local addresses for the resolver.
// If no local addresses are set, it will find a IP address and IPv6 address, if applicable.
func (rc *ResolverConfig) populateLocalAddrs() error {
	if rc.IPVersionMode != IPv6Only && len(rc.LocalAddrsV4) == 0 {
		// localAddr not set, so we need to find the default IP address
		conn, err := net.Dial("udp", googleDNSResolverAddr)
		if err != nil {
			return fmt.Errorf("unable to find default IP address to open socket: %w", err)
		}
		rc.LocalAddrsV4 = append(rc.LocalAddrsV4, conn.LocalAddr().(*net.UDPAddr).IP)
		// cleanup socket
		if err = conn.Close(); err != nil {
			log.Error("unable to close test connection to Google public DNS: ", err)
		}
	}

	if rc.IPVersionMode != IPv4Only && len(rc.LocalAddrsV6) == 0 {
		// localAddr not set, so we need to find the default IPv6 address
		conn, err := net.Dial("udp", googleDNSResolverAddrV6)
		if err != nil {
			if rc.IPVersionMode == IPv6Only {
				// if user selected only IPv6 and we can't find a default IPv6 address, return an error
				return errors.New("unable to find default IPv6 address to open socket")
			}
			// user didn't specify IPv6 only, so we'll just log the issue and continue with IPv4
			log.Warn("unable to find default IPv6 address to open socket, using IPv4 only: ", err)
			rc.IPVersionMode = IPv4Only
			return nil
		}
		rc.LocalAddrsV6 = append(rc.LocalAddrsV6, conn.LocalAddr().(*net.UDPAddr).IP)
		// cleanup socket
		if err = conn.Close(); err != nil {
			log.Error("unable to close test connection to Google IPv6 public DNS: ", err)
		}

		nonLinkLocalIPv6 := make([]net.IP, 0, len(rc.LocalAddrsV6))
		for _, ip := range rc.LocalAddrsV6 {
			if util.IsIPv6(&ip) && (ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()) {
				log.Debug("ignoring link-local IPv6 nameserver: ", ip)
				continue
			}
			nonLinkLocalIPv6 = append(nonLinkLocalIPv6, ip)
		}
		rc.LocalAddrsV6 = nonLinkLocalIPv6
	}
	return nil
}

func (rc *ResolverConfig) populateNameServers() error {
	if len(rc.ExternalNameServersV4) == 0 && len(rc.ExternalNameServersV6) == 0 {
		// if nameservers aren't set, use OS' default
		nsv4, nsv6, err := GetDNSServers(rc.DNSConfigFilePath)
		if err != nil {
			nsv4, nsv6 = util.GetDefaultResolvers()
			log.Warnf("Unable to parse resolvers file (%v). Using ZDNS defaults: %s", err, strings.Join(append(nsv4, nsv6...), ", "))
		}
		rc.ExternalNameServersV4 = nsv4
		rc.ExternalNameServersV6 = nsv6
	}

	// ensure port is set for all nameservers
	portValidatedNSsV4 := make([]string, 0, len(rc.ExternalNameServersV4))
	portValidatedNSsV6 := make([]string, 0, len(rc.ExternalNameServersV6))
	// check that the nameservers have a port and append one if necessary
	for _, ns := range rc.ExternalNameServersV4 {
		portNS, err := util.AddDefaultPortToDNSServerName(ns)
		if err != nil {
			return fmt.Errorf("could not parse name server: %s", ns)
		}
		portValidatedNSsV4 = append(portValidatedNSsV4, portNS)
	}
	for _, ns := range rc.ExternalNameServersV6 {
		portNS, err := util.AddDefaultPortToDNSServerName(ns)
		if err != nil {
			return fmt.Errorf("could not parse name server: %s", ns)
		}
		portValidatedNSsV6 = append(portValidatedNSsV6, portNS)
	}
	// remove link-local IPv6 nameservers
	nonLinkLocalIPv6NSs := make([]string, 0, len(portValidatedNSsV6))
	for _, ns := range portValidatedNSsV6 {
		ip, _, err := util.SplitHostPort(ns)
		if err != nil {
			return errors.Wrapf(err, "could not split host and port for nameserver: %s", ns)
		}
		if util.IsIPv6(&ip) && (ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()) {
			log.Debug("ignoring link-local IPv6 nameserver: ", ns)
			continue
		}
		nonLinkLocalIPv6NSs = append(nonLinkLocalIPv6NSs, ns)
	}
	rc.ExternalNameServersV4 = portValidatedNSsV4
	rc.ExternalNameServersV6 = nonLinkLocalIPv6NSs

	return nil
}

// validateLoopbackConsistency checks that the following is true
// - if using a loopback nameserver, all nameservers are loopback and vice-versa
// - if using a loopback local address, all local addresses are loopback and vice-versa
// - either all nameservers AND all local addresses are loopback, or none are
func (rc *ResolverConfig) validateLoopbackConsistency() error {
	allNameServers := append(rc.ExternalNameServersV4, rc.ExternalNameServersV6...)
	// check if all nameservers are loopback or non-loopback
	allNameserversLoopback := true
	noneNameserversLoopback := true
	for _, ns := range allNameServers {
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
	if len(append(rc.ExternalNameServersV4, rc.ExternalNameServersV6...)) > 0 && loopbackNameserverMismatch {
		return fmt.Errorf("cannot mix loopback and non-loopback nameservers: %v", allNameServers)
	}

	allLocalAddrsLoopback := true
	noneLocalAddrsLoopback := true
	allLocalAddrs := append(rc.LocalAddrsV4, rc.LocalAddrsV6...)
	// check if all local addresses are loopback or non-loopback
	for _, addr := range allLocalAddrs {
		if addr.IsLoopback() {
			noneLocalAddrsLoopback = false
		} else {
			allLocalAddrsLoopback = false
		}
	}
	if len(allLocalAddrs) > 0 && allLocalAddrsLoopback == noneLocalAddrsLoopback {
		return fmt.Errorf("cannot mix loopback and non-loopback local addresses: %v", allLocalAddrs)
	}

	// Both nameservers and local addresses are completely loopback or non-loopback
	// if using loopback nameservers, override local addresses to be loopback and warn user
	if allNameserversLoopback && noneLocalAddrsLoopback {
		log.Warn("nameservers are loopback, setting local address to loopback to match")
		rc.LocalAddrsV4 = []net.IP{net.ParseIP(LoopbackAddrString)}
		// we ignore link-local local addresses, so nothing to be done for IPv6
	} else if noneNameserversLoopback && allLocalAddrsLoopback {
		return errors.New("using loopback local addresses with non-loopback nameservers is not supported. " +
			"Consider setting nameservers to loopback addresses assuming you have a local DNS server")
	}
	return nil
}

func (rc *ResolverConfig) PrintInfo() {
	log.Infof("using local addresses: %v", append(rc.LocalAddrsV4, rc.LocalAddrsV6...))
	log.Infof("for non-iterative lookups, using nameservers: %s", strings.Join(append(rc.ExternalNameServersV4, rc.ExternalNameServersV6...), ", "))
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

		rootNameServers: []string{},
	}
	log.SetLevel(r.logLevel)
	// create connection info for IPv4
	if config.IPVersionMode == IPv4Only || config.IPVersionMode == IPv4OrIPv6 {
		connInfo, err := getConnectionInfo(config.LocalAddrsV4, config.TransportMode, config.Timeout, config.ShouldRecycleSockets)
		if err != nil {
			return nil, fmt.Errorf("could not create connection info for IPv4: %w", err)
		}
		r.connInfoIPv4 = connInfo
	}
	// create connection info for IPv6
	if config.IPVersionMode == IPv6Only || config.IPVersionMode == IPv4OrIPv6 {
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
	// use the set of 13 root name servers
	if r.ipVersionMode != IPv6Only {
		// add IPv4 root servers
		r.rootNameServers = append(r.rootNameServers, RootServersV4...)
	}
	if r.ipVersionMode != IPv4Only {
		// add IPv6 root servers
		r.rootNameServers = append(r.rootNameServers, RootServersV6...)
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
		return nil, nil, StatusIllegalInput, fmt.Errorf("could not parse name server (%s): %w", dstServer, err)
	}
	if dstServer != dstServerWithPort {
		log.Info("no port provided for external lookup, using default port 53")
	}
	// Check for loopback mis-match
	nsIP, _, err := util.SplitHostPort(dstServerWithPort)
	if err != nil {
		return nil, nil, StatusIllegalInput, fmt.Errorf("could not split host and port for name server: %w", err)
	}
	if nsIP.To4() != nil && r.connInfoIPv4 != nil && r.connInfoIPv4.localAddr.IsLoopback() != nsIP.IsLoopback() {
		return nil, nil, StatusIllegalInput, errors.New("nameserver (%s) and local address(%s) must be both loopback or non-loopback")
	} else if util.IsIPv6(&nsIP) && nsIP.IsLoopback() {
		return nil, nil, StatusIllegalInput, errors.New("cannot use IPv6 loopback nameserver")
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
