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
	"net"
	"strings"
	"sync"
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
	defaultShouldUseIPv4         = false
	defaultShouldUseIPv6         = false // TODO Phillip - these are weird, like if both are false what do we do? Should maybe be an enum
	defaultNameServerConfigFile  = "/etc/resolv.conf"
)
const ()

// A ResolverBuilder allows the user to configure a Resolver starting with sane defaults and then setting up any customized behavior they desire. This
// prevents changing the underlying Resolver struct after creation, reducing edge cases. After configuring the ResolverBuilder with rb.With...() methods,
// the user can call rb.Build...() to create a new Resolver. A ResolverBuilder can only create one Resolver, to preserve thread-safety.
type ResolverBuilder struct {
	nameServersSet bool
	localAddrSet   bool
	hasBeenBuilt   bool // flag to prevent creating two resolvers from the same builder. This is a limitation of the current design
	r              *Resolver
}

func NewResolverBuilder() *ResolverBuilder {
	c := new(Cache)
	c.Init(defaultCacheSize)
	return &ResolverBuilder{
		r: &Resolver{
			lookupClient: LookupClient{},
			cache:        c,

			blacklist: blacklist.New(),
			blMu:      sync.Mutex{},

			maxDepth:             defaultMaxDepth,
			shouldRecycleSockets: defaultShouldRecycleSockets,
			retries:              defaultRetries,
			iterativeTimeout:     defaultIterativeTimeout,
			timeout:              defaultTimeout,
			shouldTrace:          defaultShouldTrace,
			checkingDisabled:     defaultCheckingDisabledBit,
			dnsSecEnabled:        defaultDNSSECEnabled,

			transportMode: defaultTransportMode,
			shouldUseIPv4: defaultShouldUseIPv4,
			shouldUseIPv6: defaultShouldUseIPv6,

			logLevel: defaultLogVerbosity,
		},
	}
}

func (rb *ResolverBuilder) WithNameServers(nameServers []string) *ResolverBuilder {
	rb.nameServersSet = true
	rb.r.nameServers = nameServers
	return rb
}

func (rb *ResolverBuilder) WithShouldTrace(shouldTrace bool) *ResolverBuilder {
	rb.r.shouldTrace = shouldTrace
	return rb
}

func (rb *ResolverBuilder) WithLookuper(lu Lookuper) *ResolverBuilder {
	rb.r.lookupClient = lu
	return rb
}

// BuildExternalResolver creates a new Resolver that will perform DNS resolution using an external resolver (ex: 1.1.1.1)
func (rb *ResolverBuilder) BuildExternalResolver() (*Resolver, error) {
	r, err := rb.buildResolverHelper()
	if err != nil {
		return nil, fmt.Errorf("unable to create new external resolver: %w", err)
	}

	r.isIterative = false

	if !rb.nameServersSet {
		// configure the default name servers the OS is using
		ns, err := GetDNSServers(defaultNameServerConfigFile)
		if err != nil {
			ns = util.GetDefaultResolvers()
			log.Warn("Unable to parse resolvers file with error %w. Using ZDNS defaults: ", err, strings.Join(ns, ", "))
		}
		r.nameServers = ns
		log.Info("No name servers specified. will use: ", strings.Join(r.nameServers, ", "))
	}

	return r, nil
}

// BuildIterativeResolver creates a new Resolver that will perform iterative DNS resolution using a cache for top-level domains
// If cache is nil, one will be instantiated in this constructor.
func (rb *ResolverBuilder) BuildIterativeResolver(cache *Cache) (*Resolver, error) {
	r, err := rb.buildResolverHelper()
	if err != nil {
		return nil, fmt.Errorf("unable to create new iterative resolver: %w", err)
	}
	if cache != nil {
		// use caller's cache
		r.cache = cache
	} else {
		r.cache = new(Cache)
		r.cache.Init(defaultCacheSize)
	}
	r.isIterative = true

	if !rb.nameServersSet {
		// use the set of 13 root name servers
		r.nameServers = RootServers[:]
	}
	return r, nil
}

// isValid checks if the resolver is valid
// Returns true, nil or false, error where error describes what is invalid about the resolver builder. Called before building the resolver
func (rb *ResolverBuilder) isValid() (bool, error) {
	if rb.hasBeenBuilt {
		return false, fmt.Errorf("cannot change resolver builder after resolver has been built")
	}
	if isValid, reason := rb.r.transportMode.isValid(); !isValid {
		return false, reason
	}
	return true, nil
}

// buildResolverHelper has the common build logic for all resolvers
func (rb *ResolverBuilder) buildResolverHelper() (*Resolver, error) {
	if isValid, err := rb.isValid(); !isValid {
		return nil, fmt.Errorf("invalid resolver: %w", err)
	}
	log.SetLevel(rb.r.logLevel)
	if !rb.localAddrSet {
		// set the local address to the default IP address
		conn, err := net.Dial("udp", googleDNSResolverAddr)
		if err != nil {
			return nil, fmt.Errorf("unable to find default IP address to open socket: %w", err)
		}
		rb.r.localAddr = conn.LocalAddr().(*net.UDPAddr).IP
		// cleanup socket
		if err = conn.Close(); err != nil {
			log.Warn("Unable to close test connection to Google Public DNS: ", err)
		}
	}
	if rb.r.shouldRecycleSockets {
		// create persistent connection
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: rb.r.localAddr})
		if err != nil {
			return nil, fmt.Errorf("unable to create UDP connection: %w", err)
		}
		rb.r.conn = new(dns.Conn)
		rb.r.conn.Conn = conn
	}

	if rb.r.transportMode == UDPOrTCP || rb.r.transportMode == UDPOnly {
		rb.r.udpClient = new(dns.Client)
		rb.r.udpClient.Timeout = rb.r.timeout
		rb.r.udpClient.Dialer = &net.Dialer{
			Timeout:   rb.r.timeout,
			LocalAddr: &net.UDPAddr{IP: rb.r.localAddr},
		}
	}
	if rb.r.transportMode == UDPOrTCP || rb.r.transportMode == TCPOnly {
		rb.r.tcpClient = new(dns.Client)
		rb.r.tcpClient.Net = "tcp"
		rb.r.tcpClient.Timeout = rb.r.timeout
		rb.r.tcpClient.Dialer = &net.Dialer{
			Timeout:   rb.r.timeout,
			LocalAddr: &net.TCPAddr{IP: rb.r.localAddr},
		}

	}
	return rb.r, nil
}
