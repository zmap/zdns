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
	defaultIPVersionMode         = IPv4OrIPv6
	defaultNameServerConfigFile  = "/etc/resolv.conf"
	defaultLookupAllNameServers  = false
)
const ()

// A ResolverConfigurer allows the user to configure a Resolver starting with sane defaults and then setting up any customized behavior they desire. This
// prevents changing the underlying Resolver struct after creation, reducing edge cases. After configuring the ResolverConfigurer using With...() methods,
// the user can call Build...() to create a new Resolver. A ResolverConfigurer can only create one Resolver, to preserve thread-safety.
type ResolverConfigurer struct {
	nameServersSet bool // flag to prevent setting the name servers in Build...() if user has set
	localAddrSet   bool // flag to prevent setting the local address in Build...() if user has set
	hasBeenBuilt   bool // flag to prevent creating two resolvers from the same configurer, for thread-safety
	r              *Resolver
}

func NewResolverBuilder() *ResolverConfigurer {
	c := new(Cache)
	c.Init(defaultCacheSize)
	return &ResolverConfigurer{
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
			checkingDisabledBit:  defaultCheckingDisabledBit,
			dnsSecEnabled:        defaultDNSSECEnabled,
			lookupAllNameServers: defaultLookupAllNameServers,

			transportMode: defaultTransportMode,
			ipVersionMode: defaultIPVersionMode,

			logLevel: defaultLogVerbosity,
		},
	}
}

func (rc *ResolverConfigurer) WithNameServers(nameServers []string) *ResolverConfigurer {
	rc.nameServersSet = true
	rc.r.nameServers = nameServers
	return rc
}

func (rc *ResolverConfigurer) WithLookuper(lu Lookuper) *ResolverConfigurer {
	rc.r.lookupClient = lu
	return rc
}

func (rc *ResolverConfigurer) WithMaxDepth(maxDepth int) *ResolverConfigurer {
	rc.r.maxDepth = maxDepth
	return rc
}

func (rc *ResolverConfigurer) WithShouldRecycleSockets(shouldRecycleSockets bool) *ResolverConfigurer {
	rc.r.shouldRecycleSockets = shouldRecycleSockets
	return rc
}

func (rc *ResolverConfigurer) WithRetries(retries int) *ResolverConfigurer {
	rc.r.retries = retries
	return rc
}

func (rc *ResolverConfigurer) WithIterativeTimeout(iterativeTimeout time.Duration) *ResolverConfigurer {
	rc.r.iterativeTimeout = iterativeTimeout
	return rc
}

func (rc *ResolverConfigurer) WithTimeout(timeout time.Duration) *ResolverConfigurer {
	rc.r.timeout = timeout
	return rc
}

func (rc *ResolverConfigurer) WithShouldTrace(shouldTrace bool) *ResolverConfigurer {
	rc.r.shouldTrace = shouldTrace
	return rc
}

func (rc *ResolverConfigurer) WithCheckingDisabled(checkingDisabled bool) *ResolverConfigurer {
	rc.r.checkingDisabledBit = checkingDisabled
	return rc
}

func (rc *ResolverConfigurer) WithDnsSecEnabled(dnsSecEnabled bool) *ResolverConfigurer {
	rc.r.dnsSecEnabled = dnsSecEnabled
	return rc
}

func (rc *ResolverConfigurer) WithTransportMode(transportMode transportMode) *ResolverConfigurer {
	rc.r.transportMode = transportMode
	return rc
}

func (rc *ResolverConfigurer) WithIpVersionMode(ipVersionMode ipVersionMode) *ResolverConfigurer {
	rc.r.ipVersionMode = ipVersionMode
	return rc
}

func (rc *ResolverConfigurer) WithLogLevel(logLevel log.Level) *ResolverConfigurer {
	rc.r.logLevel = logLevel
	return rc
}

// BuildExternalResolver creates a new Resolver that will perform DNS resolution using an external resolver (ex: 1.1.1.1)
func (rc *ResolverConfigurer) BuildExternalResolver() (*Resolver, error) {
	r, err := rc.buildResolverHelper()
	if err != nil {
		return nil, fmt.Errorf("unable to create new external resolver: %w", err)
	}

	r.isIterative = false

	if !rc.nameServersSet {
		// configure the default name servers the OS is using
		ns, err := GetDNSServers(defaultNameServerConfigFile)
		if err != nil {
			ns = util.GetDefaultResolvers()
			log.Warn("Unable to parse resolvers file with error %w. Using ZDNS defaults: ", err, strings.Join(ns, ", "))
		}
		r.nameServers = ns
		log.Info("No name servers specified. will use: ", strings.Join(r.nameServers, ", "))
	}
	rc.hasBeenBuilt = true
	return r, nil
}

// BuildIterativeResolver creates a new Resolver that will perform iterative DNS resolution using a cache for top-level domains
// If cache is nil, one will be instantiated in this constructor.
func (rc *ResolverConfigurer) BuildIterativeResolver(cache *Cache) (*Resolver, error) {
	r, err := rc.buildResolverHelper()
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

	if !rc.nameServersSet {
		// use the set of 13 root name servers
		r.nameServers = RootServers[:]
	}
	rc.hasBeenBuilt = true
	return r, nil
}

// isValid checks if the resolver is valid
// Returns true, nil or false, error where error describes what is invalid about the resolver configurer. Called before building the resolver
func (rc *ResolverConfigurer) isValid() (bool, string) {
	if rc.hasBeenBuilt {
		return false, "cannot change resolver builder after resolver has been built"
	}
	if isValid, reason := rc.r.transportMode.isValid(); !isValid {
		return false, reason
	}
	return true, ""
}

// buildResolverHelper has the common build logic for all resolvers
func (rc *ResolverConfigurer) buildResolverHelper() (*Resolver, error) {
	if isValid, err := rc.isValid(); !isValid {
		return nil, fmt.Errorf("invalid resolver: %w", err)
	}
	log.SetLevel(rc.r.logLevel)
	if !rc.localAddrSet {
		// set the local address to the default IP address
		conn, err := net.Dial("udp", googleDNSResolverAddr)
		if err != nil {
			return nil, fmt.Errorf("unable to find default IP address to open socket: %w", err)
		}
		rc.r.localAddr = conn.LocalAddr().(*net.UDPAddr).IP
		// cleanup socket
		if err = conn.Close(); err != nil {
			log.Warn("Unable to close test connection to Google Public DNS: ", err)
		}
	}
	if rc.r.shouldRecycleSockets {
		// create persistent connection
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: rc.r.localAddr})
		if err != nil {
			return nil, fmt.Errorf("unable to create UDP connection: %w", err)
		}
		rc.r.conn = new(dns.Conn)
		rc.r.conn.Conn = conn
	}

	if rc.r.transportMode == UDPOrTCP || rc.r.transportMode == UDPOnly {
		rc.r.udpClient = new(dns.Client)
		rc.r.udpClient.Timeout = rc.r.timeout
		rc.r.udpClient.Dialer = &net.Dialer{
			Timeout:   rc.r.timeout,
			LocalAddr: &net.UDPAddr{IP: rc.r.localAddr},
		}
	}
	if rc.r.transportMode == UDPOrTCP || rc.r.transportMode == TCPOnly {
		rc.r.tcpClient = new(dns.Client)
		rc.r.tcpClient.Net = "tcp"
		rc.r.tcpClient.Timeout = rc.r.timeout
		rc.r.tcpClient.Dialer = &net.Dialer{
			Timeout:   rc.r.timeout,
			LocalAddr: &net.TCPAddr{IP: rc.r.localAddr},
		}

	}
	return rc.r, nil
}
