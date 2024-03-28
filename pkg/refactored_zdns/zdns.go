package refactored_zdns

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
	defaultNameServerConfigFile = "/etc/resolv.conf"

	defaultTimeout   = 15 * time.Second
	defaultCacheSize = 10000
)

// TODO Phillip - Probably want to rename this
type Resolver struct {
	cache *Cache

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

	isIterative      bool // whether the user desires iterative resolution or recursive
	iterativeTimeout time.Duration
	timeout          time.Duration // timeout for the network conns
	maxDepth         int
	nameServers      []string

	dnsSecEnabled    bool
	ednsOptions      []dns.EDNS0
	checkingDisabled bool
}

// NewExternalResolver creates a new Resolver that will perform DNS resolution using an external resolver (ex: 1.1.1.1)
func NewExternalResolver(cache *Cache) (*Resolver, error) {
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

// NewIterativeResolver creates a new Resolver that will perform iterative DNS resolution
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
	// use the set of 13 root name servers
	r.nameServers = RootServers[:]
	return r, nil
}

func (r *Resolver) Lookup(q *Question) ([]ExtendedResult, error) {
	ns := r.randomNameServer()
	res, trace, status, err := r.doSingleNameServerLookup(*q, ns)
	if err != nil {
		return nil, fmt.Errorf("error resolving name %v: %w", q.Name, err)
	}
	return []ExtendedResult{
		{
			Res:        res,
			Status:     status,
			Nameserver: ns,
			Trace:      trace,
		},
	}, nil
}

func (r *Resolver) WithNameServers(nameServers []string) *Resolver {
	r.nameServers = nameServers
	return r
}

func (r *Resolver) VerboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}

// newResolver has the common setup for all resolvers
func newResolver() (*Resolver, error) {
	r := &Resolver{
		isIterative: false,

		blacklist: blacklist.New(),
		blMu:      sync.Mutex{},

		ipv4Lookup: false,
		ipv6Lookup: false,
	}
	// set-up persistent TCP/UDP connections and conn for UDP socket re-use
	// Step 1: get the local address
	conn, err := net.Dial("udp", "8.8.8.8:53")
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
		return fmt.Errorf("unable to create socket", err)
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
