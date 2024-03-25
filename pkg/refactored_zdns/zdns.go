package refactored_zdns

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/go-iptree/blacklist"
	"github.com/zmap/zdns/internal/util"
	"strings"
	"sync"
	"time"
)

const (
	defaultNameServerConfigFile = "/etc/resolv.conf"
)

// TODO Phillip - Probably want to rename this
type Resolver struct {
	cache        *Cache
	networkConns *NetworkConns

	blacklist *blacklist.Blacklist
	blMu      sync.Mutex

	retries int

	isIterative      bool // whether the user desires iterative resolution or recursive
	iterativeTimeout time.Duration
	maxDepth         int
	nameServers      []string

	dnsSecEnabled    bool
	ednsOptions      []dns.EDNS0
	checkingDisabled bool
}

type NetworkConns struct {
	UDPClient *dns.Client
	TCPClient *dns.Client
	Conn      *dns.Conn
}

func (r *Resolver) init() {}

func NewResolver(cache *Cache, networkConns *NetworkConns, isIterative bool) (*Resolver, error) {
	r := &Resolver{}
	if cache == nil {
		// TODO Phillip create a new empty cache
	}
	if networkConns == nil {
		// TODO Phillip create a new empty network Conns object
	}
	// if we're doing recursive resolution, figure out default OS name servers
	// otherwise, use the set of 13 root name servers
	if isIterative {
		r.nameServers = RootServers[:]
	} else {
		ns, err := GetDNSServers(defaultNameServerConfigFile)
		if err != nil {
			ns = util.GetDefaultResolvers()
			log.Warn("Unable to parse resolvers file with error %w. Using ZDNS defaults: ", err, strings.Join(ns, ", "))
		}
		r.nameServers = ns
	}
	log.Info("No name servers specified. will use: ", strings.Join(r.nameServers, ", "))
	return &Resolver{
		cache:        cache,
		networkConns: networkConns,
		blacklist:    blacklist.New(),
		blMu:         sync.Mutex{},
	}, nil
}

func (r *Resolver) WithNameServers(nameServers []string) *Resolver {
	r.nameServers = nameServers
	return r
}

func (r *Resolver) Lookup(q *Question) ([]ExtendedResult, error) {
	switch q.Type {
	case dns.TypeA:
		return r.doALookup(q)
	default:
		return nil, fmt.Errorf("type %d not supported", q.Type)
	}
}

func (r *Resolver) doALookup(q *Question) ([]ExtendedResult, error) {
	return nil, nil
}

func (r *Resolver) VerboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}
