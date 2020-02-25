package miekg

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
	"github.com/zmap/go-iptree/blacklist"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/cachehash"
)

type DNSFlags struct {
	Response           bool `json:"response" groups:"flags,long,trace"`
	Opcode             int  `json:"opcode" groups:"flags,long,trace"`
	Authoritative      bool `json:"authoritative" groups:"flags,long,trace"`
	Truncated          bool `json:"truncated" groups:"flags,long,trace"`
	RecursionDesired   bool `json:"recursion_desired" groups:"flags,long,trace"`
	RecursionAvailable bool `json:"recursion_available" groups:"flags,long,trace"`
	Authenticated      bool `json:"authenticated" groups:"flags,long,trace"`
	CheckingDisabled   bool `json:"checking_disabled" groups:"flags,long,trace"`
	ErrorCode          int  `json:"error_code" groups:"flags,long,trace"`
}

// result to be returned by scan of host
type Result struct {
	Answers     []interface{} `json:"answers,omitempty" groups:"short,normal,long,trace"`
	Additional  []interface{} `json:"additionals,omitempty" groups:"short,normal,long,trace"`
	Authorities []interface{} `json:"authorities,omitempty" groups:"short,normal,long,trace"`
	Protocol    string        `json:"protocol" groups:"protocol,normal,long,trace"`
	Resolver    string        `json:"resolver" groups:"resolver,normal,long,trace"`
	Flags       DNSFlags      `json:"flags" groups:"flags,long,trace"`
}

type TraceStep struct {
	Result     Result   `json:"results" groups:"trace"`
	DnsType    uint16   `json:"type" groups:"trace"`
	DnsClass   uint16   `json:"class" groups:"trace"`
	Name       string   `json:"name" groups:"trace"`
	NameServer string   `json:"name_server" groups:"trace"`
	Depth      int      `json:"depth" groups:"trace"`
	Layer      string   `json:"layer" groups:"trace"`
	Cached     IsCached `json:"cached" groups:"trace"`
}

type TimedAnswer struct {
	Answer    interface{}
	ExpiresAt time.Time
}

type CachedResult struct {
	Answers map[interface{}]TimedAnswer
}

type IsCached bool

// Helpers
func makeVerbosePrefix(depth int, threadID int) string {
	return fmt.Sprintf("THREADID %06d,DEPTH %02d", threadID, depth) + ":" + strings.Repeat("  ", 2*depth)
}

func (s *GlobalLookupFactory) VerboseGlobalLog(depth int, threadID int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth, threadID), args)
}

func (s *Lookup) VerboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth, s.Factory.ThreadID), args)
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func TranslateMiekgErrorCode(err int) zdns.Status {
	return zdns.Status(dns.RcodeToString[err])
}

// ZDNS Module

type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
	IterativeCache cachehash.ShardedCacheHash
	DNSType        uint16
	DNSClass       uint16
	BlacklistPath  string
	Blacklist      *blacklist.Blacklist
	BlMu           sync.Mutex
}

func (s *GlobalLookupFactory) BlacklistInit() error {
	if s.BlacklistPath != "" {
		s.Blacklist = blacklist.New()
		if err := s.Blacklist.ParseFromFile(s.BlacklistPath); err != nil {
			return err
		}
	}
	return nil
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.StringVar(&s.BlacklistPath, "blacklist-file", "",
		"blacklist file for servers to exclude from lookups, only effective for iterative lookups")
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	err := s.BlacklistInit()
	if err != nil {
		return err
	}
	s.IterativeCache.Init(c.CacheSize, 4096)
	s.DNSClass = dns.ClassINET

	return nil
}

func (s *GlobalLookupFactory) SetDNSType(dnsType uint16) {
	s.DNSType = dnsType
}

func (s *GlobalLookupFactory) SetDNSClass(dnsClass uint16) {
	s.DNSClass = dnsClass
}

func (s *GlobalLookupFactory) MakeRoutineFactory(threadID int) (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Factory = s
	r.Initialize(s.GlobalConf)
	r.DNSType = s.DNSType
	r.ThreadID = threadID
	return r, nil
}

func makeCacheKey(name string, dnsType uint16) interface{} {
	return struct {
		Name    string
		DnsType uint16
	}{
		Name:    strings.ToLower(name),
		DnsType: dnsType,
	}
}

func (s *GlobalLookupFactory) AddCachedAnswer(answer interface{}, name string, dnsType uint16, ttl uint32, depth int, threadID int) {
	a, ok := answer.(Answer)
	if !ok {
		// we can't cache this entry because we have no idea what to name it
		return
	}
	// only cache records that can help prevent future iteration: A(AAA), NS, (C|D)NAME.
	// This will prevent some entries that will never help future iteration (e.g., PTR)
	// from causing unnecessary cache evictions.
	// TODO: this is overly broad right now and will unnecessarily cache some leaf A/AAAA records. However,
	// it's a lot of work to understand _why_ we're doing a specific lookup and this will still help
	// in other cases, e.g., PTR lookups
	if !(dnsType == dns.TypeA || dnsType == dns.TypeAAAA || dnsType == dns.TypeNS || dnsType == dns.TypeDNAME || dnsType == dns.TypeCNAME) {
		return
	}
	key := makeCacheKey(name, dnsType)
	expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)
	s.IterativeCache.Lock(key)
	// don't bother to move this to the top of the linked list. we're going
	// to add this record back in momentarily and that will take care of this
	i, ok := s.IterativeCache.GetNoMove(key)
	ca, ok := i.(*CachedResult)
	if !ok && i != nil {
		panic("unable to cast cached result")
	}
	if !ok {
		ca = &CachedResult{}
		ca.Answers = make(map[interface{}]TimedAnswer)
	}
	// we have an existing record. Let's add this answer to it.
	ta := TimedAnswer{
		Answer:    answer,
		ExpiresAt: expiresAt}
	ca.Answers[a] = ta
	s.IterativeCache.Add(key, ca)
	s.IterativeCache.Unlock(key)
	s.VerboseGlobalLog(depth+1, threadID, "Add cached answer ", key, " ", ca)
}

func (s *GlobalLookupFactory) GetCachedResult(name string, dnsType uint16, isAuthCheck bool, depth int, threadID int) (Result, bool) {
	s.VerboseGlobalLog(depth+1, threadID, "Cache request for: ", name, " (", dnsType, ")")
	var retv Result
	key := makeCacheKey(name, dnsType)
	s.IterativeCache.Lock(key)
	unres, ok := s.IterativeCache.Get(key)
	if !ok { // nothing found
		s.VerboseGlobalLog(depth+2, threadID, "-> no entry found in cache")
		s.IterativeCache.Unlock(key)
		return retv, false
	}
	retv.Authorities = make([]interface{}, 0)
	retv.Answers = make([]interface{}, 0)
	retv.Additional = make([]interface{}, 0)
	cachedRes, ok := unres.(*CachedResult)
	if !ok {
		panic("bad cache entry")
	}
	// great we have a result. let's go through the entries and build
	// and build a result. In the process, throw away anything that's expired
	now := time.Now()
	for k, cachedAnswer := range cachedRes.Answers {
		if cachedAnswer.ExpiresAt.Before(now) {
			// if we have a write lock, we can perform the necessary actions
			// and then write this back to the cache. However, if we don't,
			// we need to start this process over with a write lock
			s.VerboseGlobalLog(depth+2, threadID, "Expiring cache entry ", k)
			delete(cachedRes.Answers, k)
		} else {
			// this result is valid. append it to the Result we're going to hand to the user
			if isAuthCheck {
				retv.Authorities = append(retv.Authorities, cachedAnswer.Answer)
			} else {
				retv.Answers = append(retv.Answers, cachedAnswer.Answer)
			}
		}
	}
	s.IterativeCache.Unlock(key)
	// Don't return an empty response.
	if len(retv.Answers) == 0 && len(retv.Authorities) == 0 && len(retv.Additional) == 0 {
		s.VerboseGlobalLog(depth+2, threadID, "-> no entry found in cache, after expiration")
		var emptyRetv Result
		return emptyRetv, false
	}

	s.VerboseGlobalLog(depth+2, threadID, "Cache hit: ", retv)
	return retv, true
}

type RoutineLookupFactory struct {
	Factory             *GlobalLookupFactory
	Client              *dns.Client
	TCPClient           *dns.Client
	Retries             int
	MaxDepth            int
	Timeout             time.Duration
	IterativeTimeout    time.Duration
	IterativeResolution bool
	Trace               bool
	DNSType             uint16
	DNSClass            uint16
	ThreadID            int
}

func (s *RoutineLookupFactory) Initialize(c *zdns.GlobalConf) {
	if c.IterativeResolution {
		s.Timeout = c.IterationTimeout
	} else {
		s.Timeout = c.Timeout
	}

	if !c.TCPOnly {
		s.Client = new(dns.Client)
		s.Client.Timeout = s.Timeout
	}

	if !c.UDPOnly {
		s.TCPClient = new(dns.Client)
		s.TCPClient.Net = "tcp"
		s.TCPClient.Timeout = s.Timeout
	}

	s.IterativeTimeout = c.Timeout
	s.Retries = c.Retries
	s.MaxDepth = c.MaxDepth
	s.IterativeResolution = c.IterativeResolution
	if c.ResultVerbosity == "trace" {
		s.Trace = true
	} else {
		s.Trace = false
	}

	s.DNSClass = c.Class
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	nameServer := s.Factory.RandomNameServer()
	a.Initialize(nameServer, s.DNSType, s.DNSClass, s)
	return &a, nil
}

type Lookup struct {
	zdns.BaseLookup

	Factory       *RoutineLookupFactory
	DNSType       uint16
	DNSClass      uint16
	Prefix        string
	NameServer    string
	IterativeStop time.Time
}

func (s *Lookup) Initialize(nameServer string, dnsType uint16, dnsClass uint16, factory *RoutineLookupFactory) error {
	s.Factory = factory
	s.NameServer = nameServer
	s.DNSType = dnsType
	s.DNSClass = dnsClass
	return nil
}

func (s *Lookup) doLookup(dnsType uint16, dnsClass uint16, name string, nameServer string, recursive bool) (Result, zdns.Status, error) {
	return DoLookupWorker(s.Factory.Client, s.Factory.TCPClient, dnsType, dnsClass, name, nameServer, recursive)
}

// Expose the inner logic so other tools can use it
func DoLookupWorker(udp *dns.Client, tcp *dns.Client, dnsType uint16, dnsClass uint16, name string, nameServer string, recursive bool) (Result, zdns.Status, error) {
	res := Result{Answers: []interface{}{}, Authorities: []interface{}{}, Additional: []interface{}{}}
	res.Resolver = nameServer

	m := new(dns.Msg)
	m.SetQuestion(dotName(name), dnsType)
	m.Question[0].Qclass = dnsClass
	m.RecursionDesired = recursive

	var r *dns.Msg
	var err error
	if udp != nil {
		res.Protocol = "udp"
		r, _, err = udp.Exchange(m, nameServer)
		// if record comes back truncated, but we have a TCP connection, try again with that
		if r != nil && (r.Truncated || r.Rcode == dns.RcodeBadTrunc) {
			if tcp != nil {
				return DoLookupWorker(nil, tcp, dnsType, dnsClass, name, nameServer, recursive)
			} else {
				return res, zdns.STATUS_TRUNCATED, err
			}
		}
	} else {
		res.Protocol = "tcp"
		r, _, err = tcp.Exchange(m, nameServer)
	}
	if err != nil || r == nil {
		if nerr, ok := err.(net.Error); ok {
			if nerr.Timeout() {
				return res, zdns.STATUS_TIMEOUT, nil
			} else if nerr.Temporary() {
				return res, zdns.STATUS_TEMPORARY, err
			}
		}
		return res, zdns.STATUS_ERROR, err
	}

	if err != nil || r == nil {
		return res, zdns.STATUS_ERROR, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return res, TranslateMiekgErrorCode(r.Rcode), nil
	}

	res.Flags.Response = r.Response
	res.Flags.Opcode = r.Opcode
	res.Flags.Authoritative = r.Authoritative
	res.Flags.Truncated = r.Truncated
	res.Flags.RecursionDesired = r.RecursionDesired
	res.Flags.RecursionAvailable = r.RecursionAvailable
	res.Flags.Authenticated = r.AuthenticatedData
	res.Flags.CheckingDisabled = r.CheckingDisabled
	res.Flags.ErrorCode = r.Rcode

	for _, ans := range r.Answer {
		inner := ParseAnswer(ans)
		if inner != nil {
			res.Answers = append(res.Answers, inner)
		}
	}
	for _, ans := range r.Extra {
		inner := ParseAnswer(ans)
		if inner != nil {
			res.Additional = append(res.Additional, inner)
		}
	}
	for _, ans := range r.Ns {
		inner := ParseAnswer(ans)
		if inner != nil {
			res.Authorities = append(res.Authorities, inner)
		}
	}
	return res, zdns.STATUS_NOERROR, nil
}

func (s *Lookup) SafeAddCachedAnswer(a interface{}, layer string, debugType string, depth int) {
	ans, ok := a.(Answer)
	if !ok {
		s.VerboseLog(depth+1, "unable to cast ", debugType, ": ", layer, ": ", a)
		return
	}
	ok, _ = nameIsBeneath(ans.Name, layer)
	if !ok {
		log.Info("detected poison ", debugType, ": ", ans.Name, "(", ans.Type, "): ", layer, ": ", a)
		return
	}
	s.Factory.Factory.AddCachedAnswer(a, ans.Name, ans.rrType, ans.Ttl, depth, s.Factory.ThreadID)
}

func (s *Lookup) cacheUpdate(layer string, result Result, depth int) {
	for _, a := range result.Additional {
		s.SafeAddCachedAnswer(a, layer, "additional", depth)
	}
	for _, a := range result.Authorities {
		s.SafeAddCachedAnswer(a, layer, "authority", depth)
	}
	if result.Flags.Authoritative == true {
		for _, a := range result.Answers {
			s.SafeAddCachedAnswer(a, layer, "anwer", depth)
		}
	}
}

func (s *Lookup) tracedRetryingLookup(dnsType uint16, dnsClass uint16, name string, nameServer string, recursive bool) (Result, []interface{}, zdns.Status, error) {

	res, status, err := s.retryingLookup(dnsType, dnsClass, name, nameServer, recursive)

	trace := make([]interface{}, 0)

	if s.Factory.Trace {
		var t TraceStep
		t.Result = res
		t.DnsType = dnsType
		t.DnsClass = dnsClass
		t.Name = name
		t.NameServer = nameServer
		t.Layer = name
		t.Depth = 1
		t.Cached = false
		trace = append(trace, t)
	}

	return res, trace, status, err
}

func (s *Lookup) retryingLookup(dnsType uint16, dnsClass uint16, name string, nameServer string, recursive bool) (Result, zdns.Status, error) {
	s.VerboseLog(1, "****WIRE LOOKUP*** ", typeNames[dnsType], " ", name, " ", nameServer)

	var origTimeout time.Duration
	if s.Factory.Client != nil {
		origTimeout = s.Factory.Client.Timeout
	} else {
		origTimeout = s.Factory.TCPClient.Timeout
	}
	for i := 0; i < s.Factory.Retries; i++ {
		result, status, err := s.doLookup(dnsType, dnsClass, name, nameServer, recursive)
		if (status != zdns.STATUS_TIMEOUT && status != zdns.STATUS_TEMPORARY) || i+1 == s.Factory.Retries {
			if s.Factory.Client != nil {
				s.Factory.Client.Timeout = origTimeout
			}
			if s.Factory.TCPClient != nil {
				s.Factory.TCPClient.Timeout = origTimeout
			}
			return result, status, err
		}
		if s.Factory.Client != nil {
			s.Factory.Client.Timeout = 2 * s.Factory.Client.Timeout
		}
		if s.Factory.TCPClient != nil {
			s.Factory.TCPClient.Timeout = 2 * s.Factory.TCPClient.Timeout
		}
	}
	panic("loop must return")
}

func (s *Lookup) cachedRetryingLookup(dnsType uint16, dnsClass uint16, name string, nameServer string, layer string, depth int) (Result, IsCached, zdns.Status, error) {
	var isCached IsCached
	isCached = false
	s.VerboseLog(depth+1, "Cached retrying lookup. Name: ", name, ", Layer: ", layer, ", Nameserver: ", nameServer)
	if s.IterativeStop.Before(time.Now()) {
		s.VerboseLog(depth+2, "ITERATIVE_TIMEOUT ", name, ", Layer: ", layer, ", Nameserver: ", nameServer)
		var r Result
		return r, isCached, zdns.STATUS_ITER_TIMEOUT, nil
	}
	// First, we check the answer
	cachedResult, ok := s.Factory.Factory.GetCachedResult(name, dnsType, false, depth+1, s.Factory.ThreadID)
	if ok {
		isCached = true
		return cachedResult, isCached, zdns.STATUS_NOERROR, nil
	}

	nameServerIP, _, err := net.SplitHostPort(nameServer)
	// Stop if we hit a nameserver we don't want to hit
	if s.Factory.Factory.Blacklist != nil {
		s.Factory.Factory.BlMu.Lock()
		if blacklisted, err := s.Factory.Factory.Blacklist.IsBlacklisted(nameServerIP); err != nil {
			s.Factory.Factory.BlMu.Unlock()
			s.VerboseLog(depth+2, "Blacklist error!", err)
			var r Result
			return r, isCached, zdns.STATUS_ERROR, err
		} else if blacklisted {
			s.Factory.Factory.BlMu.Unlock()
			s.VerboseLog(depth+2, "Hit blacklisted nameserver ", name, ", Layer: ", layer, ", Nameserver: ", nameServer)
			var r Result
			return r, isCached, zdns.STATUS_BLACKLIST, nil
		}
		s.Factory.Factory.BlMu.Unlock()
	}

	// Now, we check the authoritative:
	name = strings.ToLower(name)
	layer = strings.ToLower(layer)
	authName, err := nextAuthority(name, layer)
	if err != nil {
		s.VerboseLog(depth+2, err)
		var r Result
		return r, isCached, zdns.STATUS_AUTHFAIL, err
	}
	if name != layer && authName != layer {
		if authName == "" {
			s.VerboseLog(depth+2, "Can't parse name to authority properly. name: ", name, ", layer: ", layer)
			var r Result
			return r, isCached, zdns.STATUS_AUTHFAIL, nil
		}
		s.VerboseLog(depth+2, "Cache auth check for ", authName)
		cachedResult, ok = s.Factory.Factory.GetCachedResult(authName, dns.TypeNS, true, depth+2, s.Factory.ThreadID)
		if ok {
			isCached = true
			return cachedResult, isCached, zdns.STATUS_NOERROR, nil
		}
	}

	// Alright, we're not sure what to do, go to the wire.
	s.VerboseLog(depth+2, "Wire lookup for name: ", name, " (", dnsType, ") at nameserver: ", nameServer)
	result, status, err := s.retryingLookup(dnsType, dnsClass, name, nameServer, false)

	s.cacheUpdate(layer, result, depth+2)
	return result, isCached, status, err
}

func nameIsBeneath(name string, layer string) (bool, string) {
	name = strings.ToLower(name)
	layer = strings.ToLower(layer)
	name = strings.TrimSuffix(name, ".")
	if layer == "." {
		return true, name
	}

	if strings.HasSuffix(name, "."+layer) || name == layer {
		return true, name
	}
	return false, ""
}

func nextAuthority(name string, layer string) (string, error) {
	// We are our own authority for PTRs
	// (This is dealt with elsewhere)
	if strings.HasSuffix(name, "in-addr.arpa") && layer == "." {
		return "in-addr.arpa", nil
	}

	idx := strings.LastIndex(name, ".")
	if idx < 0 || (idx+1) >= len(name) {
		return name, nil
	}
	if layer == "." {
		return name[idx+1:], nil
	}

	if !strings.HasSuffix(name, layer) {
		return "", errors.New("Server did not provide appropriate resolvers to continue recursion")
	}

	// Limit the search space to the prefix of the string that isnt layer
	idx = strings.LastIndex(name, layer) - 1
	if idx < 0 || (idx+1) >= len(name) {
		// Out of bounds. We are our own authority
		return name, nil
	}
	// Find the next step in the layer
	idx = strings.LastIndex(name[0:idx], ".")
	next := name[idx+1:]
	return next, nil
}

func (s *Lookup) checkGlue(server string, depth int, result Result) (Result, zdns.Status) {
	for _, additional := range result.Additional {
		ans, ok := additional.(Answer)
		if !ok {
			continue
		}
		if ans.Type == "A" && strings.TrimSuffix(ans.Name, ".") == server {
			var retv Result
			retv.Authorities = make([]interface{}, 0)
			retv.Answers = make([]interface{}, 0)
			retv.Additional = make([]interface{}, 0)
			retv.Answers = append(retv.Answers, ans)
			s.VerboseLog(depth+1, "Glue hit for Authority: ", server, ". ", ans)
			return retv, zdns.STATUS_NOERROR
		}
	}

	var r Result
	return r, zdns.STATUS_SERVFAIL
}

func (s *Lookup) extractAuthority(authority interface{}, layer string, depth int, result Result, trace []interface{}) (string, zdns.Status, string, []interface{}) {

	// Is it an answer
	ans, ok := authority.(Answer)
	if !ok {
		return "", zdns.STATUS_SERVFAIL, layer, trace
	}

	// Is the layering correct
	ok, layer = nameIsBeneath(ans.Name, layer)
	if !ok {
		return "", zdns.STATUS_AUTHFAIL, layer, trace
	}

	server := strings.TrimSuffix(ans.Answer, ".")

	// Short circuit a lookup from the glue
	// Normally this would be handled by caching, but we want to support following glue
	// that would normally be cache poison. Because it's "ok" and quite common
	res, status := s.checkGlue(server, depth, result)
	if status != zdns.STATUS_NOERROR {
		// Fall through to normal query
		res, trace, status, _ = s.iterativeLookup(dns.TypeA, dns.ClassINET, server, s.NameServer, depth+1, ".", trace)
	}
	if status == zdns.STATUS_ITER_TIMEOUT {
		return "", status, "", trace
	}
	if status == zdns.STATUS_NOERROR {
		// XXX we don't actually check the question here
		for _, inner_a := range res.Answers {
			inner_ans, ok := inner_a.(Answer)
			if !ok {
				continue
			}
			if inner_ans.Type == "A" {
				server := strings.TrimSuffix(inner_ans.Answer, ".") + ":53"
				return server, zdns.STATUS_NOERROR, layer, trace
			}
		}
	}
	return "", zdns.STATUS_SERVFAIL, layer, trace
}

func debugReverseLookup(name string) string {
	nameServerNoPort := strings.Split(name, ":")[0]
	nameServers, err := net.LookupAddr(nameServerNoPort)
	if err == nil && len(nameServers) > 0 {
		return strings.TrimSuffix(nameServers[0], ".")
	}
	return "unknown"
}

func handleStatus(status *zdns.Status, err error) (*zdns.Status, error) {
	switch *status {
	case zdns.STATUS_ITER_TIMEOUT:
		return status, err
	case zdns.STATUS_NXDOMAIN:
		return status, nil
	case zdns.STATUS_SERVFAIL:
		return status, nil
	case zdns.STATUS_REFUSED:
		return status, nil
	case zdns.STATUS_AUTHFAIL:
		return status, nil
	case zdns.STATUS_NO_RECORD:
		return status, nil
	case zdns.STATUS_BLACKLIST:
		return status, nil
	case zdns.STATUS_NO_OUTPUT:
		return status, nil
	case zdns.STATUS_NO_ANSWER:
		return status, nil
	case zdns.STATUS_TRUNCATED:
		return status, nil
	case zdns.STATUS_ILLEGAL_INPUT:
		return status, nil
	case zdns.STATUS_TEMPORARY:
		return status, nil
	default:
		var s *zdns.Status
		return s, nil
	}
}

func (s *Lookup) iterateOnAuthorities(dnsType uint16, dnsClass uint16, name string,
	depth int, result Result, layer string, trace []interface{}) (Result, []interface{}, zdns.Status, error) {
	//
	if len(result.Authorities) == 0 {
		var r Result
		return r, trace, zdns.STATUS_SERVFAIL, nil
	}
	for _, elem := range result.Authorities {
		s.VerboseLog(depth+1, "Trying Authority: ", elem)
		ns, ns_status, layer, trace := s.extractAuthority(elem, layer, depth, result, trace)
		s.VerboseLog((depth + 1), "Output from extract authorities: ", ns)
		if ns_status == zdns.STATUS_ITER_TIMEOUT {
			s.VerboseLog((depth + 2), "--> Hit iterative timeout: ")
		}
		if ns_status != zdns.STATUS_NOERROR {
			var err error
			new_status, err := handleStatus(&ns_status, err)
			// default case we continue
			if new_status == nil && err == nil {
				s.VerboseLog((depth + 2), "--> Auth find Failed: ", ns_status)
				continue
			} else {
				// otherwise we hit a status we know
				var r Result
				return r, trace, *new_status, err
			}
		}
		r, trace, status, err := s.iterativeLookup(dnsType, dnsClass, name, ns, depth+1, layer, trace)
		if status != zdns.STATUS_NOERROR {
			new_status, err := handleStatus(&status, err)
			// default case is a status we don't handle, so we continue
			if new_status == nil && err == nil {
				s.VerboseLog((depth + 2), "--> Auth resolution of ", ns, " Failed: ", status)
				continue

			} else {
				// otherwise we hit a status we know
				return r, trace, *new_status, err
			}
		}
		s.VerboseLog((depth + 1), "--> Auth Resolution success: ", status)
		return r, trace, status, err
	}
	s.VerboseLog((depth + 1), "Unable to find authoritative name server")
	var r Result
	return r, trace, zdns.STATUS_ERROR, errors.New("could not find authoritative name server")
}

func (s *Lookup) iterativeLookup(dnsType uint16, dnsClass uint16, name string, nameServer string,
	depth int, layer string, trace []interface{}) (Result, []interface{}, zdns.Status, error) {
	//
	if log.GetLevel() == log.DebugLevel {
		//s.VerboseLog((depth), "iterative lookup for ", name, " (", dnsType, ") against ", nameServer, " (", debugReverseLookup(nameServer), ") layer ", layer)
		s.VerboseLog((depth), "iterative lookup for ", name, " (", dnsType, ") against ", nameServer, " layer ", layer)
	}
	if depth > s.Factory.MaxDepth {
		var r Result
		s.VerboseLog((depth + 1), "-> Max recursion depth reached")
		return r, trace, zdns.STATUS_ERROR, errors.New("Max recursion depth reached")
	}
	result, isCached, status, err := s.cachedRetryingLookup(dnsType, dnsClass, name, nameServer, layer, depth)
	if s.Factory.Trace && status == zdns.STATUS_NOERROR {
		var t TraceStep
		t.Result = result
		t.DnsType = dnsType
		t.DnsClass = dnsClass
		t.Name = name
		t.NameServer = nameServer
		t.Layer = layer
		t.Depth = depth
		t.Cached = isCached
		trace = append(trace, t)

	}
	if status != zdns.STATUS_NOERROR {
		s.VerboseLog((depth + 1), "-> error occurred during lookup")
		return result, trace, status, err
	} else if len(result.Answers) != 0 || result.Flags.Authoritative == true {
		if len(result.Answers) != 0 {
			s.VerboseLog((depth + 1), "-> answers found")
			if len(result.Authorities) > 0 {
				s.VerboseLog((depth + 2), "Dropping ", len(result.Authorities), " authority answers from output")
				result.Authorities = make([]interface{}, 0)
			}
			if len(result.Additional) > 0 {
				s.VerboseLog((depth + 2), "Dropping ", len(result.Additional), " additional answers from output")
				result.Additional = make([]interface{}, 0)
			}
		} else {
			s.VerboseLog((depth + 1), "-> authoritative response found")
		}
		return result, trace, status, err
	} else if len(result.Authorities) != 0 {
		s.VerboseLog((depth + 1), "-> Authority found, iterating")
		return s.iterateOnAuthorities(dnsType, dnsClass, name, depth, result, layer, trace)
	} else {
		s.VerboseLog((depth + 1), "-> No Authority found, error")
		return result, trace, zdns.STATUS_ERROR, errors.New("NOERROR record without any answers or authorities")
	}
}

func (s *Lookup) DoMiekgLookup(name string, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	if s.DNSType == dns.TypePTR {
		var err error
		name, err = dns.ReverseAddr(name)
		if err != nil {
			return nil, nil, zdns.STATUS_ILLEGAL_INPUT, err
		}
		name = name[:len(name)-1]
	}
	if nameServer == "" {
		nameServer = s.NameServer
	}
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", s.DNSType, ")")
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(s.DNSType, s.DNSClass, name, nameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", s.DNSType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err
	} else {
		return s.tracedRetryingLookup(s.DNSType, s.DNSClass, name, nameServer, true)
	}
}

func (s *Lookup) DoMiekgLookupForClass(name string, dnsClass uint16, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	if nameServer == "" {
		nameServer = s.NameServer
	}
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", s.DNSType, ") in class ", dnsClass)
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(s.DNSType, s.DNSClass, name, nameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", s.DNSType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err

	} else {
		return s.tracedRetryingLookup(s.DNSType, s.DNSClass, name, nameServer, true)
	}
}

func (s *Lookup) DoTypedMiekgLookup(name string, dnsType uint16, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	if s.Factory == nil {
		panic("factory not defined")
	}
	if nameServer == "" {
		nameServer = s.NameServer
	}
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", dnsType, ")")
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(dnsType, s.DNSClass, name, nameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", dnsType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err
	} else {
		return s.tracedRetryingLookup(dnsType, s.DNSClass, name, nameServer, true)
	}
}

func (s *Lookup) DoTypedMiekgLookupInClass(name string, dnsType uint16, dnsClass uint16, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	if s.Factory == nil {
		panic("factory not defined")
	}
	if nameServer == "" {
		nameServer = s.NameServer
	}
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", dnsType, ") in class ", dnsClass)
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(dnsType, dnsClass, name, nameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", dnsType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err
	} else {
		return s.tracedRetryingLookup(dnsType, dnsClass, name, nameServer, true)
	}
}

func (s *Lookup) DoTxtLookup(name string, nameServer string) (string, []interface{}, zdns.Status, error) {
	res, trace, status, err := s.DoMiekgLookup(name, nameServer)
	if status != zdns.STATUS_NOERROR {
		return "", trace, status, err
	}
	if parsedResult, ok := res.(Result); ok {
		for _, a := range parsedResult.Answers {
			ans, _ := a.(Answer)
			if strings.HasPrefix(ans.Answer, s.Prefix) {
				return ans.Answer, trace, zdns.STATUS_NOERROR, err
			}
		}
	}
	return "", trace, zdns.STATUS_NO_RECORD, nil
}

// allow miekg to be used as a ZDNS module
func (s *Lookup) DoLookup(name string, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	return s.DoMiekgLookup(name, nameServer)
}

func (s *GlobalLookupFactory) Help() string {
	return ""
}
