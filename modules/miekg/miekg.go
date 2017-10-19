package miekg

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/cachehash"
)

type Answer struct {
	Ttl     uint32 `json:"ttl,omitempty"`
	Type    string `json:"type,omitempty"`
	rrType  uint16
	Class   string `json:"class,omitempty"`
	rrClass uint16
	Name    string `json:"name,omitempty"`
	Answer  string `json:"answer,omitempty"`
}

type MXAnswer struct {
	Answer
	Preference uint16 `json:"preference"`
}

type CAAAnswer struct {
	Answer
	Tag   string `json:"tag"`
	Value string `json:"value"`
	Flag  uint8  `json:"flag"`
}

type SOAAnswer struct {
	Answer
	Ns      string `json:"ns"`
	Mbox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minttl  uint32 `json:"min_ttl"`
}

type DNSFlags struct {
	Response           bool `json:"response"`
	Opcode             int  `json:"opcode"`
	Authoritative      bool `json:"authoritative"`
	Truncated          bool `json:"truncated"`
	RecursionDesired   bool `json:"recursion_desired"`
	RecursionAvailable bool `json:"recursion_available"`
	Authenticated      bool `json:"authenticated"`
	CheckingDisabled   bool `json:"checking_disabled"`
	ErrorCode          int  `json:"error_code"`
}

// result to be returned by scan of host
type Result struct {
	Answers     []interface{} `json:"answers"`
	Additional  []interface{} `json:"additionals"`
	Authorities []interface{} `json:"authorities"`
	Protocol    string        `json:"protocol"`
	Flags       DNSFlags      `json:"flags"`
}

type TraceStep struct {
	Result     Result   `json:"results"`
	DnsType    uint16   `json:"type"`
	DnsClass   uint16   `json:"class"`
	Name       string   `json:"name"`
	NameServer string   `json:"name_server"`
	Depth      int      `json:"depth"`
	Layer      string   `json:"layer"`
	Cached     IsCached `json:"cached"`
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

func ParseAnswer(ans dns.RR) interface{} {
	var retv Answer
	if a, ok := ans.(*dns.A); ok {
		retv = Answer{
			Ttl:     a.Hdr.Ttl,
			Type:    dns.Type(a.Hdr.Rrtype).String(),
			rrType:  a.Hdr.Rrtype,
			Class:   dns.Class(a.Hdr.Class).String(),
			rrClass: a.Hdr.Class,
			Name:    a.Hdr.Name,
			Answer:  a.A.String()}
	} else if aaaa, ok := ans.(*dns.AAAA); ok {
		retv = Answer{Ttl: aaaa.Hdr.Ttl, Type: dns.Type(aaaa.Hdr.Rrtype).String(), rrType: aaaa.Hdr.Rrtype, Class: dns.Class(aaaa.Hdr.Class).String(), rrClass: aaaa.Hdr.Class, Name: aaaa.Hdr.Name, Answer: aaaa.AAAA.String()}
	} else if cname, ok := ans.(*dns.CNAME); ok {
		retv = Answer{Ttl: cname.Hdr.Ttl, Type: dns.Type(cname.Hdr.Rrtype).String(), rrType: cname.Hdr.Rrtype, Class: dns.Class(cname.Hdr.Class).String(), rrClass: cname.Hdr.Class, Name: cname.Hdr.Name, Answer: cname.Target}
	} else if dname, ok := ans.(*dns.DNAME); ok {
		retv = Answer{Ttl: dname.Hdr.Ttl, Type: dns.Type(dname.Hdr.Rrtype).String(), rrType: dname.Hdr.Rrtype, Class: dns.Class(dname.Hdr.Class).String(), rrClass: dname.Hdr.Class, Name: dname.Hdr.Name, Answer: dname.Target}
	} else if txt, ok := ans.(*dns.TXT); ok {
		retv = Answer{Ttl: txt.Hdr.Ttl, Type: dns.Type(txt.Hdr.Rrtype).String(), rrType: txt.Hdr.Rrtype, Class: dns.Class(txt.Hdr.Class).String(), rrClass: txt.Hdr.Class, Name: txt.Hdr.Name, Answer: strings.Join(txt.Txt, "\n")}
	} else if ns, ok := ans.(*dns.NS); ok {
		retv = Answer{Ttl: ns.Hdr.Ttl, Type: dns.Type(ns.Hdr.Rrtype).String(), rrType: ns.Hdr.Rrtype, Class: dns.Class(ns.Hdr.Class).String(), rrClass: ns.Hdr.Class, Name: ns.Hdr.Name, Answer: strings.TrimRight(ns.Ns, ".")}
	} else if ptr, ok := ans.(*dns.PTR); ok {
		retv = Answer{Ttl: ptr.Hdr.Ttl, Type: dns.Type(ptr.Hdr.Rrtype).String(), rrType: ptr.Hdr.Rrtype, Class: dns.Class(ptr.Hdr.Class).String(), rrClass: ptr.Hdr.Class, Name: ptr.Hdr.Name, Answer: ptr.Ptr}
	} else if spf, ok := ans.(*dns.SPF); ok {
		retv = Answer{Ttl: spf.Hdr.Ttl, Type: dns.Type(spf.Hdr.Rrtype).String(), rrType: spf.Hdr.Rrtype, Class: dns.Class(spf.Hdr.Class).String(), rrClass: spf.Hdr.Class, Name: spf.Hdr.Name, Answer: spf.String()}
	} else if mx, ok := ans.(*dns.MX); ok {
		return MXAnswer{
			Answer: Answer{
				Name:    strings.TrimRight(mx.Hdr.Name, "."),
				Type:    dns.Type(mx.Hdr.Rrtype).String(),
				rrType:  mx.Hdr.Rrtype,
				Class:   dns.Class(mx.Hdr.Class).String(),
				rrClass: mx.Hdr.Class,
				Ttl:     mx.Hdr.Ttl,
				Answer:  strings.TrimRight(mx.Mx, "."),
			},
			Preference: mx.Preference,
		}
	} else if caa, ok := ans.(*dns.CAA); ok {
		return CAAAnswer{
			Answer: Answer{
				Name:    caa.Hdr.Name,
				Ttl:     caa.Hdr.Ttl,
				Type:    dns.Type(caa.Hdr.Rrtype).String(),
				rrType:  caa.Hdr.Rrtype,
				Class:   dns.Class(caa.Hdr.Class).String(),
				rrClass: caa.Hdr.Class,
			},
			Tag:   caa.Tag,
			Value: caa.Value,
			Flag:  caa.Flag,
		}
	} else if soa, ok := ans.(*dns.SOA); ok {
		return SOAAnswer{
			Answer: Answer{
				Name:    strings.TrimSuffix(soa.Hdr.Name, "."),
				Type:    dns.Type(soa.Hdr.Rrtype).String(),
				rrType:  soa.Hdr.Rrtype,
				Class:   dns.Class(soa.Hdr.Class).String(),
				rrClass: soa.Hdr.Class,
				Ttl:     soa.Hdr.Ttl,
			},
			Ns:      strings.TrimSuffix(soa.Ns, "."),
			Mbox:    strings.TrimSuffix(soa.Mbox, "."),
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minttl:  soa.Minttl,
		}
	} else {
		return struct {
			Type     string `json:"type"`
			rrType   uint16
			Class    string `json:"class"`
			rrClass  uint16
			Unparsed dns.RR `json:"unparsed_rr"`
		}{
			Type:     dns.Type(ans.Header().Rrtype).String(),
			rrType:   ans.Header().Rrtype,
			Class:    dns.Class(ans.Header().Class).String(),
			rrClass:  ans.Header().Class,
			Unparsed: ans,
		}
	}
	retv.Name = strings.TrimSuffix(retv.Name, ".")
	return retv
}

func TranslateMiekgErrorCode(err int) zdns.Status {
	return zdns.Status(dns.RcodeToString[err])
}

// ZDNS Module

type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
	IterativeCache cachehash.CacheHash
	CacheMutex     *sync.RWMutex
	DNSType        uint16
	DNSClass       uint16
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	s.IterativeCache.Init(c.CacheSize)
	s.CacheMutex = &sync.RWMutex{}
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
	key := makeCacheKey(name, dnsType)
	expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)
	s.CacheMutex.Lock()
	// don't bother to move this to the top of the linked list. we're going
	// to add this record back in momentarily and that will take care of this
	i, ok := s.IterativeCache.GetNoMove(key)
	ca, ok := i.(CachedResult)
	if !ok && i != nil {
		panic("unable to cast cached result")
	}
	if !ok {
		ca = CachedResult{}
		ca.Answers = make(map[interface{}]TimedAnswer)
	}
	// we have an existing record. Let's add this answer to it.
	ta := TimedAnswer{
		Answer:    answer,
		ExpiresAt: expiresAt}
	ca.Answers[a] = ta
	s.VerboseGlobalLog(depth+1, threadID, "Add cached answer ", key, " ", ca)
	s.IterativeCache.Add(key, ca)
	s.CacheMutex.Unlock()
}

func (s *GlobalLookupFactory) GetCachedResult(name string, dnsType uint16, isAuthCheck bool, depth int, threadID int) (Result, bool) {
	s.VerboseGlobalLog(depth+1, threadID, "Cache request for: ", name, " (", dnsType, ")")
	var retv Result
	key := makeCacheKey(name, dnsType)
	s.CacheMutex.Lock()
	unres, ok := s.IterativeCache.Get(key)
	if !ok { // nothing found
		s.VerboseGlobalLog(depth+2, threadID, "-> no entry found in cache")
		s.CacheMutex.Unlock()
		return retv, false
	}
	retv.Authorities = make([]interface{}, 0)
	retv.Answers = make([]interface{}, 0)
	retv.Additional = make([]interface{}, 0)
	cachedRes, ok := unres.(CachedResult)
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
	s.CacheMutex.Unlock()
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

	s.Client = new(dns.Client)
	s.Client.Timeout = s.Timeout

	s.TCPClient = new(dns.Client)
	s.TCPClient.Net = "tcp"
	s.TCPClient.Timeout = s.Timeout

	s.IterativeTimeout = c.Timeout
	s.Retries = c.Retries
	s.MaxDepth = c.MaxDepth
	s.IterativeResolution = c.IterativeResolution
	s.Trace = c.Trace

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

	m := new(dns.Msg)
	m.SetQuestion(dotName(name), dnsType)
	m.Question[0].Qclass = dnsClass
	m.RecursionDesired = recursive

	useTCP := false
	res.Protocol = "udp"

	r, _, err := udp.Exchange(m, nameServer)
	if err == dns.ErrTruncated {
		if tcp == nil {
			return res, zdns.STATUS_TRUNCATED, err
		}

		r, _, err = tcp.Exchange(m, nameServer)
		useTCP = true
		res.Protocol = "tcp"
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
	if r.Rcode == dns.RcodeBadTrunc && !useTCP {
		if tcp == nil {
			return res, zdns.STATUS_TRUNCATED, err
		}
		r, _, err = tcp.Exchange(m, nameServer)
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
	s.VerboseLog(1, "****WIRE LOOKUP***", name, " ", nameServer)

	if dnsType == dns.TypePTR {
		var err error
		name, err = dns.ReverseAddr(name)
		if err != nil {
			var r Result
			return r, zdns.STATUS_ILLEGAL_INPUT, err
		}
		name = name[:len(name)-1]
	}

	origTimeout := s.Factory.Client.Timeout
	for i := 0; i < s.Factory.Retries; i++ {
		result, status, err := s.doLookup(dnsType, dnsClass, name, nameServer, recursive)
		if (status != zdns.STATUS_TIMEOUT && status != zdns.STATUS_TEMPORARY) || i+1 == s.Factory.Retries {
			s.Factory.Client.Timeout = origTimeout
			s.Factory.TCPClient.Timeout = origTimeout
			return result, status, err
		}
		s.Factory.Client.Timeout = 2 * s.Factory.Client.Timeout
		s.Factory.TCPClient.Timeout = 2 * s.Factory.TCPClient.Timeout
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
	// Now, we check the authoritative:
	name = strings.ToLower(name)
	layer = strings.ToLower(layer)
	authName := nextAuthority(name, layer)
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

	s.VerboseLog(depth+2, "Wire lookup for name: ", name, " (", dnsType, ") at nameserver: ", nameServer)
	// Alright, we're not sure what to do, go to the wire.
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

func nextAuthority(name string, layer string) string {
	// We are our own authority for PTRs
	// (This is dealt with elsewhere)
	if strings.HasSuffix(layer, "in-addr.arpa") {
		return name
	}

	idx := strings.LastIndex(name, ".")
	if idx < 0 || (idx+1) >= len(name) {
		return name
	}
	if layer == "." {
		return name[idx+1:]
	}

	if !strings.HasSuffix(name, layer) {
		panic("Layers by definition are suffixes of names")
	}

	// Limit the search space to the prefix of the string that isnt layer
	idx = strings.LastIndex(name, layer) - 1
	if idx < 0 || (idx+1) >= len(name) {
		// Out of bounds. We are our own authority
		return name
	}
	// Find the next step in the layer
	idx = strings.LastIndex(name[0:idx], ".")
	next := name[idx+1:]
	return next
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

func (s *Lookup) iterateOnAuthorities(dnsType uint16, dnsClass uint16, name string, depth int, result Result, layer string, trace []interface{}) (Result, []interface{}, zdns.Status, error) {
	if len(result.Authorities) == 0 {
		var r Result
		return r, trace, zdns.STATUS_SERVFAIL, nil
	}
	for _, elem := range result.Authorities {
		s.VerboseLog(depth+1, "Trying Authority: ", elem)
		ns, ns_status, layer, trace := s.extractAuthority(elem, layer, depth, result, trace)
		s.VerboseLog((depth + 1), "Output from extract authorities: ", ns)
		if ns_status == zdns.STATUS_ITER_TIMEOUT {
			var r Result
			s.VerboseLog((depth + 2), "--> Hit iterative timeout: ")
			return r, trace, ns_status, nil
		}
		if ns_status != zdns.STATUS_NOERROR {
			s.VerboseLog((depth + 2), "--> Auth find Failed: ", ns_status)
			continue
		}
		r, trace, status, err := s.iterativeLookup(dnsType, dnsClass, name, ns, depth+1, layer, trace)
		if status == zdns.STATUS_ITER_TIMEOUT {
			return r, trace, status, err
		}
		if status == zdns.STATUS_NXDOMAIN {
			return r, trace, status, nil
		}
		if status != zdns.STATUS_NOERROR {
			s.VerboseLog((depth + 2), "--> Auth resolution of ", ns, " Failed: ", status)
			continue
		}
		s.VerboseLog((depth + 1), "--> Auth Resolution success: ", status)
		return r, trace, status, err
	}
	s.VerboseLog((depth + 1), "Unable to find authoritative name server")
	var r Result
	return r, trace, zdns.STATUS_ERROR, errors.New("could not find authoritative name server")
}

func (s *Lookup) iterativeLookup(dnsType uint16, dnsClass uint16, name string, nameServer string, depth int, layer string, trace []interface{}) (Result, []interface{}, zdns.Status, error) {
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

func (s *Lookup) DoMiekgLookup(name string) (interface{}, []interface{}, zdns.Status, error) {
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", s.DNSType, ")")
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(s.DNSType, s.DNSClass, name, s.NameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", s.DNSType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err

	} else {
		return s.tracedRetryingLookup(s.DNSType, s.DNSClass, name, s.NameServer, true)
	}
}

func (s *Lookup) DoMiekgLookupForClass(name string, dnsClass uint16) (interface{}, []interface{}, zdns.Status, error) {
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", s.DNSType, ") in class ", dnsClass)
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(s.DNSType, s.DNSClass, name, s.NameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", s.DNSType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err

	} else {
		return s.tracedRetryingLookup(s.DNSType, s.DNSClass, name, s.NameServer, true)
	}
}

func (s *Lookup) DoTypedMiekgLookup(name string, dnsType uint16) (interface{}, []interface{}, zdns.Status, error) {
	if s.Factory == nil {
		panic("factory not defined")
	}
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", dnsType, ")")
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(dnsType, s.DNSClass, name, s.NameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", dnsType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err
	} else {
		return s.tracedRetryingLookup(dnsType, s.DNSClass, name, s.NameServer, true)
	}
}

func (s *Lookup) DoTypedMiekgLookupInClass(name string, dnsType uint16, dnsClass uint16) (interface{}, []interface{}, zdns.Status, error) {
	if s.Factory == nil {
		panic("factory not defined")
	}
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", name, " (", dnsType, ") in class ", dnsClass)
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(dnsType, dnsClass, name, s.NameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", name, " (", dnsType, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err
	} else {
		return s.tracedRetryingLookup(dnsType, dnsClass, name, s.NameServer, true)
	}
}

func (s *Lookup) DoTxtLookup(name string) (string, []interface{}, zdns.Status, error) {
	res, trace, status, err := s.DoMiekgLookup(name)
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
func (s *Lookup) DoLookup(name string) (interface{}, []interface{}, zdns.Status, error) {
	return s.DoMiekgLookup(name)
}

func (s *GlobalLookupFactory) Help() string {
	return ""
}

// let's register some modules!
func init() {
	a := new(GlobalLookupFactory)
	a.SetDNSType(dns.TypeA)
	zdns.RegisterLookup("A", a)

	aaaa := new(GlobalLookupFactory)
	aaaa.SetDNSType(dns.TypeAAAA)
	zdns.RegisterLookup("AAAA", aaaa)

	any := new(GlobalLookupFactory)
	any.SetDNSType(dns.TypeANY)
	zdns.RegisterLookup("ANY", any)

	caa := new(GlobalLookupFactory)
	caa.SetDNSType(dns.TypeCAA)
	zdns.RegisterLookup("CAA", caa)

	cname := new(GlobalLookupFactory)
	cname.SetDNSType(dns.TypeCNAME)
	zdns.RegisterLookup("CNAME", cname)

	mx := new(GlobalLookupFactory)
	mx.SetDNSType(dns.TypeMX)
	zdns.RegisterLookup("MX", mx)

	ns := new(GlobalLookupFactory)
	ns.SetDNSType(dns.TypeNS)
	zdns.RegisterLookup("NS", ns)

	ptr := new(GlobalLookupFactory)
	ptr.SetDNSType(dns.TypePTR)
	zdns.RegisterLookup("PTR", ptr)

	soa := new(GlobalLookupFactory)
	soa.SetDNSType(dns.TypeSOA)
	zdns.RegisterLookup("SOA", soa)

	txt := new(GlobalLookupFactory)
	txt.SetDNSType(dns.TypeTXT)
	zdns.RegisterLookup("TXT", txt)

	spf := new(GlobalLookupFactory)
	spf.SetDNSType(dns.TypeSPF)
	zdns.RegisterLookup("SPF", spf)

}
