package miekg

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/cachehash"
)

type Answer struct {
	Ttl    uint32 `json:"ttl,omitempty"`
	Type   string `json:"type,omitempty"`
	Name   string `json:"name,omitempty"`
	Answer string `json:"answer,omitempty"`
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

type TimedAnswer struct {
	Answer    interface{}
	ExpiresAt time.Time
}

type CachedResult struct {
	Answers map[interface{}]TimedAnswer
}

// Helpers

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func ParseAnswer(ans dns.RR) interface{} {
	var retv Answer
	if a, ok := ans.(*dns.A); ok {
		retv = Answer{Ttl: a.Hdr.Ttl, Type: dns.Type(a.Hdr.Rrtype).String(), Name: a.Hdr.Name, Answer: a.A.String()}
	} else if aaaa, ok := ans.(*dns.AAAA); ok {
		retv = Answer{Ttl: aaaa.Hdr.Ttl, Type: dns.Type(aaaa.Hdr.Rrtype).String(), Name: aaaa.Hdr.Name, Answer: aaaa.AAAA.String()}
	} else if cname, ok := ans.(*dns.CNAME); ok {
		retv = Answer{Ttl: cname.Hdr.Ttl, Type: dns.Type(cname.Hdr.Rrtype).String(), Name: cname.Hdr.Name, Answer: cname.Target}
	} else if dname, ok := ans.(*dns.DNAME); ok {
		retv = Answer{Ttl: dname.Hdr.Ttl, Type: dns.Type(dname.Hdr.Rrtype).String(), Name: dname.Hdr.Name, Answer: dname.Target}
	} else if txt, ok := ans.(*dns.TXT); ok {
		retv = Answer{Ttl: txt.Hdr.Ttl, Type: dns.Type(txt.Hdr.Rrtype).String(), Name: txt.Hdr.Name, Answer: strings.Join(txt.Txt, "\n")}
	} else if ns, ok := ans.(*dns.NS); ok {
		retv = Answer{Ttl: ns.Hdr.Ttl, Type: dns.Type(ns.Hdr.Rrtype).String(), Name: ns.Hdr.Name, Answer: ns.Ns}
	} else if ptr, ok := ans.(*dns.PTR); ok {
		retv = Answer{Ttl: ptr.Hdr.Ttl, Type: dns.Type(ptr.Hdr.Rrtype).String(), Name: ptr.Hdr.Name, Answer: ptr.Ptr}
	} else if spf, ok := ans.(*dns.SPF); ok {
		retv = Answer{Ttl: spf.Hdr.Ttl, Type: dns.Type(spf.Hdr.Rrtype).String(), Name: spf.Hdr.Name, Answer: spf.String()}
	} else if mx, ok := ans.(*dns.MX); ok {
		return MXAnswer{
			Answer: Answer{
				Name:   mx.Hdr.Name,
				Type:   dns.Type(mx.Hdr.Rrtype).String(),
				Ttl:    mx.Hdr.Ttl,
				Answer: mx.Mx,
			},
			Preference: mx.Preference,
		}
	} else if caa, ok := ans.(*dns.CAA); ok {
		return CAAAnswer{
			Answer: Answer{
				Name: caa.Hdr.Name,
				Ttl:  caa.Hdr.Ttl,
				Type: dns.Type(caa.Hdr.Rrtype).String(),
			},
			Tag:   caa.Tag,
			Value: caa.Value,
			Flag:  caa.Flag,
		}
	} else if soa, ok := ans.(*dns.SOA); ok {
		return SOAAnswer{
			Answer: Answer{
				Name: soa.Hdr.Name,
				Type: dns.Type(soa.Hdr.Rrtype).String(),
				Ttl:  soa.Hdr.Ttl,
			},
			Ns:      strings.TrimSuffix(soa.Ns, "."),
			Mbox:    soa.Mbox,
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minttl:  soa.Minttl,
		}
	} else {
		return struct {
			Type     string `json:"type"`
			Unparsed dns.RR `json:"unparsed_rr"`
		}{
			Type:     dns.Type(ans.Header().Rrtype).String(),
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
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	s.IterativeCache.Init(c.CacheSize)
	s.CacheMutex = &sync.RWMutex{}

	return nil
}

func makeCacheKey(name string, layer string, dnsType uint16) interface{} {
	return struct {
		Name    string
		Layer   string
		DnsType uint16
	}{
		Name:    name,
		Layer:   layer,
		DnsType: dnsType,
	}
}

func (s *GlobalLookupFactory) AddCachedAnswer(answer interface{}, name string, layer string, dnsType uint16, ttl uint32) {
	a, ok := answer.(Answer)
	if !ok {
		// we can't cache this entry because we have no idea what to name it
		return
	}
	key := makeCacheKey(name, layer, dnsType)
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
	log.Debug("Add cached answer ", key, " ", ca)
	s.IterativeCache.Add(key, ca)
	s.CacheMutex.Unlock()
}

func (s *GlobalLookupFactory) GetCachedResult(name string, layer string, dnsType uint16, wLock bool) (Result, bool) {
	log.Debug("cache request for: ", name, " (", dnsType, "), layer: ", layer, " wlock (", wLock, "):")
	var retv Result
	key := makeCacheKey(name, layer, dnsType)
	if wLock {
		s.CacheMutex.Lock()
	} else {
		s.CacheMutex.RLock()
	}
	unres, ok := s.IterativeCache.Get(key)
	if !wLock {
		s.CacheMutex.RUnlock()
	}
	if !ok { // nothing found
		log.Debug(" -> no entry found in cache")
		return retv, false
	}
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
			if wLock {
				log.Debug("Expiring cache entry ", k)
				delete(cachedRes.Answers, k)
			} else {
				log.Debug("cache trying to expire. Retrying with lock")
				return s.GetCachedResult(name, layer, dnsType, true)
			}
		} else {
			// this result is valid. append it to the Result we're going to hand to the user
			retv.Answers = append(retv.Answers, cachedAnswer.Answer)
		}
	}
	if wLock {
		s.CacheMutex.Unlock()
	}
	//if res.ExpiresAt.After(now) {
	//	s.CacheMutex.Lock()
	//	s.IterativeCache.Delete(key)
	//	s.CacheMutex.Unlock()
	//	log.Debug(" -> cache entry expired. removed.")
	//	return retv, false
	//}
	//log.Debug(" -> cached answers found")
	//for _, ans := range res.Result.Answers {
	//	log.Debug("      - ", ans)
	//}
	return retv, true
}

type RoutineLookupFactory struct {
	Factory             *GlobalLookupFactory
	Client              *dns.Client
	TCPClient           *dns.Client
	Retries             int
	MaxDepth            int
	Timeout             time.Duration
	IterativeResolution bool
	DNSType             uint16
}

func (s *RoutineLookupFactory) Initialize(c *zdns.GlobalConf) {
	s.Client = new(dns.Client)
	s.Client.Timeout = c.Timeout

	s.TCPClient = new(dns.Client)
	s.TCPClient.Net = "tcp"
	s.TCPClient.Timeout = c.Timeout

	s.Timeout = c.Timeout
	s.Retries = c.Retries
	s.MaxDepth = c.MaxDepth
	s.IterativeResolution = c.IterativeResolution
}

type Lookup struct {
	zdns.BaseLookup

	Factory    *RoutineLookupFactory
	DNSType    uint16
	Prefix     string
	NameServer string
}

func (s *Lookup) Initialize(nameServer string, dnsType uint16, factory *RoutineLookupFactory) error {
	s.Factory = factory
	s.NameServer = nameServer
	s.DNSType = dnsType
	return nil
}

func (s *Lookup) doLookup(dnsType uint16, name string, nameServer string, recursive bool) (Result, zdns.Status, error) {
	res := Result{Answers: []interface{}{}, Authorities: []interface{}{}, Additional: []interface{}{}}

	m := new(dns.Msg)
	m.SetQuestion(dotName(name), dnsType)
	m.RecursionDesired = recursive

	useTCP := false
	res.Protocol = "udp"

	r, _, err := s.Factory.Client.Exchange(m, nameServer)
	if err == dns.ErrTruncated {
		if s.Factory.TCPClient == nil {
			return res, zdns.STATUS_TRUNCATED, err
		}
		r, _, err = s.Factory.TCPClient.Exchange(m, nameServer)
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
		r, _, err = s.Factory.TCPClient.Exchange(m, s.NameServer)
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

func (s *Lookup) SafeAddCachedAnswer(name string, dnsType uint16, a interface{}, layer string, debugType string) {
	ans, ok := a.(Answer)
	if !ok {
		log.Debug("unable to cast ", debugType, ": ", name, " (", dnsType, "): ", a)
		return
	}
	ok, _ = s.nameIsBeneath(ans.Name, layer)
	if !ok {
		log.Info("detected poison ", debugType, ": ", name, " (", dnsType, "): ", a)
		return
	}
	s.Factory.Factory.AddCachedAnswer(a, ans.Name, layer, dnsType, ans.Ttl)
}

func (s *Lookup) cacheUpdate(dnsType uint16, name string, layer string, result Result) {
	for _, a := range result.Additional {
		s.SafeAddCachedAnswer(name, dnsType, a, layer, "additional")
	}
	for _, a := range result.Authorities {
		s.SafeAddCachedAnswer(name, dnsType, a, layer, "authority")
	}
	for _, a := range result.Answers {
		s.SafeAddCachedAnswer(name, dnsType, a, layer, "anwer")
	}
}

func (s *Lookup) retryingLookup(dnsType uint16, name string, nameServer string, recursive bool) (Result, zdns.Status, error) {
	log.Debug("****WIRE***")
	origTimeout := s.Factory.Client.Timeout
	for i := 0; i < s.Factory.Retries; i++ {
		result, status, err := s.doLookup(dnsType, name, nameServer, recursive)
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

func (s *Lookup) cachedRetryingLookup(dnsType uint16, name string, nameServer string, layer string) (Result, zdns.Status, error) {
	cachedResult, ok := s.Factory.Factory.GetCachedResult(name, layer, dnsType, false)
	if ok {
		return cachedResult, zdns.STATUS_NOERROR, nil
	}
	result, status, err := s.retryingLookup(dnsType, name, nameServer, false)
	s.cacheUpdate(dnsType, name, layer, result)
	return result, status, err
}

func (s *Lookup) extractAdditionals(res Result) map[string][]Answer {
	if len(res.Authorities) == 0 {
		// this is a lost cause.
		return nil
	}
	// most reasonable servers will include the A or AAAA record for a DNS
	// server in the additionals. Put all into a hash table that we can check
	// when we iterate over the records in the authorities section
	searchSet := make(map[string][]Answer)
	for _, a := range res.Additional {
		ans, ok := a.(Answer)
		if !ok {
			// XXX add logging
			continue
		}
		if ans.Type == "A" {
			name := dotName(ans.Name)
			searchSet[name] = append(searchSet[name], ans)
		}
	}
	return searchSet
}

func (s *Lookup) nameIsBeneath(name string, layer string) (bool, string) {
	name = strings.TrimSuffix(name, ".")
	if layer == "." {
		return true, name
	}

	if strings.HasSuffix(name, "."+layer) || name == layer {
		return true, name
	}
	return false, ""
}

func (s *Lookup) extractAuthority(searchSet map[string][]Answer, authority interface{}, layer string, depth int) (string, zdns.Status, string) {
	// check if we have the IP address for any of the authorities
	ans, ok := authority.(Answer)
	if !ok {
		return "", zdns.STATUS_SERVFAIL, layer
	}

	ok, layer = s.nameIsBeneath(ans.Name, layer)
	if !ok {
		return "", zdns.STATUS_AUTHFAIL, layer
	}

	if ip, ok := searchSet[ans.Answer]; ok {
		server := strings.TrimSuffix(ip[0].Answer, ".") + ":53"
		return server, zdns.STATUS_NOERROR, layer
	}
	// nothing was found. we need to lookup the A record for one of the NS servers. Quit once
	// we've found one.
	server := strings.TrimSuffix(ans.Answer, ".")
	res, status, _ := s.iterativeLookup(dns.TypeA, server, s.NameServer, depth+1, ".")
	if status == zdns.STATUS_NOERROR {
		for _, inner_a := range res.Answers {
			inner_ans, ok := inner_a.(Answer)
			if !ok {
				continue
			}
			if inner_ans.Type == "A" {
				server := strings.TrimSuffix(inner_ans.Answer, ".") + ":53"
				return server, zdns.STATUS_NOERROR, layer
			}
		}
	}
	return "", zdns.STATUS_SERVFAIL, layer
}

func makeDepthPadding(depth int) string {
	return strings.Repeat("  ", depth)
}

func debugReverseLookup(name string) string {
	nameServerNoPort := strings.Split(name, ":")[0]
	nameServers, err := net.LookupAddr(nameServerNoPort)
	if err == nil && len(nameServers) > 0 {
		return strings.TrimSuffix(nameServers[0], ".")
	}
	return "unknown"
}

func debugExtractAuthorityInput(result Result, depth int) {
	log.Debug(makeDepthPadding(depth+1), "-> authorities found. will attempt to extract IP of an authority")
	log.Debug(makeDepthPadding(depth+1), "   Intput to extract authorities: ")
	log.Debug(makeDepthPadding(depth+1), "    - Authorities:")
	for _, elem := range result.Authorities {
		log.Debug(makeDepthPadding(depth+1), "      - ", elem)
	}
	log.Debug(makeDepthPadding(depth+1), "    - Additionals:")
	for _, elem := range result.Additional {
		log.Debug(makeDepthPadding(depth+1), "      - ", elem)
	}
}

func (s *Lookup) iterateOnAuthorities(dnsType uint16, name string, depth int, result Result, layer string) (Result, zdns.Status, error) {
	if len(result.Authorities) == 0 {
		var r Result
		return r, zdns.STATUS_SERVFAIL, nil
	}
	searchSet := s.extractAdditionals(result)
	for _, elem := range result.Authorities {
		// XXX log stuff
		ns, ns_status, layer := s.extractAuthority(searchSet, elem, layer, depth)
		log.Debug(makeDepthPadding(depth+1), "   Output from extract authorities: ", ns)
		if ns_status != zdns.STATUS_NOERROR {
			// XXX Log stuff
			continue
		}
		r, status, err := s.iterativeLookup(dnsType, name, ns, depth+1, layer)
		if ns_status != zdns.STATUS_NOERROR {
			// XXX Log stuff
			continue
		}
		return r, status, err
	}
	var r Result
	return r, zdns.STATUS_ERROR, errors.New("could not find authoritative name server")
}

func (s *Lookup) iterativeLookup(dnsType uint16, name string, nameServer string, depth int, layer string) (Result, zdns.Status, error) {
	if log.GetLevel() == log.DebugLevel {
		log.Debug(makeDepthPadding(depth), "iterative lookup for ", name, " (", dnsType, ") against ", nameServer, " (", debugReverseLookup(nameServer), ") layer ", layer)
	}
	if depth > s.Factory.MaxDepth {
		var r Result
		return r, zdns.STATUS_ERROR, errors.New("Max recursion depth reached")
	}
	result, status, err := s.cachedRetryingLookup(dnsType, name, nameServer, layer)
	if status != zdns.STATUS_NOERROR {
		log.Debug(makeDepthPadding(depth+1), "-> error occurred during lookup")
		return result, status, err
	} else if result.Flags.Authoritative == true {
		log.Debug(makeDepthPadding(depth+1), "-> authoritative response found")
		return result, status, err
	} else if len(result.Answers) != 0 {
		log.Debug(makeDepthPadding(depth+1), "-> answers found")
		return result, status, err
	} else if len(result.Authorities) != 0 {
		return s.iterateOnAuthorities(dnsType, name, depth, result, layer)
	} else {
		return result, zdns.STATUS_ERROR, errors.New("NOERROR record without any answers or authorities")
	}
}

func (s *Lookup) DoMiekgLookup(name string) (interface{}, zdns.Status, error) {
	if s.Factory.IterativeResolution {
		return s.iterativeLookup(s.DNSType, name, s.NameServer, 0, ".")
	} else {
		return s.retryingLookup(s.DNSType, name, s.NameServer, true)
	}
}

func (s *Lookup) DoTypedMiekgLookup(name string, dnsType uint16) (interface{}, zdns.Status, error) {
	if s.Factory.IterativeResolution {
		return s.iterativeLookup(dnsType, name, s.NameServer, 0, ".")
	} else {
		return s.retryingLookup(dnsType, name, s.NameServer, true)
	}
}

func (s *Lookup) DoTxtLookup(name string) (string, zdns.Status, error) {
	res, status, err := s.DoMiekgLookup(name)
	if status != zdns.STATUS_NOERROR {
		return "", status, err
	}
	if parsedResult, ok := res.(Result); ok {
		for _, a := range parsedResult.Answers {
			ans, _ := a.(Answer)
			if strings.HasPrefix(ans.Answer, s.Prefix) {
				return ans.Answer, zdns.STATUS_NOERROR, err
			}
		}
	}
	return "", zdns.STATUS_NO_RECORD, nil
}
