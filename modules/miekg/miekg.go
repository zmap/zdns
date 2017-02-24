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
	Ttl        uint32 `json:"ttl,omitempty"`
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Answer     string `json:"answer,omitempty"`
	Preference uint16 `json:"preference"`
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
			Ttl:        mx.Hdr.Ttl,
			Type:       dns.Type(mx.Hdr.Rrtype).String(),
			Name:       mx.Hdr.Name,
			Answer:     mx.Mx,
			Preference: mx.Preference,
		}
	} else if caa, ok := ans.(*dns.CAA); ok {
		return struct {
			Ttl   uint32 `json:"ttl"`
			Type  string `json:"type"`
			Tag   string `json:"tag"`
			Value string `json:"value"`
			Flag  uint8  `json:"flag"`
		}{
			Ttl:   caa.Hdr.Ttl,
			Type:  dns.Type(caa.Hdr.Rrtype).String(),
			Tag:   caa.Tag,
			Value: caa.Value,
			Flag:  caa.Flag,
		}
	} else if soa, ok := ans.(*dns.SOA); ok {
		return struct {
			Ttl     uint32 `json:"ttl"`
			Type    string `json:"type"`
			Name    string `json:"name"`
			Ns      string `json:"ns"`
			Mbox    string `json:"mbox"`
			Serial  uint32 `json:"serial"`
			Refresh uint32 `json:"refresh"`
			Retry   uint32 `json:"retry"`
			Expire  uint32 `json:"expire"`
			Minttl  uint32 `json:"min_ttl"`
		}{
			Ttl:     soa.Hdr.Ttl,
			Type:    dns.Type(soa.Hdr.Rrtype).String(),
			Name:    soa.Hdr.Name,
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
	CacheMutex     sync.RWMutex
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	s.IterativeCache.Init(c.CacheSize)
	return nil
}

func (s *GlobalLookupFactory) AddCachedAuthority(name string, authorities []string, ttl int) error {
	return nil
}

func (s *GlobalLookupFactory) GetCachedAuthority(name string) ([]string, error) {
	var retv []string
	return retv, nil
}

type RoutineLookupFactory struct {
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

func (s *Lookup) retryingLookup(dnsType uint16, name string, nameServer string, recursive bool) (Result, zdns.Status, error) {
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

func (s *Lookup) extractAuthority(res Result) (string, zdns.Status, error) {
	//fmt.Println("extract authority called on", res)
	if len(res.Authorities) == 0 {
		// this is a lost cause.
		return "", zdns.STATUS_SERVFAIL, nil
	}
	// most reasonable servers will include the A or AAAA record for a DNS
	// server in the additionals. Put all into a hash table that we can check
	// when we iterate over the records in the authorities section
	searchSet := make(map[string][]Answer)
	for _, a := range res.Additional {
		ans, ok := a.(Answer)
		if !ok {
			continue
		}
		if ans.Type == "A" {
			name := dotName(ans.Name)
			searchSet[name] = append(searchSet[name], ans)
		}
	}
	// check if we have the IP address for any of the authorities
	for _, a := range res.Authorities {
		ans, ok := a.(Answer)
		if !ok {
			continue
		}
		if ip, ok := searchSet[ans.Answer]; ok {
			server := strings.TrimSuffix(ip[0].Answer, ".") + ":53"
			return server, zdns.STATUS_NOERROR, nil
		}
	}
	// nothing was found. we need to lookup the A record for one of the NS servers. Quit once
	// we've found one.
	for _, a := range res.Authorities {
		ans, ok := a.(Answer)
		if !ok {
			continue
		}
		server := strings.TrimSuffix(ans.Answer, ".")
		res, status, _ := s.iterativeLookup(dns.TypeA, server, s.NameServer, 0)
		if status == zdns.STATUS_NOERROR {
			for _, inner_a := range res.Answers {
				inner_ans, ok := inner_a.(Answer)
				if !ok {
					continue
				}
				if inner_ans.Type == "A" {
					server := strings.TrimSuffix(inner_ans.Answer, ".") + ":53"
					return server, zdns.STATUS_NOERROR, nil
				}
			}
		}
	}
	return "", zdns.STATUS_SERVFAIL, nil
}

func (s *Lookup) iterativeLookup(dnsType uint16, name string, nameServer string, depth int) (Result, zdns.Status, error) {
	if log.GetLevel() == log.DebugLevel {
		nameServerReverse := "unknown"
		nameServerNoPort := strings.Split(nameServer, ":")[0]
		nameServers, err := net.LookupAddr(nameServerNoPort)
		if err == nil && len(nameServers) > 0 {
			nameServerReverse = strings.TrimSuffix(nameServers[0], ".")
		}
		log.Debug("iterative lookup for ", name, " (", dnsType, ") against ", nameServerNoPort, " (", nameServerReverse, ")")
	}
	if depth > s.Factory.MaxDepth {
		var r Result
		return r, zdns.STATUS_ERROR, errors.New("Max recursion depth reached")
	}
	result, status, err := s.retryingLookup(dnsType, name, nameServer, false)
	//j, _ := json.Marshal(result)
	//fmt.Println(string(j))
	if status != zdns.STATUS_NOERROR {
		return result, status, err
	} else if result.Flags.Authoritative == true {
		return result, status, err
	} else if len(result.Answers) != 0 {
		return result, status, err
	} else if len(result.Authorities) != 0 {
		// find an appropriate name server and continue the recursion
		ns, ns_status, _ := s.extractAuthority(result)
		//fmt.Println(">>>>>", ns)
		if ns_status != zdns.STATUS_NOERROR {
			var r Result
			return r, zdns.STATUS_ERROR, errors.New("could not find authoritative name server")
		}
		return s.iterativeLookup(dnsType, name, ns, depth+1)
	} else {
		return result, zdns.STATUS_ERROR, errors.New("NOERROR record without any answers or authorities")
	}
}

func (s *Lookup) DoMiekgLookup(name string) (interface{}, zdns.Status, error) {
	if s.Factory.IterativeResolution {
		return s.iterativeLookup(s.DNSType, name, s.NameServer, 0)
	} else {
		return s.retryingLookup(s.DNSType, name, s.NameServer, true)
	}
}

func (s *Lookup) DoTxtLookup(name string) (string, zdns.Status, error) {
	res, status, err := s.DoLookup(name)
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
