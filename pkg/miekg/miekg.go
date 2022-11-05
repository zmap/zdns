/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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

package miekg

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/zmap/dns"
	"github.com/zmap/go-iptree/blacklist"
	"github.com/zmap/zdns/pkg/zdns"
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

type Question struct {
	Type  uint16
	Class uint16
	Name  string
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

type ExtendedResult struct {
	Res        Result      `json:"result,omitempty" groups:"short,normal,long,trace"`
	Status     zdns.Status `json:"status" groups:"short,normal,long,trace"`
	Nameserver string      `json:"nameserver" groups:"short,normal,long,trace"`
}

type CombinedResult struct {
	Results []ExtendedResult `json:"results" groups:"short,normal,long,trace"`
}

type NSRecord struct {
	Name          string   `json:"name" groups:"short,normal,long,trace"`
	Type          string   `json:"type" groups:"short,normal,long,trace"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
	TTL           uint32   `json:"ttl" groups:"normal,long,trace"`
}

type NSResult struct {
	Servers []NSRecord `json:"servers,omitempty" groups:"short,normal,long,trace"`
}

type IpResult struct {
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
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
	Try        int      `json:"try" groups:"trace"`
}

func (s *GlobalLookupFactory) VerboseGlobalLog(depth int, threadID int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth, threadID), args)
}

func (s *Lookup) VerboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth, s.Factory.ThreadID), args)
}

// ZDNS Module

type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
	IterativeCache Cache
	DNSType        uint16
	DNSClass       uint16
	BlacklistPath  string
	Blacklist      *blacklist.Blacklist
	BlMu           sync.Mutex
}

// Lookup client interface for helping in mocking
type LookupClient interface {
	ProtocolLookup(s *Lookup, q Question, nameServer string) (interface{}, zdns.Trace, zdns.Status, error)
}

type MiekgLookupClient struct{}

func (lc MiekgLookupClient) ProtocolLookup(s *Lookup, q Question, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	return s.DoMiekgLookup(q, nameServer)
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

func (s *GlobalLookupFactory) SetFlags(f *pflag.FlagSet) {
	// If there's an error, panic is appropriate since we should at least be getting the default here.
	var err error
	s.BlacklistPath, err = f.GetString("blacklist-file")
	if err != nil {
		panic(err)
	}
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	err := s.BlacklistInit()
	if err != nil {
		return err
	}
	s.IterativeCache.Init(c.CacheSize)
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
	r.DNSType = s.DNSType
	r.ThreadID = threadID
	r.Initialize(s.GlobalConf)
	return r, nil
}

type RoutineLookupFactory struct {
	Factory              *GlobalLookupFactory
	ClientV4             *dns.Client
	ClientV6             *dns.Client
	TCPClientV4          *dns.Client
	TCPClientV6          *dns.Client
	Retries              int
	MaxDepth             int
	Timeout              time.Duration
	IterativeTimeout     time.Duration
	IterativeResolution  bool
	LookupAllNameServers bool
	Trace                bool
	DNSType              uint16
	DNSClass             uint16
	LocalV4Addr          net.IP
	LocalV6Addr          net.IP
	ConnV4               *dns.Conn
	ConnV6               *dns.Conn
	ThreadID             int
	PrefixRegexp         *regexp.Regexp
}

func (s *RoutineLookupFactory) Initialize(c *zdns.GlobalConf) {
	if c.IterativeResolution {
		s.Timeout = c.IterationTimeout
	} else {
		s.Timeout = c.Timeout
	}

	if s.Factory == nil {
		panic("null factory")
	}
	s.LocalV4Addr = s.Factory.RandomLocalV4Addr()
	s.LocalV6Addr = s.Factory.RandomLocalV6Addr()

	if s.LocalV4Addr == nil && s.LocalV6Addr == nil {
		// We should not be able to get here; config should have handled this
		log.Fatal("No local addresses specified")
	}

	if !c.TCPOnly {
		if s.LocalV4Addr != nil {
			s.ClientV4 = new(dns.Client)
			s.ClientV4.Timeout = s.Timeout
			s.ClientV4.Dialer = &net.Dialer{
				Timeout:   s.Timeout,
				LocalAddr: &net.UDPAddr{IP: s.LocalV4Addr},
			}
			if c.RecycleSockets {
				// create PacketConn for use throughout thread's life
				conn, err := net.ListenUDP("udp", &net.UDPAddr{s.LocalV4Addr, 0, ""})
				if err != nil {
					log.Fatal("unable to create socket", err)
				}
				s.ConnV4 = new(dns.Conn)
				s.ConnV4.Conn = conn
			}
		}

		if s.LocalV6Addr != nil {
			s.ClientV6 = new(dns.Client)
			s.ClientV6.Timeout = s.Timeout
			s.ClientV6.Dialer = &net.Dialer{
				Timeout:   s.Timeout,
				LocalAddr: &net.UDPAddr{IP: s.LocalV6Addr},
			}
			if c.RecycleSockets {
				// create PacketConn for use throughout thread's life
				conn, err := net.ListenUDP("udp", &net.UDPAddr{s.LocalV6Addr, 0, ""})
				if err != nil {
					log.Fatal("unable to create socket", err)
				}
				s.ConnV6 = new(dns.Conn)
				s.ConnV6.Conn = conn
			}

		}

	}
	if !c.UDPOnly {
		if s.LocalV4Addr != nil {
			s.TCPClientV4 = new(dns.Client)
			s.TCPClientV4.Net = "tcp"
			s.TCPClientV4.Timeout = s.Timeout
			s.TCPClientV4.Dialer = &net.Dialer{
				Timeout:   s.Timeout,
				LocalAddr: &net.TCPAddr{IP: s.LocalV4Addr},
			}
		}
		if s.LocalV6Addr != nil {
			s.TCPClientV6 = new(dns.Client)
			s.TCPClientV6.Net = "tcp"
			s.TCPClientV6.Timeout = s.Timeout
			s.TCPClientV6.Dialer = &net.Dialer{
				Timeout:   s.Timeout,
				LocalAddr: &net.TCPAddr{IP: s.LocalV6Addr},
			}
		}
	}
	s.IterativeTimeout = c.Timeout
	s.Retries = c.Retries
	s.MaxDepth = c.MaxDepth
	s.IterativeResolution = c.IterativeResolution
	s.LookupAllNameServers = c.LookupAllNameServers
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
	NameServer    string
	IterativeStop time.Time

	ConnV4 *dns.Conn
	ConnV6 *dns.Conn
}

func (s *Lookup) Initialize(nameServer string, dnsType uint16, dnsClass uint16, factory *RoutineLookupFactory) error {
	s.Factory = factory
	s.NameServer = nameServer
	s.DNSType = dnsType
	s.DNSClass = dnsClass
	s.ConnV4 = factory.ConnV4
	s.ConnV6 = factory.ConnV6

	return nil
}

func (s *Lookup) doLookup(q Question, nameServer string, recursive bool) (Result, zdns.Status, error) {
	return DoLookupWorker(s.Factory.ClientV4, s.Factory.ClientV6, s.Factory.TCPClientV4, s.Factory.TCPClientV6, s.ConnV4, s.ConnV6, q, nameServer, recursive)
}

// CheckTxtRecords common function for all modules based on search in TXT record
func (s *Lookup) CheckTxtRecords(res interface{}, status zdns.Status, err error) (string, zdns.Status, error) {
	if status != zdns.STATUS_NOERROR {
		return "", status, err
	}
	cast, _ := res.(Result)
	resString, err := s.FindTxtRecord(cast)
	if err != nil {
		status = zdns.STATUS_NO_RECORD
	} else {
		status = zdns.STATUS_NOERROR
	}
	return resString, status, err
}

func (s *Lookup) FindTxtRecord(res Result) (string, error) {

	for _, a := range res.Answers {
		ans, _ := a.(Answer)
		if s.Factory.PrefixRegexp == nil || s.Factory.PrefixRegexp.MatchString(ans.Answer) {
			return ans.Answer, nil
		}
	}
	return "", errors.New("no such TXT record found")
}

// Expose the inner logic so other tools can use it
func DoLookupWorker(udpV4 *dns.Client, udpV6 *dns.Client, tcpV4 *dns.Client, tcpV6 *dns.Client, connV4 *dns.Conn, connV6 *dns.Conn, q Question, nameServer string, recursive bool) (Result, zdns.Status, error) {
	res := Result{Answers: []interface{}{}, Authorities: []interface{}{}, Additional: []interface{}{}}
	res.Resolver = nameServer

	m := new(dns.Msg)
	m.SetQuestion(dotName(q.Name), q.Type)
	m.Question[0].Qclass = q.Class
	m.RecursionDesired = recursive

	var r *dns.Msg
	var err error

	if udpV4 != nil || udpV6 != nil  {

		res.Protocol = "udp"
		var conn *dns.Conn
		var udp *dns.Client

		dst, _ := net.ResolveUDPAddr("udp", nameServer)
		if dst.IP.To4() != nil {
			conn = connV4
			udp = udpV4
		} else {
			conn = connV6
			udp = udpV6
		}

		if conn != nil {
			r, _, err = udp.ExchangeWithConnTo(m, conn, dst)
		} else {
			r, _, err = udp.Exchange(m, nameServer)
		}

		// if record comes back truncated, but we have a TCP connection, try again with that
		if r != nil && (r.Truncated || r.Rcode == dns.RcodeBadTrunc) {
			if tcpV4 != nil || tcpV6 != nil {
				return DoLookupWorker(nil, nil, tcpV4, tcpV6, connV4, connV6, q, nameServer, recursive)
			} else {
				return res, zdns.STATUS_TRUNCATED, err
			}
		}
	} else {
		res.Protocol = "tcp"
		var tcp *dns.Client

		dst, _ := net.ResolveTCPAddr("tcp", nameServer)
		if dst.IP.To4() != nil {
			tcp = tcpV4
		} else {
			tcp = tcpV6
		}

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

func (s *Lookup) tracedRetryingLookup(q Question, nameServer string, recursive bool) (Result, zdns.Trace, zdns.Status, error) {

	res, status, try, err := s.retryingLookup(q, nameServer, recursive)

	trace := make([]interface{}, 0)

	if s.Factory.Trace {
		var t TraceStep
		t.Result = res
		t.DnsType = q.Type
		t.DnsClass = q.Class
		t.Name = q.Name
		t.NameServer = nameServer
		t.Layer = q.Name
		t.Depth = 1
		t.Cached = false
		t.Try = try
		trace = append(trace, t)
	}

	return res, trace, status, err
}

func (s *Lookup) retryingLookup(q Question, nameServer string, recursive bool) (Result, zdns.Status, int, error) {
	s.VerboseLog(1, "****WIRE LOOKUP*** ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)

	var origTimeout time.Duration
	var UDPClient *dns.Client
	var TCPClient *dns.Client

	// Figure out if we're talking to a v4 or v6 server
	// This can be udp or tcp, doesnt matter, we just want to parse the nameserver and port.
	dst, _ := net.ResolveUDPAddr("udp", nameServer)

	if dst.IP.To4() != nil {
		UDPClient = s.Factory.ClientV4
		TCPClient = s.Factory.TCPClientV4
	} else {
		UDPClient = s.Factory.ClientV6
		TCPClient = s.Factory.TCPClientV6
	}

	if UDPClient != nil {
		origTimeout = UDPClient.Timeout
	} else {
		origTimeout = TCPClient.Timeout
	}
	for i := 0; i <= s.Factory.Retries; i++ {
		result, status, err := s.doLookup(q, nameServer, recursive)
		if (status != zdns.STATUS_TIMEOUT && status != zdns.STATUS_TEMPORARY) || i == s.Factory.Retries {
			if UDPClient != nil {
				UDPClient.Timeout = origTimeout
			}
			if TCPClient != nil {
				TCPClient.Timeout = origTimeout
			}
			return result, status, (i + 1), err
		}
		if UDPClient != nil {
			UDPClient.Timeout = 2 * UDPClient.Timeout
		}
		if TCPClient != nil {
			TCPClient.Timeout = 2 * TCPClient.Timeout
		}
	}
	panic("loop must return")
}

func (s *Lookup) cachedRetryingLookup(q Question, nameServer, layer string, depth int) (Result, IsCached, zdns.Status, int, error) {
	var isCached IsCached
	isCached = false
	s.VerboseLog(depth+1, "Cached retrying lookup. Name: ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)
	if s.IterativeStop.Before(time.Now()) {
		s.VerboseLog(depth+2, "ITERATIVE_TIMEOUT ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)
		var r Result
		return r, isCached, zdns.STATUS_ITER_TIMEOUT, 0, nil
	}
	// First, we check the answer
	cachedResult, ok := s.Factory.Factory.IterativeCache.GetCachedResult(q, false, depth+1, s.Factory.ThreadID)
	if ok {
		isCached = true
		return cachedResult, isCached, zdns.STATUS_NOERROR, 0, nil
	}

	nameServerIP, _, err := net.SplitHostPort(nameServer)
	// Stop if we hit a nameserver we don't want to hit
	if s.Factory.Factory.Blacklist != nil {
		s.Factory.Factory.BlMu.Lock()
		if blacklisted, err := s.Factory.Factory.Blacklist.IsBlacklisted(nameServerIP); err != nil {
			s.Factory.Factory.BlMu.Unlock()
			s.VerboseLog(depth+2, "Blacklist error!", err)
			var r Result
			return r, isCached, zdns.STATUS_ERROR, 0, err
		} else if blacklisted {
			s.Factory.Factory.BlMu.Unlock()
			s.VerboseLog(depth+2, "Hit blacklisted nameserver ", q.Name, ", Layer: ", layer, ", Nameserver: ", nameServer)
			var r Result
			return r, isCached, zdns.STATUS_BLACKLIST, 0, nil
		}
		s.Factory.Factory.BlMu.Unlock()
	}

	// Now, we check the authoritative:
	name := strings.ToLower(q.Name)
	layer = strings.ToLower(layer)
	authName, err := nextAuthority(name, layer)
	if err != nil {
		s.VerboseLog(depth+2, err)
		var r Result
		return r, isCached, zdns.STATUS_AUTHFAIL, 0, err
	}
	if name != layer && authName != layer {
		if authName == "" {
			s.VerboseLog(depth+2, "Can't parse name to authority properly. name: ", name, ", layer: ", layer)
			var r Result
			return r, isCached, zdns.STATUS_AUTHFAIL, 0, nil
		}
		s.VerboseLog(depth+2, "Cache auth check for ", authName)
		var qAuth Question
		qAuth.Name = authName
		qAuth.Type = dns.TypeNS
		qAuth.Class = dns.ClassINET
		cachedResult, ok = s.Factory.Factory.IterativeCache.GetCachedResult(qAuth, true, depth+2, s.Factory.ThreadID)
		if ok {
			isCached = true
			return cachedResult, isCached, zdns.STATUS_NOERROR, 0, nil
		}
	}

	// Alright, we're not sure what to do, go to the wire.
	s.VerboseLog(depth+2, "Wire lookup for name: ", q.Name, " (", q.Type, ") at nameserver: ", nameServer)
	result, status, try, err := s.retryingLookup(q, nameServer, false)

	s.Factory.Factory.IterativeCache.CacheUpdate(layer, result, depth+2, s.Factory.ThreadID)
	return result, isCached, status, try, err
}

func (s *Lookup) extractAuthority(authority interface{}, layer string, depth int, result Result, trace []interface{}) (string, zdns.Status, string, []interface{}) {

	// Is it an answer
	ans, ok := authority.(Answer)
	if !ok {
		return "", zdns.STATUS_FORMERR, layer, trace
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
	res, status := checkGlue(server, depth, result)
	if status != zdns.STATUS_NOERROR {
		// Fall through to normal query
		var q Question
		q.Name = server
		q.Type = dns.TypeA
		q.Class = dns.ClassINET
		res, trace, status, _ = s.iterativeLookup(q, s.NameServer, depth+1, ".", trace)
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

func (s *Lookup) iterateOnAuthorities(q Question, depth int, result Result, layer string, trace []interface{}) (Result, []interface{}, zdns.Status, error) {
	//
	if len(result.Authorities) == 0 {
		var r Result
		return r, trace, zdns.STATUS_NOAUTH, nil
	}
	for i, elem := range result.Authorities {
		s.VerboseLog(depth+1, "Trying Authority: ", elem)
		ns, ns_status, layer, trace := s.extractAuthority(elem, layer, depth, result, trace)
		s.VerboseLog((depth + 1), "Output from extract authorities: ", ns)
		if ns_status == zdns.STATUS_ITER_TIMEOUT {
			s.VerboseLog((depth + 2), "--> Hit iterative timeout: ")
			var r Result
			return r, trace, zdns.STATUS_ITER_TIMEOUT, nil
		}
		if ns_status != zdns.STATUS_NOERROR {
			var err error
			new_status, err := handleStatus(&ns_status, err)
			// default case we continue
			if new_status == nil && err == nil {
				if i+1 == len(result.Authorities) {
					s.VerboseLog((depth + 2), "--> Auth find Failed. Unknown error. No more authorities to try, terminating: ", ns_status)
					var r Result
					return r, trace, ns_status, err
				} else {
					s.VerboseLog((depth + 2), "--> Auth find Failed. Unknown error. Continue: ", ns_status)
					continue
				}
			} else {
				// otherwise we hit a status we know
				var r Result
				if i+1 == len(result.Authorities) {
					// We don't allow the continue fall through in order to report the last auth falure code, not STATUS_EROR
					s.VerboseLog((depth + 2), "--> Final auth find non-success. Last auth. Terminating: ", ns_status)
					return r, trace, *new_status, err
				} else {
					s.VerboseLog((depth + 2), "--> Auth find non-success. Trying next: ", ns_status)
					continue
				}
			}
		}
		r, trace, status, err := s.iterativeLookup(q, ns, depth+1, layer, trace)
		if isStatusAnswer(status) {
			s.VerboseLog((depth + 1), "--> Auth Resolution success: ", status)
			return r, trace, status, err
		} else if i+1 < len(result.Authorities) {
			s.VerboseLog((depth + 2), "--> Auth resolution of ", ns, " Failed: ", status, ". Will try next authority")
			continue
		} else {
			// We don't allow the continue fall through in order to report the last auth falure code, not STATUS_EROR
			s.VerboseLog((depth + 2), "--> Iterative resolution of ", q.Name, " at ", ns, " Failed. Last auth. Terminating: ", status)
			return r, trace, status, err
		}
	}
	panic("should not be able to reach here")
}

func (s *Lookup) iterativeLookup(q Question, nameServer string,
	depth int, layer string, trace []interface{}) (Result, []interface{}, zdns.Status, error) {
	//
	if log.GetLevel() == log.DebugLevel {
		s.VerboseLog((depth), "iterative lookup for ", q.Name, " (", q.Type, ") against ", nameServer, " layer ", layer)
	}
	if depth > s.Factory.MaxDepth {
		var r Result
		s.VerboseLog((depth + 1), "-> Max recursion depth reached")
		return r, trace, zdns.STATUS_ERROR, errors.New("Max recursion depth reached")
	}
	result, isCached, status, try, err := s.cachedRetryingLookup(q, nameServer, layer, depth)
	if s.Factory.Trace && status == zdns.STATUS_NOERROR {
		var t TraceStep
		t.Result = result
		t.DnsType = q.Type
		t.DnsClass = q.Class
		t.Name = q.Name
		t.NameServer = nameServer
		t.Layer = layer
		t.Depth = depth
		t.Cached = isCached
		t.Try = try
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
		return s.iterateOnAuthorities(q, depth, result, layer, trace)
	} else {
		s.VerboseLog((depth + 1), "-> No Authority found, error")
		return result, trace, zdns.STATUS_ERROR, errors.New("NOERROR record without any answers or authorities")
	}
}

func (s *Lookup) DoMiekgLookup(q Question, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if nameServer == "" {
		nameServer = s.NameServer
	}
	if q.Type == 0 {
		q.Type = s.DNSType
	}
	if q.Class == 0 {
		q.Class = s.DNSClass
	}
	if s.DNSType == dns.TypePTR {
		var err error
		q.Name, err = dns.ReverseAddr(q.Name)
		if err != nil {
			return nil, nil, zdns.STATUS_ILLEGAL_INPUT, err
		}
		q.Name = q.Name[:len(q.Name)-1]
	}
	if s.Factory.IterativeResolution {
		s.VerboseLog(0, "MIEKG-IN: iterative lookup for ", q.Name, " (", q.Type, ")")
		s.IterativeStop = time.Now().Add(time.Duration(s.Factory.IterativeTimeout))
		result, trace, status, err := s.iterativeLookup(q, nameServer, 1, ".", make([]interface{}, 0))
		s.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", q.Name, " (", q.Type, "): status: ", status, " , err: ", err)
		if s.Factory.Trace {
			return result, trace, status, err
		}
		return result, trace, status, err
	} else {
		return s.tracedRetryingLookup(q, nameServer, true)
	}
}

func populateResults(records []interface{}, dnsType uint16, candidateSet map[string][]Answer, cnameSet map[string][]Answer, garbage map[string][]Answer) {
	for _, a := range records {
		// filter only valid answers of requested type or CNAME (#163)
		if ans, ok := a.(Answer); ok {
			lowerCaseName := strings.ToLower(strings.TrimSuffix(ans.Name, "."))
			// Verify that the answer type matches requested type
			if VerifyAddress(ans.Type, ans.Answer) {
				ansType := dns.StringToType[ans.Type]
				if dnsType == ansType {
					candidateSet[lowerCaseName] = append(candidateSet[lowerCaseName], ans)
				} else if ok && dns.TypeCNAME == ansType {
					cnameSet[lowerCaseName] = append(cnameSet[lowerCaseName], ans)
				} else {
					garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
				}
			} else {
				garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
			}
		}
	}
}

// Function to recursively search for IP addresses
func (s *Lookup) DoIpsLookup(lc LookupClient, name string, nameServer string, dnsType uint16, candidateSet map[string][]Answer, cnameSet map[string][]Answer, origName string, depth int) ([]string, []interface{}, zdns.Status, error) {
	// avoid infinite loops
	if name == origName && depth != 0 {
		return nil, make([]interface{}, 0), zdns.STATUS_ERROR, errors.New("infinite redirection loop")
	}
	if depth > 10 {
		return nil, make([]interface{}, 0), zdns.STATUS_ERROR, errors.New("max recursion depth reached")
	}
	// check if the record is already in our cache. if not, perform normal A lookup and
	// see what comes back. Then iterate over results and if needed, perform further lookups
	var trace []interface{}
	garbage := map[string][]Answer{}
	if _, ok := candidateSet[name]; !ok {
		var miekgResult interface{}
		var status zdns.Status
		var err error
		miekgResult, trace, status, err = lc.ProtocolLookup(s, Question{Name: name, Type: dnsType}, nameServer)
		if status != zdns.STATUS_NOERROR || err != nil {
			return nil, trace, status, err
		}

		populateResults(miekgResult.(Result).Answers, dnsType, candidateSet, cnameSet, garbage)
		populateResults(miekgResult.(Result).Additional, dnsType, candidateSet, cnameSet, garbage)
	}
	// our cache should now have any data that exists about the current name
	if res, ok := candidateSet[name]; ok && len(res) > 0 {
		// we have IP addresses to hand back to the user. let's make an easy-to-use array of strings
		var ips []string
		for _, answer := range res {
			ips = append(ips, answer.Answer)
		}
		return ips, trace, zdns.STATUS_NOERROR, nil
	} else if res, ok = cnameSet[name]; ok && len(res) > 0 {
		// we have a CNAME and need to further recurse to find IPs
		shortName := strings.ToLower(strings.TrimSuffix(res[0].Answer, "."))
		res, secondTrace, status, err := s.DoIpsLookup(lc, shortName, nameServer, dnsType, candidateSet, cnameSet, origName, depth+1)
		trace = append(trace, secondTrace...)
		return res, trace, status, err
	} else if res, ok = garbage[name]; ok && len(res) > 0 {
		return nil, trace, zdns.STATUS_ERROR, errors.New("unexpected record type received")
	} else {
		// we have no data whatsoever about this name. return an empty recordset to the user
		var ips []string
		return ips, trace, zdns.STATUS_NOERROR, nil
	}
}

func (s *Lookup) DoTargetedLookup(l LookupClient, name, nameServer string, lookupIpv4 bool, lookupIpv6 bool) (interface{}, []interface{}, zdns.Status, error) {
	res := IpResult{}
	candidateSet := map[string][]Answer{}
	cnameSet := map[string][]Answer{}
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace []interface{}
	var ipv6Trace []interface{}
	var ipv4status zdns.Status
	var ipv6status zdns.Status

	if lookupIpv4 {
		ipv4, ipv4Trace, ipv4status, _ = s.DoIpsLookup(l, name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0)
		if len(ipv4) > 0 {
			res.IPv4Addresses = make([]string, len(ipv4))
			copy(res.IPv4Addresses, ipv4)
		}
	}
	candidateSet = map[string][]Answer{}
	cnameSet = map[string][]Answer{}
	if lookupIpv6 {
		ipv6, ipv6Trace, ipv6status, _ = s.DoIpsLookup(l, name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0)
		if len(ipv6) > 0 {
			res.IPv6Addresses = make([]string, len(ipv6))
			copy(res.IPv6Addresses, ipv6)
		}
	}

	combinedTrace := append(ipv4Trace, ipv6Trace...)

	// In case we get no IPs and a non-NOERROR status from either
	// IPv4 or IPv6 lookup, we return that status.
	if len(res.IPv4Addresses) == 0 && len(res.IPv6Addresses) == 0 {
		if lookupIpv4 && !SafeStatus(ipv4status) {
			return nil, combinedTrace, ipv4status, nil
		} else if lookupIpv6 && !SafeStatus(ipv6status) {
			return nil, combinedTrace, ipv6status, nil
		} else {
			return res, combinedTrace, zdns.STATUS_NOERROR, nil
		}
	}
	return res, combinedTrace, zdns.STATUS_NOERROR, nil
}

func (s *Lookup) DoNSLookup(l LookupClient, name string, lookupIpv4 bool, lookupIpv6 bool, nameServer string) (NSResult, zdns.Trace, zdns.Status, error) {
	var retv NSResult
	res, trace, status, err := l.ProtocolLookup(s, Question{Name: name, Type: dns.TypeNS}, nameServer)
	if status != zdns.STATUS_NOERROR || err != nil {
		return retv, trace, status, err
	}
	ns := res.(Result)
	ipv4s := make(map[string][]string)
	ipv6s := make(map[string][]string)
	for _, ans := range ns.Additional {
		a, ok := ans.(Answer)
		if !ok {
			continue
		}
		recName := strings.TrimSuffix(a.Name, ".")
		if VerifyAddress(a.Type, a.Answer) {
			if a.Type == "A" {
				ipv4s[recName] = append(ipv4s[recName], a.Answer)
			} else if a.Type == "AAAA" {
				ipv6s[recName] = append(ipv6s[recName], a.Answer)
			}
		}
	}
	for _, ans := range ns.Answers {
		a, ok := ans.(Answer)
		if !ok {
			continue
		}

		if a.Type != "NS" {
			continue
		}

		var rec NSRecord
		rec.Type = a.Type
		rec.Name = strings.TrimSuffix(a.Answer, ".")
		rec.TTL = a.Ttl

		var findIpv4 = false
		var findIpv6 = false

		if lookupIpv4 {
			if ips, ok := ipv4s[rec.Name]; ok {
				rec.IPv4Addresses = ips
			} else {
				findIpv4 = true
			}
		}
		if lookupIpv6 {
			if ips, ok := ipv6s[rec.Name]; ok {
				rec.IPv6Addresses = ips
			} else {
				findIpv6 = true
			}
		}
		if findIpv4 || findIpv6 {
			res, nextTrace, _, _ := s.DoTargetedLookup(l, rec.Name, nameServer, findIpv4, findIpv6)
			if res != nil {
				if findIpv4 {
					rec.IPv4Addresses = res.(IpResult).IPv4Addresses
				}
				if findIpv6 {
					rec.IPv6Addresses = res.(IpResult).IPv6Addresses
				}
			}
			trace = append(trace, nextTrace...)
		}

		retv.Servers = append(retv.Servers, rec)
	}
	return retv, trace, zdns.STATUS_NOERROR, nil
}

func (s *Lookup) DoLookupAllNameservers(l LookupClient, name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	var retv CombinedResult
	var curServer string

	// Lookup both ipv4 and ipv6 addresses of nameservers.
	nsResults, nsTrace, nsStatus, nsError := s.DoNSLookup(l, name, true, true, nameServer)

	// Terminate early if nameserver lookup also failed
	if nsStatus != zdns.STATUS_NOERROR {
		return nil, nsTrace, nsStatus, nsError
	}

	// fullTrace holds the complete trace including all lookups
	var fullTrace zdns.Trace = nsTrace
	var tmpRes Result

	for _, nserver := range nsResults.Servers {
		// Use all the ipv4 and ipv6 addresses of each nameserver
		nameserver := nserver.Name
		ips := append(nserver.IPv4Addresses, nserver.IPv6Addresses...)
		for _, ip := range ips {
			curServer = net.JoinHostPort(ip, "53")
			res, trace, status, _ := l.ProtocolLookup(s, Question{Name: name, Type: s.DNSType, Class: s.DNSClass}, curServer)

			fullTrace = append(fullTrace, trace...)
			tmpRes = Result{}
			if res != nil {
				tmpRes = res.(Result)
			}
			extendedResult := ExtendedResult{
				Res:        tmpRes,
				Status:     status,
				Nameserver: nameserver,
			}
			retv.Results = append(retv.Results, extendedResult)
		}
	}
	return retv, fullTrace, zdns.STATUS_NOERROR, nil
}

// allow miekg to be used as a ZDNS module
func (s *Lookup) DoLookup(name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if s.Factory.LookupAllNameServers {
		l := MiekgLookupClient{}
		return s.DoLookupAllNameservers(l, name, nameServer)
	} else {
		return s.DoMiekgLookup(Question{Name: name, Type: s.DNSType, Class: s.DNSClass}, nameServer)
	}
}
