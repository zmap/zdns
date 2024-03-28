package refactored_zdns

import (
	"context"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"net"
	"strings"
	"time"
)

// GetDNSServers returns a list of DNS servers from a file, or an error if one occurs
func GetDNSServers(path string) ([]string, error) {
	c, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return []string{}, fmt.Errorf("error reading DNS config file: %w", err)
	}
	var servers []string
	for _, s := range c.Servers {
		if s[0:1] != "[" && strings.Contains(s, ":") {
			s = "[" + s + "]"
		}
		full := strings.Join([]string{s, c.Port}, ":")
		servers = append(servers, full)
	}
	return servers, nil
}

func handleStatus(status *Status, err error) (*Status, error) {
	switch *status {
	case STATUS_ITER_TIMEOUT:
		return status, err
	case STATUS_NXDOMAIN:
		return status, nil
	case STATUS_SERVFAIL:
		return status, nil
	case STATUS_REFUSED:
		return status, nil
	case STATUS_AUTHFAIL:
		return status, nil
	case STATUS_NO_RECORD:
		return status, nil
	case STATUS_BLACKLIST:
		return status, nil
	case STATUS_NO_OUTPUT:
		return status, nil
	case STATUS_NO_ANSWER:
		return status, nil
	case STATUS_TRUNCATED:
		return status, nil
	case STATUS_ILLEGAL_INPUT:
		return status, nil
	case STATUS_TEMPORARY:
		return status, nil
	default:
		var s *Status
		return s, nil
	}
}

// TODO Phillip: what exactly does this function do??? Improve docs and comments, make it clear
func (r *Resolver) DoTargetedLookup(name, nameServer string, lookupIpv4 bool, lookupIpv6 bool) (*IPResult, Trace, Status, error) {
	name = strings.ToLower(name)
	res := IPResult{}
	candidateSet := map[string][]Answer{}
	cnameSet := map[string][]Answer{}
	var ipv4 []string
	var ipv6 []string
	var ipv4Trace Trace
	var ipv6Trace Trace
	var ipv4status Status
	var ipv6status Status

	if lookupIpv4 {
		ipv4, ipv4Trace, ipv4status, _ = r.DoIpsLookup(name, nameServer, dns.TypeA, candidateSet, cnameSet, name, 0)
		if len(ipv4) > 0 {
			ipv4 = Unique(ipv4)
			res.IPv4Addresses = make([]string, len(ipv4))
			copy(res.IPv4Addresses, ipv4)
		}
	}
	candidateSet = map[string][]Answer{}
	cnameSet = map[string][]Answer{}
	if lookupIpv6 {
		ipv6, ipv6Trace, ipv6status, _ = r.DoIpsLookup(name, nameServer, dns.TypeAAAA, candidateSet, cnameSet, name, 0)
		if len(ipv6) > 0 {
			ipv6 = Unique(ipv6)
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
			return &res, combinedTrace, STATUS_NOERROR, nil
		}
	}
	return &res, combinedTrace, STATUS_NOERROR, nil
}

// TODO Phillip: what exactly does this function do???
// Function to recursively search for IP addresses
func (r *Resolver) DoIpsLookup(name string, nameServer string, dnsType uint16, candidateSet map[string][]Answer, cnameSet map[string][]Answer, origName string, depth int) ([]string, Trace, Status, error) {
	// avoid infinite loops
	if name == origName && depth != 0 {
		return nil, make(Trace, 0), STATUS_ERROR, errors.New("infinite redirection loop")
	}
	if depth > 10 {
		return nil, make(Trace, 0), STATUS_ERROR, errors.New("max recursion depth reached")
	}
	// check if the record is already in our cache. if not, perform normal A lookup and
	// see what comes back. Then iterate over results and if needed, perform further lookups
	var trace Trace
	garbage := map[string][]Answer{}
	if _, ok := candidateSet[name]; !ok {
		var miekgResult interface{}
		var status Status
		var err error
		miekgResult, trace, status, err = r.doSingleNameServerLookup(Question{Name: name, Type: dnsType}, nameServer)
		if status != STATUS_NOERROR || err != nil {
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
		return ips, trace, STATUS_NOERROR, nil
	} else if res, ok = cnameSet[name]; ok && len(res) > 0 {
		// we have a CNAME and need to further recurse to find IPs
		shortName := strings.ToLower(strings.TrimSuffix(res[0].Answer, "."))
		res, secondTrace, status, err := r.DoIpsLookup(shortName, nameServer, dnsType, candidateSet, cnameSet, origName, depth+1)
		trace = append(trace, secondTrace...)
		return res, trace, status, err
	} else if res, ok = garbage[name]; ok && len(res) > 0 {
		return nil, trace, STATUS_ERROR, errors.New("unexpected record type received")
	} else {
		// we have no data whatsoever about this name. return an empty recordset to the user
		var ips []string
		return ips, trace, STATUS_NOERROR, nil
	}
}

/*
// TODO Phillip, yeah we gotta rename this
doSingleNameServerLookup

	iterativeLookup
		cachedRetryingLookup
			retryingLookup
				wireLookup

doSingleNameServerLookup

	retryingLookup
*/
func (r *Resolver) doLookupAllNameservers(q Question, nameServer string) (interface{}, Trace, Status, error) {
	var retv CombinedResults
	var curServer string

	// Lookup both ipv4 and ipv6 addresses of nameservers.
	nsResults, nsTrace, nsStatus, nsError := r.DoNSLookup(q.Name, true, true, nameServer)

	// Terminate early if nameserver lookup also failed
	if nsStatus != STATUS_NOERROR {
		return nil, nsTrace, nsStatus, nsError
	}

	// fullTrace holds the complete trace including all lookups
	var fullTrace Trace = nsTrace
	var tmpRes Result

	for _, nserver := range nsResults.Servers {
		// Use all the ipv4 and ipv6 addresses of each nameserver
		nameserver := nserver.Name
		ips := append(nserver.IPv4Addresses, nserver.IPv6Addresses...)
		for _, ip := range ips {
			curServer = net.JoinHostPort(ip, "53")
			res, trace, status, err := r.doSingleNameServerLookup(q, curServer)

			fullTrace = append(fullTrace, trace...)
			tmpRes = Result{}
			if err == nil {
				tmpRes = res
			}
			extendedResult := ExtendedResult{
				Res:        tmpRes,
				Status:     status,
				Nameserver: nameserver,
			}
			retv.Results = append(retv.Results, extendedResult)
		}
	}
	return retv, fullTrace, STATUS_NOERROR, nil
}

func (r *Resolver) doSingleNameServerLookup(q Question, nameServer string) (Result, Trace, Status, error) {
	if nameServer == "" {
		return Result{}, nil, STATUS_ILLEGAL_INPUT, errors.New("no nameserver specified")
	}

	if q.Type == dns.TypePTR {
		var err error
		q.Name, err = dns.ReverseAddr(q.Name)
		if err != nil {
			return Result{}, nil, STATUS_ILLEGAL_INPUT, err
		}
		q.Name = q.Name[:len(q.Name)-1]
	}
	if r.isIterative {
		r.VerboseLog(0, "MIEKG-IN: iterative lookup for ", q.Name, " (", q.Type, ")")
		ctx, cancel := context.WithTimeout(context.Background(), r.iterativeTimeout)
		defer cancel()
		result, trace, status, err := r.iterativeLookup(ctx, q, nameServer, 1, ".", make(Trace, 0))
		r.VerboseLog(0, "MIEKG-OUT: iterative lookup for ", q.Name, " (", q.Type, "): status: ", status, " , err: ", err)
		if r.shouldTrace {
			return result, trace, status, err
		}
		return result, trace, status, err
	}
	res, status, try, err := r.retryingLookup(q, nameServer, true)
	if err != nil {
		return res, nil, status, fmt.Errorf("could not perform retrying lookup for name %v: %w", q.Name, err)

	}
	trace := make(Trace, 0)
	if r.shouldTrace {
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

func (r *Resolver) iterativeLookup(ctx context.Context, q Question, nameServer string,
	depth int, layer string, trace Trace) (Result, Trace, Status, error) {
	//
	if log.GetLevel() == log.DebugLevel {
		r.VerboseLog((depth), "iterative lookup for ", q.Name, " (", q.Type, ") against ", nameServer, " layer ", layer)
	}
	if depth > r.maxDepth {
		var result Result
		r.VerboseLog((depth + 1), "-> Max recursion depth reached")
		return result, trace, STATUS_ERROR, errors.New("Max recursion depth reached")
	}
	result, isCached, status, try, err := r.cachedRetryingLookup(ctx, q, nameServer, layer, depth)
	if r.shouldTrace && status == STATUS_NOERROR {
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
	if status != STATUS_NOERROR {
		r.VerboseLog((depth + 1), "-> error occurred during lookup")
		return result, trace, status, err
	} else if len(result.Answers) != 0 || result.Flags.Authoritative == true {
		if len(result.Answers) != 0 {
			r.VerboseLog((depth + 1), "-> answers found")
			if len(result.Authorities) > 0 {
				r.VerboseLog((depth + 2), "Dropping ", len(result.Authorities), " authority answers from output")
				result.Authorities = make([]interface{}, 0)
			}
			if len(result.Additional) > 0 {
				r.VerboseLog((depth + 2), "Dropping ", len(result.Additional), " additional answers from output")
				result.Additional = make([]interface{}, 0)
			}
		} else {
			r.VerboseLog((depth + 1), "-> authoritative response found")
		}
		return result, trace, status, err
	} else if len(result.Authorities) != 0 {
		r.VerboseLog((depth + 1), "-> Authority found, iterating")
		return r.iterateOnAuthorities(ctx, q, depth, result, layer, trace)
	} else {
		r.VerboseLog((depth + 1), "-> No Authority found, error")
		return result, trace, STATUS_ERROR, errors.New("NOERROR record without any answers or authorities")
	}
}

func (r *Resolver) cachedRetryingLookup(ctx context.Context, q Question, nameServer, layer string, depth int) (Result, IsCached, Status, int, error) {
	var isCached IsCached
	isCached = false
	r.VerboseLog(depth+1, "Cached retrying lookup. Name: ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)

	// Check if the timeout has been reached
	select {
	case <-ctx.Done():
		r.VerboseLog(depth+2, "ITERATIVE_TIMEOUT ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)
		var r Result
		return r, isCached, STATUS_ITER_TIMEOUT, 0, nil
	default:
		// Timeout not reached, continue
	}
	// First, we check the answer
	cachedResult, ok := r.cache.GetCachedResult(q, false, depth+1)
	if ok {
		isCached = true
		return cachedResult, isCached, STATUS_NOERROR, 0, nil
	}

	nameServerIP, _, err := net.SplitHostPort(nameServer)
	// Stop if we hit a nameserver we don't want to hit
	// TODO Phillip, fix this locking code to be safer, ie within a function and a defer unlock()
	// Could wrap the blacklist in a SafeBlacklist wrapper struct that handles the locking
	if r.blacklist != nil {
		r.blMu.Lock()
		if blacklisted, err := r.blacklist.IsBlacklisted(nameServerIP); err != nil {
			r.blMu.Unlock()
			var r Result
			return r, isCached, STATUS_ERROR, 0, err
		} else if blacklisted {
			r.blMu.Unlock()
			var r Result
			return r, isCached, STATUS_BLACKLIST, 0, nil
		}
		r.blMu.Unlock()
	}

	// Now, we check the authoritative:
	name := strings.ToLower(q.Name)
	layer = strings.ToLower(layer)
	authName, err := nextAuthority(name, layer)
	if err != nil {
		var r Result
		return r, isCached, STATUS_AUTHFAIL, 0, err
	}
	if name != layer && authName != layer {
		if authName == "" {
			var r Result
			return r, isCached, STATUS_AUTHFAIL, 0, nil
		}
		var qAuth Question
		qAuth.Name = authName
		qAuth.Type = dns.TypeNS
		qAuth.Class = dns.ClassINET

		if cachedResult, ok = r.cache.GetCachedResult(qAuth, true, depth+2); ok {
			isCached = true
			return cachedResult, isCached, STATUS_NOERROR, 0, nil
		}
	}

	// Alright, we're not sure what to do, go to the wire.
	result, status, try, err := r.retryingLookup(q, nameServer, false)

	r.cache.CacheUpdate(layer, result, depth+2)
	return result, isCached, status, try, err
}

// retryingLookup wraps around wireLookup to perform a DNS lookup with retries
// Returns the result, status, number of tries, and error
func (r *Resolver) retryingLookup(q Question, nameServer string, recursive bool) (Result, Status, int, error) {
	r.VerboseLog(1, "****WIRE LOOKUP*** ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)

	var origTimeout time.Duration
	if r.udpClient != nil {
		origTimeout = r.udpClient.Timeout
	} else {
		origTimeout = r.tcpClient.Timeout
	}
	// TODO: it feels like bad practice to change the timeout value of the client without user input, should return an error/log msg and exit
	// Leaving as a separate task so as not to refactor AND change functionality
	defer func() {
		// set timeout values back to original
		if r.udpClient != nil {
			r.udpClient.Timeout = origTimeout
		}
		if r.tcpClient != nil {
			r.tcpClient.Timeout = origTimeout
		}
	}()

	for i := 0; i <= r.retries; i++ {
		result, status, err := wireLookup(r.udpClient, r.tcpClient, r.conn, q, nameServer, recursive, r.ednsOptions, r.dnsSecEnabled, r.checkingDisabled)
		if (status != STATUS_TIMEOUT && status != STATUS_TEMPORARY) || i == r.retries {
			return result, status, (i + 1), err
		}
		if r.udpClient != nil {
			r.udpClient.Timeout = 2 * r.udpClient.Timeout
		}
		if r.tcpClient != nil {
			r.tcpClient.Timeout = 2 * r.tcpClient.Timeout
		}
	}
	return Result{}, "", 0, errors.New("retry loop didn't exit properly")
}

// wireLookup performs a DNS lookup on-the-wire with the given parameters
// Attempts a UDP lookup first, then falls back to TCP if necessary (if the UDP response encounters an error or is truncated)
func wireLookup(udp *dns.Client, tcp *dns.Client, conn *dns.Conn, q Question, nameServer string, recursive bool, ednsOptions []dns.EDNS0, dnssec bool, checkingDisabled bool) (Result, Status, error) {
	res := Result{Answers: []interface{}{}, Authorities: []interface{}{}, Additional: []interface{}{}}
	res.Resolver = nameServer

	m := new(dns.Msg)
	m.SetQuestion(dotName(q.Name), q.Type)
	m.Question[0].Qclass = q.Class
	m.RecursionDesired = recursive
	m.CheckingDisabled = checkingDisabled

	m.SetEdns0(1232, dnssec)
	if ednsOpt := m.IsEdns0(); ednsOpt != nil {
		ednsOpt.Option = append(ednsOpt.Option, ednsOptions...)
	}

	var r *dns.Msg
	var err error
	if udp != nil {
		res.Protocol = "udp"
		if conn != nil {
			dst, _ := net.ResolveUDPAddr("udp", nameServer)
			r, _, err = udp.ExchangeWithConnTo(m, conn, dst)
		} else {
			r, _, err = udp.Exchange(m, nameServer)
		}
		// if record comes back truncated, but we have a TCP connection, try again with that
		if r != nil && (r.Truncated || r.Rcode == dns.RcodeBadTrunc) {
			if tcp != nil {
				return wireLookup(nil, tcp, conn, q, nameServer, recursive, ednsOptions, dnssec, checkingDisabled)
			} else {
				return res, STATUS_TRUNCATED, err
			}
		}
	} else {
		res.Protocol = "tcp"
		r, _, err = tcp.Exchange(m, nameServer)
	}
	if err != nil || r == nil {
		if nerr, ok := err.(net.Error); ok {
			if nerr.Timeout() {
				return res, STATUS_TIMEOUT, nil
			} else if nerr.Temporary() {
				return res, STATUS_TEMPORARY, err
			}
		}
		return res, STATUS_ERROR, err
	}

	if r.Rcode != dns.RcodeSuccess {
		for _, ans := range r.Extra {
			inner := ParseAnswer(ans)
			if inner != nil {
				res.Additional = append(res.Additional, inner)
			}
		}
		return res, TranslateDNSErrorCode(r.Rcode), nil
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
	return res, STATUS_NOERROR, nil
}

func (r *Resolver) iterateOnAuthorities(ctx context.Context, q Question, depth int, result Result, layer string, trace Trace) (Result, Trace, Status, error) {
	if len(result.Authorities) == 0 {
		var r Result
		return r, trace, STATUS_NOAUTH, nil
	}
	for i, elem := range result.Authorities {
		r.VerboseLog(depth+1, "Trying Authority: ", elem)
		ns, ns_status, layer, trace := r.extractAuthority(ctx, elem, layer, depth, result, trace)
		r.VerboseLog((depth + 1), "Output from extract authorities: ", ns)
		if ns_status == STATUS_ITER_TIMEOUT {
			r.VerboseLog((depth + 2), "--> Hit iterative timeout: ")
			var r Result
			return r, trace, STATUS_ITER_TIMEOUT, nil
		}
		if ns_status != STATUS_NOERROR {
			var err error
			new_status, err := handleStatus(&ns_status, err)
			// default case we continue
			if new_status == nil && err == nil {
				if i+1 == len(result.Authorities) {
					r.VerboseLog((depth + 2), "--> Auth find Failed. Unknown error. No more authorities to try, terminating: ", ns_status)
					var r Result
					return r, trace, ns_status, err
				} else {
					r.VerboseLog((depth + 2), "--> Auth find Failed. Unknown error. Continue: ", ns_status)
					continue
				}
			} else {
				// otherwise we hit a status we know
				var localResult Result
				if i+1 == len(result.Authorities) {
					// We don't allow the continue fall through in order to report the last auth falure code, not STATUS_EROR
					r.VerboseLog((depth + 2), "--> Final auth find non-success. Last auth. Terminating: ", ns_status)
					return localResult, trace, *new_status, err
				} else {
					r.VerboseLog((depth + 2), "--> Auth find non-success. Trying next: ", ns_status)
					continue
				}
			}
		}
		iterateResult, trace, status, err := r.iterativeLookup(ctx, q, ns, depth+1, layer, trace)
		if isStatusAnswer(status) {
			r.VerboseLog((depth + 1), "--> Auth Resolution success: ", status)
			return iterateResult, trace, status, err
		} else if i+1 < len(result.Authorities) {
			r.VerboseLog((depth + 2), "--> Auth resolution of ", ns, " Failed: ", status, ". Will try next authority")
			continue
		} else {
			// We don't allow the continue fall through in order to report the last auth falure code, not STATUS_EROR
			r.VerboseLog((depth + 2), "--> Iterative resolution of ", q.Name, " at ", ns, " Failed. Last auth. Terminating: ", status)
			return iterateResult, trace, status, err
		}
	}
	panic("should not be able to reach here")
}

func (r *Resolver) extractAuthority(ctx context.Context, authority interface{}, layer string, depth int, result Result, trace Trace) (string, Status, string, Trace) {
	// Is it an answer
	ans, ok := authority.(Answer)
	if !ok {
		return "", STATUS_FORMERR, layer, trace
	}

	// Is the layering correct
	ok, layer = nameIsBeneath(ans.Name, layer)
	if !ok {
		return "", STATUS_AUTHFAIL, layer, trace
	}

	server := strings.TrimSuffix(ans.Answer, ".")

	// Short circuit a lookup from the glue
	// Normally this would be handled by caching, but we want to support following glue
	// that would normally be cache poison. Because it's "ok" and quite common
	res, status := checkGlue(server, depth, result)
	if status != STATUS_NOERROR {
		// Fall through to normal query
		var q Question
		q.Name = server
		q.Type = dns.TypeA
		q.Class = dns.ClassINET
		res, trace, status, _ = r.iterativeLookup(ctx, q, r.randomNameServer(), depth+1, ".", trace)
	}
	if status == STATUS_ITER_TIMEOUT {
		return "", status, "", trace
	}
	if status == STATUS_NOERROR {
		// XXX we don't actually check the question here
		for _, inner_a := range res.Answers {
			inner_ans, ok := inner_a.(Answer)
			if !ok {
				continue
			}
			if inner_ans.Type == "A" {
				server := strings.TrimSuffix(inner_ans.Answer, ".") + ":53"
				return server, STATUS_NOERROR, layer, trace
			}
		}
	}
	return "", STATUS_SERVFAIL, layer, trace
}
