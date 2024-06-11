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
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/internal/util"
)

// GetDNSServers returns a list of DNS servers from a file, or an error if one occurs
func GetDNSServers(path string) ([]string, error) {
	c, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return []string{}, fmt.Errorf("error reading DNS config file: %w", err)
	}
	servers := make([]string, 0, len(c.Servers))
	for _, s := range c.Servers {
		if s[0:1] != "[" && strings.Contains(s, ":") {
			s = "[" + s + "]"
		}
		full := strings.Join([]string{s, c.Port}, ":")
		servers = append(servers, full)
	}
	return servers, nil
}

// Lookup client interface for help in mocking
type Lookuper interface {
	DoSingleDstServerLookup(r *Resolver, q Question, nameServer string, isIterative bool) (*SingleQueryResult, Trace, Status, error)
}

type LookupClient struct{}

func (lc LookupClient) DoSingleDstServerLookup(r *Resolver, q Question, nameServer string, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	// Check that nameserver isn't blacklisted
	nameServerIP, _, err := net.SplitHostPort(nameServer)
	if err != nil {
		return nil, nil, StatusError, fmt.Errorf("could not split nameserver %s: %w", nameServer, err)
	}
	// Stop if we hit a nameserver we don't want to hit
	if r.blacklist != nil {
		if blacklisted, err := r.blacklist.IsBlacklisted(nameServerIP); err != nil {
			var r SingleQueryResult
			return &r, Trace{}, StatusError, fmt.Errorf("could not check blacklist for nameserver %s: %w", nameServer, err)
		} else if blacklisted {
			var r SingleQueryResult
			return &r, Trace{}, StatusBlacklist, nil
		}
	}
	return r.doSingleDstServerLookup(q, nameServer, isIterative)
}

func (r *Resolver) doSingleDstServerLookup(q Question, nameServer string, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	if nameServer == "" {
		return nil, nil, StatusIllegalInput, errors.New("no nameserver specified")
	}

	if q.Type == dns.TypePTR {
		var err error
		var qname string
		qname, err = dns.ReverseAddr(q.Name)
		// might be an actual DNS name instead of an IP address
		// if that looks likely, use it as is
		if err != nil && !util.IsStringValidDomainName(q.Name) {
			return nil, nil, StatusIllegalInput, err
			// q.Name is a valid domain name, we can continue
		} else {
			// remove trailing "." added by dns.ReverseAddr
			q.Name = qname[:len(qname)-1]
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	if isIterative {
		r.verboseLog(0, "MIEKG-IN: iterative lookup for ", q.Name, " (", q.Type, ")")
		result, trace, status, err := r.iterativeLookup(ctx, q, nameServer, 1, ".", make(Trace, 0))
		r.verboseLog(0, "MIEKG-OUT: iterative lookup for ", q.Name, " (", q.Type, "): status: ", status, " , err: ", err)
		return &result, trace, status, err
	}
	res, status, try, err := r.retryingLookup(ctx, q, nameServer, true)
	if err != nil {
		return &res, nil, status, fmt.Errorf("could not perform retrying lookup for name %v: %w", q.Name, err)
	}
	var t TraceStep
	t.Result = res
	t.DNSType = q.Type
	t.DNSClass = q.Class
	t.Name = q.Name
	t.NameServer = nameServer
	t.Layer = q.Name
	t.Depth = 1
	t.Cached = false
	t.Try = try
	trace := Trace{t}
	return &res, trace, status, err
}

// TODO - This is incomplete. We only lookup all nameservers for the initial name server lookup, then just send the DNS query to this set.
// If we want to iteratively lookup all nameservers at each level of the query, we need to fix this.
// Issue - https://github.com/zmap/zdns/issues/362
func (r *Resolver) LookupAllNameservers(q *Question, nameServer string) (*CombinedResults, Trace, Status, error) {
	var retv CombinedResults
	var curServer string

	// Lookup both ipv4 and ipv6 addresses of nameservers.
	nsResults, nsTrace, nsStatus, nsError := r.DoNSLookup(q.Name, nameServer, false)

	// Terminate early if nameserver lookup also failed
	if nsStatus != StatusNoError {
		return nil, nsTrace, nsStatus, nsError
	}
	if nsResults == nil {
		return nil, nsTrace, nsStatus, errors.New("no results from nameserver lookup")
	}

	// fullTrace holds the complete trace including all lookups
	var fullTrace = Trace{}
	if nsTrace != nil {
		fullTrace = append(fullTrace, nsTrace...)
	}
	for _, nserver := range nsResults.Servers {
		// Use all the ipv4 and ipv6 addresses of each nameserver
		nameserver := nserver.Name
		ips := append(nserver.IPv4Addresses, nserver.IPv6Addresses...)
		for _, ip := range ips {
			curServer = net.JoinHostPort(ip, "53")
			res, trace, status, _ := r.ExternalLookup(q, curServer)

			fullTrace = append(fullTrace, trace...)
			extendedResult := ExtendedResult{
				Res:        *res,
				Status:     status,
				Nameserver: nameserver,
			}
			retv.Results = append(retv.Results, extendedResult)
		}
	}
	return &retv, fullTrace, StatusNoError, nil
}

func (r *Resolver) iterativeLookup(ctx context.Context, q Question, nameServer string,
	depth int, layer string, trace Trace) (SingleQueryResult, Trace, Status, error) {
	if log.GetLevel() == log.DebugLevel {
		r.verboseLog(depth, "iterative lookup for ", q.Name, " (", q.Type, ") against ", nameServer, " layer ", layer)
	}
	if depth > r.maxDepth {
		var result SingleQueryResult
		r.verboseLog(depth+1, "-> Max recursion depth reached")
		return result, trace, StatusError, errors.New("max recursion depth reached")
	}
	// create iteration context for this iteration step
	iterationStepCtx, cancel := context.WithTimeout(ctx, r.iterativeTimeout)
	defer cancel()
	result, isCached, status, try, err := r.cachedRetryingLookup(iterationStepCtx, q, nameServer, layer, depth)
	if status == StatusNoError {
		var t TraceStep
		t.Result = result
		t.DNSType = q.Type
		t.DNSClass = q.Class
		t.Name = q.Name
		t.NameServer = nameServer
		t.Layer = layer
		t.Depth = depth
		t.Cached = isCached
		t.Try = try
		trace = append(trace, t)
	}
	if status == StatusTimeout && util.HasCtxExpired(&iterationStepCtx) && !util.HasCtxExpired(&ctx) {
		// ctx's have a deadline of the minimum of their deadline and their parent's
		// retryingLookup doesn't disambiguate of whether the timeout was caused by the iteration timeout or the global timeout
		// we'll disambiguate here by checking if the iteration context has expired but the global context hasn't
		r.verboseLog(depth+2, "ITERATIVE_TIMEOUT ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)
		status = StatusIterTimeout
	}
	if status != StatusNoError {
		r.verboseLog((depth + 1), "-> error occurred during lookup")
		return result, trace, status, err
	} else if len(result.Answers) != 0 || result.Flags.Authoritative {
		if len(result.Answers) != 0 {
			r.verboseLog((depth + 1), "-> answers found")
			if len(result.Authorities) > 0 {
				r.verboseLog((depth + 2), "Dropping ", len(result.Authorities), " authority answers from output")
				result.Authorities = make([]interface{}, 0)
			}
			if len(result.Additional) > 0 {
				r.verboseLog((depth + 2), "Dropping ", len(result.Additional), " additional answers from output")
				result.Additional = make([]interface{}, 0)
			}
		} else {
			r.verboseLog((depth + 1), "-> authoritative response found")
		}
		return result, trace, status, err
	} else if len(result.Authorities) != 0 {
		r.verboseLog((depth + 1), "-> Authority found, iterating")
		return r.iterateOnAuthorities(ctx, q, depth, result, layer, trace)
	} else {
		r.verboseLog((depth + 1), "-> No Authority found, error")
		return result, trace, StatusError, errors.New("NOERROR record without any answers or authorities")
	}
}

func (r *Resolver) cachedRetryingLookup(ctx context.Context, q Question, nameServer, layer string, depth int) (SingleQueryResult, IsCached, Status, int, error) {
	var isCached IsCached
	isCached = false
	r.verboseLog(depth+1, "Cached retrying lookup. Name: ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)

	// First, we check the answer
	cachedResult, ok := r.cache.GetCachedResult(q, false, depth+1)
	if ok {
		isCached = true
		return cachedResult, isCached, StatusNoError, 0, nil
	}

	nameServerIP, _, err := net.SplitHostPort(nameServer)
	if err != nil {
		var r SingleQueryResult
		return r, isCached, StatusError, 0, errors.Wrapf(err, "could not split nameserver %s to get IP", nameServer)
	}
	// Stop if we hit a nameserver we don't want to hit
	if r.blacklist != nil {
		if blacklisted, isBlacklistedErr := r.blacklist.IsBlacklisted(nameServerIP); isBlacklistedErr != nil {
			var r SingleQueryResult
			return r, isCached, StatusError, 0, errors.Wrapf(isBlacklistedErr, "could not check blacklist for nameserver IP: %s", nameServerIP)
		} else if blacklisted {
			var r SingleQueryResult
			return r, isCached, StatusBlacklist, 0, nil
		}
	}

	// Now, we check the authoritative:
	name := strings.ToLower(q.Name)
	layer = strings.ToLower(layer)
	authName, err := nextAuthority(name, layer)
	if err != nil {
		var r SingleQueryResult
		return r, isCached, StatusAuthFail, 0, err
	}
	if name != layer && authName != layer {
		if authName == "" {
			var r SingleQueryResult
			return r, isCached, StatusAuthFail, 0, nil
		}
		var qAuth Question
		qAuth.Name = authName
		qAuth.Type = dns.TypeNS
		qAuth.Class = dns.ClassINET

		if cachedResult, ok = r.cache.GetCachedResult(qAuth, true, depth+2); ok {
			isCached = true
			return cachedResult, isCached, StatusNoError, 0, nil
		}
	}

	// Alright, we're not sure what to do, go to the wire.
	result, status, try, err := r.retryingLookup(ctx, q, nameServer, false)

	r.cache.CacheUpdate(layer, result, depth+2)
	return result, isCached, status, try, err
}

// retryingLookup wraps around wireLookup to perform a DNS lookup with retries
// Returns the result, status, number of tries, and error
func (r *Resolver) retryingLookup(ctx context.Context, q Question, nameServer string, recursive bool) (SingleQueryResult, Status, int, error) {
	r.verboseLog(1, "****WIRE LOOKUP*** ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)
	for i := 0; i <= r.retries; i++ {
		// check context before going into wireLookup
		if util.HasCtxExpired(&ctx) {
			var r SingleQueryResult
			return r, StatusTimeout, i + 1, nil
		}
		result, status, err := wireLookup(ctx, r.udpClient, r.tcpClient, r.conn, q, nameServer, recursive, r.ednsOptions, r.dnsSecEnabled, r.checkingDisabledBit)
		if status != StatusTimeout || i == r.retries {
			return result, status, i + 1, err
		}

	}
	return SingleQueryResult{}, "", 0, errors.New("retry loop didn't exit properly")
}

// wireLookup performs a DNS lookup on-the-wire with the given parameters
// Attempts a UDP lookup first, then falls back to TCP if necessary (if the UDP response encounters an error or is truncated)
func wireLookup(ctx context.Context, udp *dns.Client, tcp *dns.Client, conn *dns.Conn, q Question, nameServer string, recursive bool, ednsOptions []dns.EDNS0, dnssec bool, checkingDisabled bool) (SingleQueryResult, Status, error) {
	res := SingleQueryResult{Answers: []interface{}{}, Authorities: []interface{}{}, Additional: []interface{}{}}
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
			r, _, err = udp.ExchangeWithConnToContext(ctx, m, conn, dst)
		} else {
			r, _, err = udp.ExchangeContext(ctx, m, nameServer)
		}
		// if record comes back truncated, but we have a TCP connection, try again with that
		if r != nil && (r.Truncated || r.Rcode == dns.RcodeBadTrunc) {
			if tcp != nil {
				return wireLookup(ctx, nil, tcp, conn, q, nameServer, recursive, ednsOptions, dnssec, checkingDisabled)
			} else {
				return res, StatusTruncated, err
			}
		}
	} else {
		res.Protocol = "tcp"
		r, _, err = tcp.ExchangeContext(ctx, m, nameServer)
	}
	if err != nil || r == nil {
		if nerr, ok := err.(net.Error); ok {
			if nerr.Timeout() {
				return res, StatusTimeout, nil
			}
		}
		return res, StatusError, err
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
	return res, StatusNoError, nil
}

func (r *Resolver) iterateOnAuthorities(ctx context.Context, q Question, depth int, result SingleQueryResult, layer string, trace Trace) (SingleQueryResult, Trace, Status, error) {
	if len(result.Authorities) == 0 {
		var r SingleQueryResult
		return r, trace, StatusNoAuth, nil
	}
	for i, elem := range result.Authorities {
		r.verboseLog(depth+1, "Trying Authority: ", elem)
		ns, nsStatus, newLayer, newTrace := r.extractAuthority(ctx, elem, layer, depth, result, trace)
		r.verboseLog((depth + 1), "Output from extract authorities: ", ns)
		if nsStatus == StatusIterTimeout {
			r.verboseLog((depth + 2), "--> Hit iterative timeout: ")
			var r SingleQueryResult
			return r, newTrace, StatusIterTimeout, nil
		}
		if nsStatus != StatusNoError {
			var err error
			newStatus, err := handleStatus(&nsStatus, err)
			// default case we continue
			if newStatus == nil && err == nil {
				if i+1 == len(result.Authorities) {
					r.verboseLog((depth + 2), "--> Auth find Failed. Unknown error. No more authorities to try, terminating: ", nsStatus)
					var r SingleQueryResult
					return r, newTrace, nsStatus, err
				} else {
					r.verboseLog((depth + 2), "--> Auth find Failed. Unknown error. Continue: ", nsStatus)
					continue
				}
			} else {
				// otherwise we hit a status we know
				var localResult SingleQueryResult
				if i+1 == len(result.Authorities) {
					// We don't allow the continue fall through in order to report the last auth falure code, not STATUS_EROR
					r.verboseLog((depth + 2), "--> Final auth find non-success. Last auth. Terminating: ", nsStatus)
					return localResult, newTrace, *newStatus, err
				} else {
					r.verboseLog((depth + 2), "--> Auth find non-success. Trying next: ", nsStatus)
					continue
				}
			}
		}
		iterateResult, newTrace, status, err := r.iterativeLookup(ctx, q, ns, depth+1, newLayer, newTrace)
		if isStatusAnswer(status) {
			r.verboseLog((depth + 1), "--> Auth Resolution success: ", status)
			return iterateResult, newTrace, status, err
		} else if i+1 < len(result.Authorities) {
			r.verboseLog((depth + 2), "--> Auth resolution of ", ns, " Failed: ", status, ". Will try next authority")
			continue
		} else {
			// We don't allow the continue fall through in order to report the last auth falure code, not STATUS_EROR
			r.verboseLog((depth + 2), "--> Iterative resolution of ", q.Name, " at ", ns, " Failed. Last auth. Terminating: ", status)
			return iterateResult, newTrace, status, err
		}
	}
	panic("should not be able to reach here")
}

func (r *Resolver) extractAuthority(ctx context.Context, authority interface{}, layer string, depth int, result SingleQueryResult, trace Trace) (string, Status, string, Trace) {
	// Is it an answer
	ans, ok := authority.(Answer)
	if !ok {
		return "", StatusFormErr, layer, trace
	}

	// Is the layering correct
	ok, layer = nameIsBeneath(ans.Name, layer)
	if !ok {
		return "", StatusAuthFail, layer, trace
	}

	server := strings.TrimSuffix(ans.Answer, ".")

	// Short circuit a lookup from the glue
	// Normally this would be handled by caching, but we want to support following glue
	// that would normally be cache poison. Because it's "ok" and quite common
	res, status := checkGlue(server, result)
	if status != StatusNoError {
		// Fall through to normal query
		var q Question
		q.Name = server
		q.Type = dns.TypeA
		q.Class = dns.ClassINET
		res, trace, status, _ = r.iterativeLookup(ctx, q, r.randomRootNameServer(), depth+1, ".", trace)
	}
	if status == StatusIterTimeout {
		return "", status, "", trace
	}
	if status == StatusNoError {
		// XXX we don't actually check the question here
		for _, innerA := range res.Answers {
			innerAns, ok := innerA.(Answer)
			if !ok {
				continue
			}
			if innerAns.Type == "A" {
				server := strings.TrimSuffix(innerAns.Answer, ".") + ":53"
				return server, StatusNoError, layer, trace
			}
		}
	}
	return "", StatusServFail, layer, trace
}

// CheckTxtRecords common function for all modules based on search in TXT record
func CheckTxtRecords(res *SingleQueryResult, status Status, regex *regexp.Regexp, err error) (string, Status, error) {
	if status != StatusNoError {
		return "", status, err
	}
	resString, err := FindTxtRecord(res, regex)
	if err != nil {
		status = StatusNoRecord
	} else {
		status = StatusNoError
	}
	return resString, status, err
}

func FindTxtRecord(res *SingleQueryResult, regex *regexp.Regexp) (string, error) {

	for _, a := range res.Answers {
		ans, _ := a.(Answer)
		if regex == nil || regex.MatchString(ans.Answer) {
			return ans.Answer, nil
		}
	}
	return "", errors.New("no such TXT record found")
}
