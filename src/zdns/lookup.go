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
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/lib/output"

	"github.com/zmap/zdns/src/internal/util"
)

// GetDNSServers returns a list of IPv4, IPv6 DNS servers from a file, or an error if one occurs
func GetDNSServers(path string) (ipv4, ipv6 []string, err error) {
	c, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return []string{}, []string{}, fmt.Errorf("error reading DNS config file (%s): %w", path, err)
	}
	servers := make([]string, 0, len(c.Servers))
	for _, s := range c.Servers {
		if s[0:1] != "[" && strings.Contains(s, ":") {
			s = "[" + s + "]"
		}
		full := strings.Join([]string{s, c.Port}, ":")
		servers = append(servers, full)
	}
	ipv4 = make([]string, 0, len(servers))
	ipv6 = make([]string, 0, len(servers))
	for _, s := range servers {
		ip, _, err := util.SplitHostPort(s)
		if err != nil {
			return []string{}, []string{}, fmt.Errorf("could not parse IP address (%s) from file: %w", s, err)
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, s)
		} else if util.IsIPv6(&ip) {
			ipv6 = append(ipv6, s)
		} else {
			return []string{}, []string{}, fmt.Errorf("could not parse IP address (%s) from file: %s", s, path)
		}
	}
	return ipv4, ipv6, nil
}

// Lookup client interface for help in mocking
type Lookuper interface {
	DoSingleDstServerLookup(r *Resolver, q Question, nameServer *NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error)
}

type LookupClient struct{}

func (lc LookupClient) DoSingleDstServerLookup(r *Resolver, q Question, nameServer *NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	return r.doSingleDstServerLookup(q, nameServer, isIterative)
}

func (r *Resolver) doSingleDstServerLookup(q Question, nameServer *NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	var err error
	// nameserver is required
	if nameServer == nil {
		return nil, nil, StatusIllegalInput, errors.New("no nameserver specified")
	}

	// Stop if we hit a nameserver we don't want to hit
	if r.blacklist != nil {
		if blacklisted, blacklistedErr := r.blacklist.IsBlacklisted(nameServer.IP.String()); blacklistedErr != nil {
			var r SingleQueryResult
			return &r, Trace{}, StatusError, fmt.Errorf("could not check blacklist for nameserver %s: %w", nameServer, err)
		} else if blacklisted {
			var r SingleQueryResult
			return &r, Trace{}, StatusBlacklist, nil
		}
	}

	if q.Type == dns.TypePTR {
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
	if r.followCNAMEs {
		return r.followingLookup(ctx, q, nameServer, isIterative)
	}
	res, trace, status, err := r.lookup(ctx, q, nameServer, isIterative)
	if err != nil {
		return &res, nil, status, fmt.Errorf("could not perform retrying lookup for name %v: %w", q.Name, err)
	}
	return &res, trace, status, err
}

// lookup performs a DNS lookup for a given question and nameserver taking care of iterative and external lookups
func (r *Resolver) lookup(ctx context.Context, q Question, nameServer *NameServer, isIterative bool) (SingleQueryResult, Trace, Status, error) {
	var res SingleQueryResult
	var trace Trace
	var status Status
	var err error
	if util.HasCtxExpired(&ctx) {
		return res, trace, StatusTimeout, nil
	}
	if isIterative {
		r.verboseLog(1, "MIEKG-IN: following iterative lookup for ", q.Name, " (", q.Type, ")")
		res, trace, status, err = r.iterativeLookup(ctx, q, nameServer, 1, ".", trace)
		r.verboseLog(1, "MIEKG-OUT: following iterative lookup for ", q.Name, " (", q.Type, "): status: ", status, " , err: ", err)
	} else {
		tries := 0
		// external lookup
		r.verboseLog(1, "MIEKG-IN: following external lookup for ", q.Name, " (", q.Type, ")")
		res, status, tries, err = r.retryingLookup(ctx, q, nameServer, true)
		r.verboseLog(1, "MIEKG-OUT: following external lookup for ", q.Name, " (", q.Type, ") with ", tries, " attempts: status: ", status, " , err: ", err)
		var t TraceStep
		t.Result = res
		t.DNSType = q.Type
		t.DNSClass = q.Class
		t.Name = q.Name
		t.NameServer = nameServer.String()
		t.Layer = q.Name
		t.Depth = 1
		t.Cached = false
		t.Try = tries
		trace = Trace{t}
	}
	return res, trace, status, err
}

// followingLoopup follows CNAMEs and DNAMEs in a DNS lookup for either an iterative or external lookup
// If an error occurs during the lookup, the last good result/status is returned along with the error and a full trace
// If an error occurs on the first lookup, the bad result/status is returned along with the error and a full trace
func (r *Resolver) followingLookup(ctx context.Context, q Question, nameServer *NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	var res SingleQueryResult
	var trace Trace
	var status Status

	candidateSet := make(map[string][]Answer)
	cnameSet := make(map[string][]Answer)
	garbage := make(map[string][]Answer)
	allAnswerSet := make([]interface{}, 0)
	dnameSet := make(map[string][]Answer)

	originalName := q.Name // in case this is a CNAME, this keeps track of the original name while we change the question
	currName := q.Name     // this is the current name we are looking up
	r.verboseLog(0, "MIEKG-IN: starting a C/DNAME following lookup for ", originalName, " (", q.Type, ")")
	for i := 0; i < r.maxDepth; i++ {
		q.Name = currName // update the question with the current name, this allows following CNAMEs
		iterRes, iterTrace, iterStatus, lookupErr := r.lookup(ctx, q, nameServer, isIterative)
		// append iterTrace to the global trace so we can return full trace
		if iterTrace != nil {
			trace = append(trace, iterTrace...)
		}
		if iterStatus != StatusNoError || lookupErr != nil {
			if i == 0 {
				// only have 1 result to return
				return &iterRes, trace, iterStatus, lookupErr
			}
			// return the last good result/status if we're traversing CNAMEs
			return &res, trace, status, errors.Wrapf(lookupErr, "iterative lookup failed for name %v at depth %d", q.Name, i)
		}
		// update the result with the latest iteration since there's no error
		// We'll return the latest good result if we're traversing CNAMEs
		res = iterRes
		status = iterStatus

		if q.Type == dns.TypeMX {
			// MX records have a special lookup format, so we won't attempt to follow CNAMES here
			return &res, trace, status, nil
		}

		// populateResults will parse the Answers and update the candidateSet, cnameSet, and garbage caching maps
		populateResults(res.Answers, q.Type, candidateSet, cnameSet, dnameSet, garbage)
		for _, ans := range res.Answers {
			answer, ok := ans.(Answer)
			if !ok {
				continue
			}
			allAnswerSet = append(allAnswerSet, answer)
		}

		if isLookupComplete(originalName, candidateSet, cnameSet, dnameSet) {
			return &SingleQueryResult{
				Answers:            allAnswerSet,
				Additional:         res.Additional,
				Protocol:           res.Protocol,
				Resolver:           res.Resolver,
				Flags:              res.Flags,
				TLSServerHandshake: res.TLSServerHandshake,
			}, trace, StatusNoError, nil
		}

		if candidates, ok := cnameSet[currName]; ok && len(candidates) > 0 {
			// we have a CNAME and need to further recurse to find IPs
			currName = strings.ToLower(strings.TrimSuffix(candidates[0].Answer, "."))
			continue
		} else if candidates, ok = garbage[currName]; ok && len(candidates) > 0 {
			return nil, trace, StatusError, errors.New("unexpected record type received")
		}
		// for each key in DNAMESet, check if the current name has a substring that matches the key.
		// if so, replace that substring
		foundDNameMatch := false
		for k, v := range dnameSet {
			if strings.Contains(currName, k) {
				currName = strings.Replace(currName, k, strings.TrimSuffix(v[0].Answer, "."), 1)
				foundDNameMatch = true
				break
			}
		}
		if foundDNameMatch {
			continue
		} else {
			// we have no data whatsoever about this name. return an empty recordset to the user
			return &iterRes, trace, StatusNoError, nil
		}
	}
	log.Debugf("MIEKG-IN: max recursion depth reached for %s lookup", originalName)
	return nil, trace, StatusServFail, errors.New("max recursion depth reached")
}

// isLookupComplete checks if there's a valid answer using the originalName and following CNAMES
// An illustrative example of why this fn is needed, say we're doing an A lookup for foo.com. There exists a CNAME from
// foo.com -> bar.com. Therefore, the candidate set will contain an A record for bar.com, and we need to ensure there's
// a complete path from foo.com -> bar.com -> bar.com's A record following the maps. This fn checks that path.
func isLookupComplete(originalName string, candidateSet map[string][]Answer, cNameSet map[string][]Answer, dNameSet map[string][]Answer) bool {
	maxDepth := len(cNameSet) + len(dNameSet) + 1
	currName := originalName
	for i := 0; i < maxDepth; i++ {
		if currName == originalName && i != 0 {
			// we're in a loop
			return true
		}
		if candidates, ok := candidateSet[currName]; ok && len(candidates) > 0 {
			return true
		}
		if candidates, ok := cNameSet[currName]; ok && len(candidates) > 0 {
			// CNAME found, update currName
			currName = strings.ToLower(strings.TrimSuffix(candidates[0].Answer, "."))
			continue
		}
		// for each key in DNAMESet, check if the current name has a substring that matches the key.
		// if so, replace that substring
		for k, v := range dNameSet {
			if strings.Contains(currName, k) {
				currName = strings.Replace(currName, k, strings.TrimSuffix(v[0].Answer, "."), 1)
				break
			}
		}
	}
	return false
}

// TODO - This is incomplete. We only lookup all nameservers for the initial name server lookup, then just send the DNS query to this set.
// If we want to iteratively lookup all nameservers at each level of the query, we need to fix this.
// Issue - https://github.com/zmap/zdns/issues/362
func (r *Resolver) LookupAllNameservers(q *Question, nameServer *NameServer) (*CombinedResults, Trace, Status, error) {
	var retv CombinedResults
	var curServer string

	// Lookup both ipv4 and ipv6 addresses of nameservers.
	nsResults, nsTrace, nsStatus, nsError := r.DoNSLookup(q.Name, nameServer, false, true, true)

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
		ips := util.Concat(nserver.IPv4Addresses, nserver.IPv6Addresses)
		for _, ip := range ips {
			// construct the nameserver
			res, trace, status, err := r.ExternalLookup(q, &NameServer{
				IP:   net.ParseIP(ip),
				Port: DefaultDNSPort,
			})
			if err != nil {
				// log and move on
				log.Errorf("lookup for domain %s to nameserver %s failed with error %s. Continueing to next nameserver", q.Name, curServer, err)
				continue
			}

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

func (r *Resolver) iterativeLookup(ctx context.Context, q Question, nameServer *NameServer,
	depth int, layer string, trace Trace) (SingleQueryResult, Trace, Status, error) {
	if log.GetLevel() == log.DebugLevel {
		r.verboseLog(depth, "iterative lookup for ", q.Name, " (", q.Type, ") against ", nameServer, " layer ", layer)
	}
	if isValid, reason := nameServer.IsValid(); !isValid {
		return SingleQueryResult{}, trace, StatusIllegalInput, fmt.Errorf("invalid nameserver (%s): %s", nameServer.String(), reason)
	}
	if depth > r.maxDepth {
		var result SingleQueryResult
		r.verboseLog(depth+1, "-> Max recursion depth reached")
		return result, trace, StatusError, errors.New("max recursion depth reached")
	}
	// check that context hasn't expired
	if util.HasCtxExpired(&ctx) {
		var result SingleQueryResult
		r.verboseLog(depth+1, "-> Context expired")
		return result, trace, StatusTimeout, nil
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
		t.NameServer = nameServer.String()
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
	if status != StatusNoError || err != nil {
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

func (r *Resolver) cachedRetryingLookup(ctx context.Context, q Question, nameServer *NameServer, layer string, depth int) (SingleQueryResult, IsCached, Status, int, error) {
	var isCached IsCached
	isCached = false
	r.verboseLog(depth+1, "Cached retrying lookup. Name: ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)

	// First, we check the answer
	cachedResult, ok := r.cache.GetCachedResult(q, false, depth+1)
	if ok {
		isCached = true
		return cachedResult, isCached, StatusNoError, 0, nil
	}

	// Stop if we hit a nameserver we don't want to hit
	if r.blacklist != nil {
		if blacklisted, isBlacklistedErr := r.blacklist.IsBlacklisted(nameServer.IP.String()); isBlacklistedErr != nil {
			var r SingleQueryResult
			return r, isCached, StatusError, 0, errors.Wrapf(isBlacklistedErr, "could not check blacklist for nameserver IP: %s", nameServer.IP.String())
		} else if blacklisted {
			var r SingleQueryResult
			return r, isCached, StatusBlacklist, 0, nil
		}
	}

	// Alright, we're not sure what to do, go to the wire.
	result, status, try, err := r.retryingLookup(ctx, q, nameServer, false)

	r.cache.CacheUpdate(layer, result, depth+2)
	return result, isCached, status, try, err
}

// retryingLookup wraps around wireLookup to perform a DNS lookup with retries
// Returns the result, status, number of tries, and error
func (r *Resolver) retryingLookup(ctx context.Context, q Question, nameServer *NameServer, recursive bool) (SingleQueryResult, Status, int, error) {
	// nameserver is required
	if nameServer == nil {
		return SingleQueryResult{}, StatusIllegalInput, 0, errors.New("no nameserver specified")
	}
	connInfo, err := r.getConnectionInfo(nameServer)
	if err != nil {
		return SingleQueryResult{}, StatusError, 0, fmt.Errorf("could not get a connection info to query nameserver %s: %v", nameServer, err)
	}
	// check that our connection info is valid
	if connInfo == nil {
		return SingleQueryResult{}, StatusError, 0, fmt.Errorf("no connection info for nameserver: %s", nameServer)
	}
	r.verboseLog(1, "****WIRE LOOKUP*** ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)
	for i := 0; i <= r.retries; i++ {
		// check context before going into wireLookup
		if util.HasCtxExpired(&ctx) {
			return SingleQueryResult{}, StatusTimeout, i + 1, nil
		}
		var result SingleQueryResult
		var status Status
		if r.dnsOverHTTPSEnabled {
			result, status, err = doDoHLookup(ctx, connInfo.httpsClient, q, nameServer, recursive, r.ednsOptions, r.dnsSecEnabled, r.checkingDisabledBit)
		} else if r.dnsOverTLSEnabled {
			result, status, err = doDoTLookup(ctx, connInfo, q, nameServer, recursive, r.ednsOptions, r.dnsSecEnabled, r.checkingDisabledBit)
		} else {
			result, status, err = wireLookup(ctx, connInfo.udpClient, connInfo.tcpClient, connInfo.conn, q, nameServer, r.ednsOptions, recursive, r.dnsSecEnabled, r.checkingDisabledBit)
		}
		if status != StatusTimeout || i == r.retries {
			return result, status, i + 1, err
		}

	}
	return SingleQueryResult{}, "", 0, errors.New("retry loop didn't exit properly")
}

func doDoTLookup(ctx context.Context, connInfo *ConnectionInfo, q Question, nameServer *NameServer, recursive bool, ednsOptions []dns.EDNS0, dnssec bool, checkingDisabled bool) (SingleQueryResult, Status, error) {
	m := new(dns.Msg)
	m.SetQuestion(dotName(q.Name), q.Type)
	m.Question[0].Qclass = q.Class
	m.RecursionDesired = recursive
	m.CheckingDisabled = checkingDisabled
	m.Id = 12345

	m.SetEdns0(1232, dnssec)
	if ednsOpt := m.IsEdns0(); ednsOpt != nil {
		ednsOpt.Option = append(ednsOpt.Option, ednsOptions...)
	}

	// if tlsConn is nil or if this is a new nameserver, create a new connection
	var isConnNew bool
	if connInfo.tlsConn != nil {
		newRemoteAddr := net.TCPAddr{IP: nameServer.IP, Port: int(nameServer.Port)}
		prevRemoteAddr := connInfo.tlsConn.Conn.RemoteAddr().String()
		if prevRemoteAddr != newRemoteAddr.String() {
			isConnNew = true
		}
	}
	if connInfo.tlsConn == nil || isConnNew {
		// new connection
		// Custom dialer with local address binding
		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP:   connInfo.localAddr,
				Port: 0,
			},
		}
		tcpConn, err := dialer.DialContext(ctx, "tcp", nameServer.String())
		if err != nil {
			return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not connect to server")
		}
		// Now wrap the connection with TLS
		// TODO - implement server cert validation
		tlsConn := tls.Client(tcpConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		err = tlsConn.Handshake()
		if err != nil {
			err := tlsConn.Close()
			if err != nil {
				log.Errorf("error closing TLS connection: %v", err)
			}
			return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not perform TLS handshake")
		}
		connInfo.tlsHandshake = tlsConn.GetHandshakeLog()
		connInfo.tlsConn = &dns.Conn{Conn: tlsConn}
	}
	err := connInfo.tlsConn.WriteMsg(m)
	if err != nil {
		return SingleQueryResult{}, "", errors.Wrap(err, "could not write query over DoT to server")
	}
	responseMsg, err := connInfo.tlsConn.ReadMsg()
	if err != nil {
		return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not unpack DNS message from DoT server")
	}
	res := SingleQueryResult{
		Resolver:    connInfo.tlsConn.Conn.RemoteAddr().String(),
		Protocol:    "DoT",
		Answers:     []interface{}{},
		Authorities: []interface{}{},
		Additional:  []interface{}{},
	}
	// if we have it, add the TLS handshake info
	if connInfo.tlsHandshake != nil {
		processor := output.Processor{Verbose: false}
		strippedOutput, stripErr := processor.Process(connInfo.tlsHandshake)
		if stripErr != nil {
			log.Warnf("Error stripping TLS log: %v", stripErr)
		} else {
			res.TLSServerHandshake = strippedOutput
		}
	}
	return constructSingleQueryResultFromDNSMsg(res, responseMsg)
}

func doDoHLookup(ctx context.Context, httpClient *http.Client, q Question, nameServer *NameServer, recursive bool, ednsOptions []dns.EDNS0, dnssec bool, checkingDisabled bool) (SingleQueryResult, Status, error) {
	m := new(dns.Msg)
	m.SetQuestion(dotName(q.Name), q.Type)
	m.Question[0].Qclass = q.Class
	m.RecursionDesired = recursive
	m.CheckingDisabled = checkingDisabled

	m.SetEdns0(1232, dnssec)
	if ednsOpt := m.IsEdns0(); ednsOpt != nil {
		ednsOpt.Option = append(ednsOpt.Option, ednsOptions...)
	}
	bytes, err := m.Pack()
	if err != nil {
		return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not pack DNS message")
	}
	if strings.Contains(nameServer.DomainName, "http://") {
		return SingleQueryResult{}, StatusError, errors.New("DoH name server must use HTTPS")
	}
	httpsDomain := nameServer.DomainName
	if !strings.HasPrefix(httpsDomain, "https://") {
		httpsDomain = "https://" + httpsDomain
	}
	if !strings.HasSuffix(httpsDomain, "/dns-query") {
		httpsDomain += "/dns-query"
	}
	req, err := http.NewRequest("POST", httpsDomain, strings.NewReader(string(bytes)))
	if err != nil {
		return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not create HTTP request")
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req = req.WithContext(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not perform HTTP request")
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Errorf("error closing DoH response body: %v", err)
		}
	}(resp.Body)
	bytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not read HTTP response")
	}

	r := new(dns.Msg)
	err = r.Unpack(bytes)
	if err != nil {
		return SingleQueryResult{}, StatusError, errors.Wrap(err, "could not unpack DNS message")
	}
	res := SingleQueryResult{
		Resolver:    nameServer.DomainName,
		Protocol:    "DoH",
		Answers:     []interface{}{},
		Authorities: []interface{}{},
		Additional:  []interface{}{},
	}
	if resp.Request != nil && resp.Request.TLSLog != nil {
		processor := output.Processor{Verbose: false}
		strippedOutput, stripErr := processor.Process(resp.Request.TLSLog)
		if stripErr != nil {
			log.Warnf("Error stripping TLS log: %v", stripErr)
		} else {
			res.TLSServerHandshake = strippedOutput
		}
	}
	return constructSingleQueryResultFromDNSMsg(res, r)
}

// wireLookup performs a DNS lookup on-the-wire with the given parameters
// Attempts a UDP lookup first, then falls back to TCP if necessary (if the UDP response encounters an error or is truncated)
func wireLookup(ctx context.Context, udp *dns.Client, tcp *dns.Client, conn *dns.Conn, q Question, nameServer *NameServer, ednsOptions []dns.EDNS0, recursive, dnssec, checkingDisabled bool) (SingleQueryResult, Status, error) {
	res := SingleQueryResult{Answers: []interface{}{}, Authorities: []interface{}{}, Additional: []interface{}{}}
	res.Resolver = nameServer.String()

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
			dst, _ := net.ResolveUDPAddr("udp", nameServer.String())
			r, _, err = udp.ExchangeWithConnToContext(ctx, m, conn, dst)
		} else {
			r, _, err = udp.ExchangeContext(ctx, m, nameServer.String())
		}
		// if record comes back truncated, but we have a TCP connection, try again with that
		if r != nil && (r.Truncated || r.Rcode == dns.RcodeBadTrunc) {
			if tcp != nil {
				return wireLookup(ctx, nil, tcp, conn, q, nameServer, ednsOptions, recursive, dnssec, checkingDisabled)
			} else {
				return res, StatusTruncated, err
			}
		}
	} else {
		res.Protocol = "tcp"
		r, _, err = tcp.ExchangeContext(ctx, m, nameServer.String())
	}
	if err != nil || r == nil {
		if nerr, ok := err.(net.Error); ok {
			if nerr.Timeout() {
				return res, StatusTimeout, nil
			}
		}
		return res, StatusError, err
	}

	return constructSingleQueryResultFromDNSMsg(res, r)
}

// fills out all the fields in a SingleQueryResult from a dns.Msg directly.
func constructSingleQueryResultFromDNSMsg(res SingleQueryResult, r *dns.Msg) (SingleQueryResult, Status, error) {
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
		ns, nsStatus, newLayer, newTrace := r.extractAuthority(ctx, elem, layer, depth, &result, trace)
		r.verboseLog((depth + 1), "Output from extract authorities: ", ns.String())
		if nsStatus == StatusIterTimeout {
			r.verboseLog((depth + 2), "--> Hit iterative timeout: ")
			var r SingleQueryResult
			return r, newTrace, StatusIterTimeout, nil
		}
		if nsStatus != StatusNoError {
			var err error
			newStatus, err := handleStatus(nsStatus, err)
			if err == nil {
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
					return localResult, newTrace, newStatus, err
				} else {
					r.verboseLog((depth + 2), "--> Auth find non-success. Trying next: ", nsStatus)
					continue
				}
			}
		}
		iterateResult, newTrace, status, err := r.iterativeLookup(ctx, q, ns, depth+1, newLayer, newTrace)
		if status == StatusNoNeededGlue {
			r.verboseLog((depth + 2), "--> Auth resolution of ", ns, " was unsuccessful. No glue to follow", status)
			return iterateResult, newTrace, status, err
		} else if isStatusAnswer(status) {
			r.verboseLog((depth + 1), "--> Auth Resolution of ", ns, " success: ", status)
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

func (r *Resolver) extractAuthority(ctx context.Context, authority interface{}, layer string, depth int, result *SingleQueryResult, trace Trace) (*NameServer, Status, string, Trace) {
	// Is it an answer
	ans, ok := authority.(Answer)
	if !ok {
		return nil, StatusFormErr, layer, trace
	}

	// Is the layering correct
	ok, layer = nameIsBeneath(ans.Name, layer)
	if !ok {
		return nil, StatusAuthFail, layer, trace
	}

	server := strings.TrimSuffix(ans.Answer, ".")

	// Short circuit a lookup from the glue
	// Normally this would be handled by caching, but we want to support following glue
	// that would normally be cache poison. Because it's "ok" and quite common
	res, status := checkGlue(server, *result, r.ipVersionMode, r.iterationIPPreference)
	if status != StatusNoError {
		if ok, _ = nameIsBeneath(server, layer); ok {
			// The domain we're searching for is beneath us but no glue was returned. We cannot proceed without this Glue.
			// Terminating
			return nil, StatusNoNeededGlue, "", trace
		}
		// Fall through to normal query
		var q Question
		q.Name = server
		q.Class = dns.ClassINET
		if r.ipVersionMode != IPv4Only && r.iterationIPPreference == PreferIPv6 {
			q.Type = dns.TypeAAAA
		} else {
			q.Type = dns.TypeA
		}
		res, trace, status, _ = r.iterativeLookup(ctx, q, r.randomRootNameServer(), depth+1, ".", trace)
	}
	if status == StatusIterTimeout || status == StatusNoNeededGlue {
		return nil, status, "", trace
	}
	if status == StatusNoError {
		// XXX we don't actually check the question here
		for _, innerA := range res.Answers {
			innerAns, ok := innerA.(Answer)
			if !ok {
				continue
			}
			aRecordAndIPv4Ok := r.ipVersionMode != IPv6Only && innerAns.Type == "A"
			aaaaRecordAndIPv6Ok := r.ipVersionMode != IPv4Only && innerAns.Type == "AAAA"
			if aRecordAndIPv4Ok || aaaaRecordAndIPv6Ok {
				ns := new(NameServer)
				parsedIPString := strings.TrimSuffix(innerAns.Answer, ".")
				ns.IP = net.ParseIP(parsedIPString)
				ns.PopulateDefaultPort(r.dnsOverTLSEnabled, r.dnsOverHTTPSEnabled)
				return ns, StatusNoError, layer, trace
			}
		}
	}
	return nil, StatusServFail, layer, trace
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

// populateResults is a helper function to populate the candidateSet, cnameSet, and garbage maps to follow CNAMES
// These maps are keyed by the domain name and contain the relevant answers for that domain
// candidateSet is a map of Answers that have a type matching the requested type.
// cnameSet is a map of Answers that are CNAME records
// dnameSet is a map of Answers that are DNAME records
// garbage is a map of Answers that are not of the requested type or CNAME records
// follows CNAME/DNAME and A/AAAA records to get all IPs for a given domain
func populateResults(records []interface{}, dnsType uint16, candidateSet map[string][]Answer, cnameSet map[string][]Answer, dnameSet map[string][]Answer, garbage map[string][]Answer) {
	var ans Answer
	var ok bool
	for _, a := range records {
		// filter only valid answers of requested type or CNAME (#163)
		if ans, ok = a.(Answer); !ok {
			continue
		}
		lowerCaseName := strings.ToLower(strings.TrimSuffix(ans.Name, "."))
		// Verify that the answer type matches requested type
		if VerifyAddress(ans.Type, ans.Answer) {
			ansType := dns.StringToType[ans.Type]
			if dnsType == ansType {
				candidateSet[lowerCaseName] = append(candidateSet[lowerCaseName], ans)
			} else if dns.TypeCNAME == ansType {
				cnameSet[lowerCaseName] = append(cnameSet[lowerCaseName], ans)
			} else if dns.TypeDNAME == ansType {
				dnameSet[lowerCaseName] = append(dnameSet[lowerCaseName], ans)
			} else {
				garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
			}
		} else {
			garbage[lowerCaseName] = append(garbage[lowerCaseName], ans)
		}
	}
}
