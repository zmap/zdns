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
	"math/rand"
	"net"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
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
	DoDstServersLookup(r *Resolver, q Question, nameServer []NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error)
}

type LookupClient struct{}

// DoDstServersLookup performs a DNS lookup for a given question against a list of interchangeable nameservers
func (lc LookupClient) DoDstServersLookup(r *Resolver, q Question, nameServers []NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	return r.doDstServersLookup(q, nameServers, isIterative)
}

func (r *Resolver) doDstServersLookup(q Question, nameServers []NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	var err error
	// nameserver is required
	if len(nameServers) == 0 {
		return nil, nil, StatusIllegalInput, errors.New("no nameserver specified")
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
	retries := r.retries
	questionWithMeta := QuestionWithMetadata{
		Q:                q,
		RetriesRemaining: &retries,
	}
	if r.followCNAMEs {
		return r.followingLookup(ctx, &questionWithMeta, nameServers, isIterative)
	}
	res, trace, status, err := r.lookup(ctx, &questionWithMeta, nameServers, isIterative)
	if err != nil {
		return res, nil, status, fmt.Errorf("could not perform retrying lookup for name %v: %w", q.Name, err)
	}
	return res, trace, status, err
}

// lookup performs a DNS lookup for a given question against a slice of interchangeable nameservers, taking care of iterative and external lookups
func (r *Resolver) lookup(ctx context.Context, qWithMeta *QuestionWithMetadata, nameServers []NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	var res *SingleQueryResult
	var isCached IsCached
	var trace Trace
	var status Status
	var err error
	if util.HasCtxExpired(&ctx) {
		return res, trace, StatusTimeout, nil
	}
	if isIterative {
		r.verboseLog(1, "MIEKG-IN: following iterative lookup for ", qWithMeta.Q.Name, " (", qWithMeta.Q.Type, ")")
		res, trace, status, err = r.iterativeLookup(ctx, qWithMeta, nameServers, 1, ".", trace)
		r.verboseLog(1, "MIEKG-OUT: following iterative lookup for ", qWithMeta.Q.Name, " (", qWithMeta.Q.Type, "): status: ", status, " , err: ", err)
	} else {
		tries := 0
		// external lookup
		r.verboseLog(1, "MIEKG-IN: following external lookup for ", qWithMeta.Q.Name, " (", qWithMeta.Q.Type, ")")
		res, isCached, status, err = r.cyclingLookup(ctx, qWithMeta, nameServers, qWithMeta.Q.Name, 1, true)
		r.verboseLog(1, "MIEKG-OUT: following external lookup for ", qWithMeta.Q.Name, " (", qWithMeta.Q.Type, ") with ", tries, " attempts: status: ", status, " , err: ", err)
		var t TraceStep
		// TODO check for null res
		if res != nil {
			t.Result = *res
			t.NameServer = res.Resolver
		} else {
			t.Result = SingleQueryResult{}
		}
		t.DNSType = qWithMeta.Q.Type
		t.DNSClass = qWithMeta.Q.Class
		t.Name = qWithMeta.Q.Name
		t.Layer = qWithMeta.Q.Name
		t.Depth = 1
		t.Cached = isCached
		t.Try = tries
		trace = Trace{t}
	}
	return res, trace, status, err
}

// followingLoopup follows CNAMEs and DNAMEs in a DNS lookup for either an iterative or external lookup
// A lookup of a name has a certain number of retries where it will re-attempt with another nameserver if one times out.
// Those retries are per-name, so all subsequent iterative lookups for that name can use the single pool of retries.
// If an error occurs during the lookup, the last good result/status is returned along with the error and a full trace
// If an error occurs on the first lookup, the bad result/status is returned along with the error and a full trace
func (r *Resolver) followingLookup(ctx context.Context, qWithMeta *QuestionWithMetadata, nameServers []NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	var res *SingleQueryResult
	var trace Trace
	var status Status

	candidateSet := make(map[string][]Answer)
	cnameSet := make(map[string][]Answer)
	garbage := make(map[string][]Answer)
	allAnswerSet := make([]interface{}, 0)
	dnameSet := make(map[string][]Answer)

	originalName := qWithMeta.Q.Name // in case this is a CNAME, this keeps track of the original name while we change the question
	currName := qWithMeta.Q.Name     // this is the current name we are looking up
	r.verboseLog(0, "MIEKG-IN: starting a C/DNAME following lookup for ", originalName, " (", qWithMeta.Q.Type, ")")
	for i := 0; i < r.maxDepth; i++ {
		qWithMeta.Q.Name = currName // update the question with the current name, this allows following CNAMEs
		iterRes, iterTrace, iterStatus, lookupErr := r.lookup(ctx, qWithMeta, nameServers, isIterative)
		// append iterTrace to the global trace so we can return full trace
		if iterTrace != nil {
			trace = append(trace, iterTrace...)
		}
		if iterStatus != StatusNoError || lookupErr != nil {
			if i == 0 {
				// only have 1 result to return
				return iterRes, trace, iterStatus, lookupErr
			}
			// return the last good result/status if we're traversing CNAMEs
			return res, trace, status, errors.Wrapf(lookupErr, "iterative lookup failed for name %v at depth %d", qWithMeta.Q.Name, i)
		}
		// update the result with the latest iteration since there's no error
		// We'll return the latest good result if we're traversing CNAMEs
		res = iterRes
		status = iterStatus

		if qWithMeta.Q.Type == dns.TypeMX {
			// MX records have a special lookup format, so we won't attempt to follow CNAMES here
			return res, trace, status, nil
		}

		// populateResults will parse the Answers and update the candidateSet, cnameSet, and garbage caching maps
		populateResults(res.Answers, qWithMeta.Q.Type, candidateSet, cnameSet, dnameSet, garbage)
		allAnswerSet = append(allAnswerSet, res.Answers...)

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
			return iterRes, trace, StatusNoError, nil
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

func (r *Resolver) iterativeLookup(ctx context.Context, qWithMeta *QuestionWithMetadata, nameServers []NameServer,
	depth int, layer string, trace Trace) (*SingleQueryResult, Trace, Status, error) {
	if depth > r.maxDepth {
		r.verboseLog(depth+1, "-> Max recursion depth reached")
		return nil, trace, StatusError, errors.New("max recursion depth reached")
	}
	// check that context hasn't expired
	if util.HasCtxExpired(&ctx) {
		r.verboseLog(depth+1, "-> Context expired")
		return nil, trace, StatusTimeout, nil
	}
	// create iteration context for this iteration step
	iterationStepCtx, cancel := context.WithTimeout(ctx, r.iterativeTimeout)
	defer cancel()
	result, isCached, status, err := r.cyclingLookup(iterationStepCtx, qWithMeta, nameServers, layer, depth, false)
	if status == StatusNoError && result != nil {
		var t TraceStep
		t.Result = *result
		t.NameServer = result.Resolver
		t.DNSType = qWithMeta.Q.Type
		t.DNSClass = qWithMeta.Q.Class
		t.Name = qWithMeta.Q.Name
		t.Layer = layer
		t.Depth = depth
		t.Cached = isCached
		t.Try = getTryNumber(r.retries, *qWithMeta.RetriesRemaining)
		trace = append(trace, t)
	}
	if status == StatusTimeout && util.HasCtxExpired(&iterationStepCtx) && !util.HasCtxExpired(&ctx) {
		// ctx's have a deadline of the minimum of their deadline and their parent's
		// retryingLookup doesn't disambiguate of whether the timeout was caused by the iteration timeout or the global timeout
		// we'll disambiguate here by checking if the iteration context has expired but the global context hasn't
		r.verboseLog(depth+2, "ITERATIVE_TIMEOUT ", qWithMeta, ", Layer: ", layer)
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
		return r.iterateOnAuthorities(ctx, qWithMeta, depth, result, layer, trace)
	} else {
		r.verboseLog((depth + 1), "-> No Authority found, error")
		return result, trace, StatusError, errors.New("NOERROR record without any answers or authorities")
	}
}

// cyclingLookup performs a DNS lookup against a slice of nameservers, cycling through them until a valid response is received.
// If the number of retries in QuestionWithMetadata is 0, the function will return an error.
func (r *Resolver) cyclingLookup(ctx context.Context, qWithMeta *QuestionWithMetadata, nameServers []NameServer, layer string, depth int, recursionDesired bool) (*SingleQueryResult, IsCached, Status, error) {
	var cacheBasedOnNameServer bool
	var cacheNonAuthoritative bool
	if recursionDesired {
		// we're doing an external lookup and need to set the recursionDesired bit
		// Additionally, in external mode we may perform the same lookup against multiple nameservers, so the cache should be based on the nameserver as well
		cacheBasedOnNameServer = true
		cacheNonAuthoritative = true
	} else {
		// we're doing an iterative lookup, so we'll cache a response for any nameserver that's authoritative
		cacheBasedOnNameServer = false
		cacheNonAuthoritative = false
	}
	var result *SingleQueryResult
	var isCached IsCached
	var status Status
	var err error
	queriedNameServers := make(map[string]struct{}, len(nameServers))
	var nameServer *NameServer

	for *qWithMeta.RetriesRemaining >= 0 {
		if util.HasCtxExpired(&ctx) {
			return &SingleQueryResult{}, false, StatusTimeout, nil
		}
		// get random unqueried nameserver
		nameServer, queriedNameServers = getRandomNonQueriedNameServer(nameServers, queriedNameServers)
		// perform the lookup
		result, isCached, status, err = r.cachedLookup(ctx, qWithMeta.Q, nameServer, layer, depth, recursionDesired, cacheBasedOnNameServer, cacheNonAuthoritative)
		if status == StatusNoError {
			r.verboseLog(depth+1, "Cycling lookup successful. Name: ", qWithMeta.Q.Name, ", Layer: ", layer, ", Nameserver: ", nameServer)
			return result, isCached, status, err
		} else if *qWithMeta.RetriesRemaining == 0 {
			r.verboseLog(depth+1, "Cycling lookup failed - out of retries. Name: ", qWithMeta.Q.Name, ", Layer: ", layer, ", Nameserver: ", nameServer)
			return result, isCached, status, errors.New("cycling lookup failed - out of retries")
		}
		r.verboseLog(depth+1, "Cycling lookup failed, using a retry. Retries remaining: ", qWithMeta.RetriesRemaining, " , Name: ", qWithMeta.Q.Name, ", Layer: ", layer, ", Nameserver: ", nameServer)
		*qWithMeta.RetriesRemaining--
	}
	return &SingleQueryResult{}, false, StatusError, errors.New("cycling lookup function did not exit properly")
}

// getRandomNonQueriedNameServer returns a random name server from the list of name servers that has not been queried yet
// If all have been queried, it resets the queriedNameServers map and returns a random name server
func getRandomNonQueriedNameServer(nameServers []NameServer, queriedNameServers map[string]struct{}) (*NameServer, map[string]struct{}) {
	for _, i := range rand.Perm(len(nameServers)) {
		if _, ok := queriedNameServers[nameServers[i].String()]; !ok {
			// set the nameserver as queried
			queriedNameServers[nameServers[i].String()] = struct{}{}
			return &nameServers[i], queriedNameServers
		}
	}
	// all have been queried, reset queriedNameServers
	queriedNameServers = make(map[string]struct{}, len(nameServers))
	// return a random one
	return getRandomNonQueriedNameServer(nameServers, queriedNameServers)
}

// cachedLookup performs a DNS lookup with caching
// returns the result, whether it was cached, the status, and an error if one occurred
// layer is the domain name layer we're currently querying ex: ".", "com.", "example.com."
// depth is the current depth of the lookup, used for iterative lookups
// requestIteration is whether to set the "recursion desired" bit in the DNS query
// cacheBasedOnNameServer is whether to consider a cache hit based on DNS question and nameserver, or just question
// cacheNonAuthoritative is whether to cache non-authoritative answers, usually used for lookups using an external resolver
func (r *Resolver) cachedLookup(ctx context.Context, q Question, nameServer *NameServer, layer string, depth int, requestIteration, cacheBasedOnNameServer, cacheNonAuthoritative bool) (*SingleQueryResult, IsCached, Status, error) {
	var isCached IsCached
	isCached = false
	r.verboseLog(depth+1, "Cached retrying lookup. Name: ", q, ", Layer: ", layer, ", Nameserver: ", nameServer)
	if isValid, reason := nameServer.IsValid(); !isValid {
		return &SingleQueryResult{}, false, StatusIllegalInput, fmt.Errorf("invalid nameserver (%s): %s", nameServer.String(), reason)
	}
	// create a context for this network lookup
	lookupCtx, cancel := context.WithTimeout(ctx, r.networkTimeout)
	defer cancel()

	// For some lookups, we want them to be nameserver specific, ie. if cacheBasedOnNameServer is true
	// Else, we don't care which nameserver returned it
	cacheNameServer := nameServer
	if !cacheBasedOnNameServer {
		cacheNameServer = nil
	}
	// First, we check the cache
	cachedResult, ok := r.cache.GetCachedResults(q, cacheNameServer, depth+1)
	if ok {
		isCached = true
		// set protocol on the result
		if r.dnsOverHTTPSEnabled {
			cachedResult.Protocol = DoHProtocol
		} else if r.dnsOverTLSEnabled {
			cachedResult.Protocol = DoTProtocol
		} else if r.transportMode == TCPOnly {
			cachedResult.Protocol = TCPProtocol
		} else {
			// default to UDP
			cachedResult.Protocol = UDPProtocol
		}
		return cachedResult, isCached, StatusNoError, nil
	}

	// Stop if we hit a nameserver we don't want to hit
	if r.blacklist != nil {
		if blacklisted, isBlacklistedErr := r.blacklist.IsBlacklisted(nameServer.IP.String()); isBlacklistedErr != nil {
			return nil, isCached, StatusError, errors.Wrapf(isBlacklistedErr, "could not check blacklist for nameserver IP: %s", nameServer.IP.String())
		} else if blacklisted {
			return &SingleQueryResult{}, isCached, StatusBlacklist, nil
		}
	}
	var authName string
	if !requestIteration {
		// We're performing our own iteration, let's try checking the cache for the next authority
		// For example, if we query yahoo.com and google.com, we don't need to go to the root servers for the gTLD
		// servers twice, they'll be identical
		name := strings.ToLower(q.Name)
		layer = strings.ToLower(layer)
		var err error
		// get the next authority to query
		authName, err = nextAuthority(name, layer)
		if err != nil {
			r.verboseLog(depth+2, err)
			return &SingleQueryResult{}, isCached, StatusAuthFail, errors.Wrap(err, "could not get next authority with name: "+name+" and layer: "+layer)
		}
		if name != layer && authName != layer {
			// we have a valid authority to check the cache for
			if authName == "" {
				r.verboseLog(depth+2, "Can't parse name to authority properly. name: ", name, ", layer: ", layer)
				return &SingleQueryResult{}, isCached, StatusAuthFail, nil
			}
			r.verboseLog(depth+2, "Cache auth check for ", authName)
			// TODO - this will need to be changed for AllNameServers
			cachedResult, ok = r.cache.GetCachedAuthority(authName, nil, depth+2)
			if ok {
				r.verboseLog(depth+2, "Cache auth hit for ", authName)
				// only want to return if we actually have additionals and authorities from the cache for the caller
				if len(cachedResult.Additional) > 0 && len(cachedResult.Authorities) > 0 {
					return cachedResult, true, StatusNoError, nil
				}
				// unsuccessful in retrieving from the cache, we'll continue to the wire
			}
		}
	}

	// Alright, we're not sure what to do, go to the wire.
	r.verboseLog(depth+2, "Cache miss for ", q, ", Layer: ", layer, ", Nameserver: ", nameServer, " going to the wire in retryingLookup")
	connInfo, err := r.getConnectionInfo(nameServer)
	if err != nil {
		return &SingleQueryResult{}, false, StatusError, fmt.Errorf("could not get a connection info to query nameserver %s: %v", nameServer, err)
	}
	// check that our connection info is valid
	if connInfo == nil {
		return &SingleQueryResult{}, false, StatusError, fmt.Errorf("no connection info for nameserver: %s", nameServer)
	}
	var result *SingleQueryResult
	var status Status
	if r.dnsOverHTTPSEnabled {
		r.verboseLog(1, "****WIRE LOOKUP*** ", DoHProtocol, " ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)
		result, status, err = doDoHLookup(lookupCtx, connInfo.httpsClient, q, nameServer, requestIteration, r.ednsOptions, r.dnsSecEnabled, r.checkingDisabledBit)
	} else if r.dnsOverTLSEnabled {
		r.verboseLog(1, "****WIRE LOOKUP*** ", DoTProtocol, " ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)
		result, status, err = doDoTLookup(lookupCtx, connInfo, q, nameServer, r.rootCAs, r.verifyServerCert, requestIteration, r.ednsOptions, r.dnsSecEnabled, r.checkingDisabledBit)
	} else if connInfo.udpClient != nil {
		r.verboseLog(1, "****WIRE LOOKUP*** ", UDPProtocol, " ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)
		result, status, err = wireLookupUDP(lookupCtx, connInfo, q, nameServer, r.ednsOptions, requestIteration, r.dnsSecEnabled, r.checkingDisabledBit)
		if status == StatusTruncated && connInfo.tcpClient != nil {
			// result truncated, try again with TCP
			r.verboseLog(1, "****WIRE LOOKUP*** ", TCPProtocol, " ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)
			result, status, err = wireLookupTCP(lookupCtx, connInfo, q, nameServer, r.ednsOptions, requestIteration, r.dnsSecEnabled, r.checkingDisabledBit)
		}
	} else if connInfo.tcpClient != nil {
		r.verboseLog(1, "****WIRE LOOKUP*** ", TCPProtocol, " ", dns.TypeToString[q.Type], " ", q.Name, " ", nameServer)
		result, status, err = wireLookupTCP(lookupCtx, connInfo, q, nameServer, r.ednsOptions, requestIteration, r.dnsSecEnabled, r.checkingDisabledBit)
	} else {
		return &SingleQueryResult{}, false, StatusError, errors.New("no connection info for nameserver")
	}

	if err != nil {
		return &SingleQueryResult{}, isCached, status, errors.Wrap(err, "could not perform lookup")
	}
	r.verboseLog(depth+2, "Results from wire for name: ", q, ", Layer: ", layer, ", Nameserver: ", nameServer, " status: ", status, " , err: ", err, " result: ", result)

	if status == StatusNoError && result != nil {
		// only cache answers that don't have errors
		if !requestIteration && strings.ToLower(q.Name) != layer && authName != layer && !result.Flags.Authoritative { // TODO - how to detect if we've retrieved an authority record or a answer record? maybe add q.Name != authName
			r.verboseLog(depth+2, "Cache auth upsert for ", authName)
			r.cache.SafeAddCachedAuthority(result, cacheNameServer, depth+2, layer)

		} else {
			r.cache.SafeAddCachedAnswer(q, result, cacheNameServer, layer, depth+2, cacheNonAuthoritative)
		}
	}
	return result, isCached, status, err
}

func doDoTLookup(ctx context.Context, connInfo *ConnectionInfo, q Question, nameServer *NameServer, rootCAs *x509.CertPool, shouldVerifyServerCert, recursive bool, ednsOptions []dns.EDNS0, dnssec bool, checkingDisabled bool) (*SingleQueryResult, Status, error) {
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
			return nil, StatusError, errors.Wrap(err, "could not connect to server")
		}
		// Now wrap the connection with TLS
		tlsConn := tls.Client(tcpConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if shouldVerifyServerCert {
			// if we're verifying the server cert, we need to pass in the root CAs
			tlsConn = tls.Client(tcpConn, &tls.Config{
				RootCAs:            rootCAs,
				InsecureSkipVerify: false,
				ServerName:         nameServer.DomainName,
			})
		}
		err = tlsConn.Handshake()
		if err != nil {
			closeErr := tlsConn.Close()
			if closeErr != nil {
				log.Errorf("error closing TLS connection: %v", err)
			}
			return nil, StatusError, errors.Wrap(err, "could not perform TLS handshake")
		}
		connInfo.tlsHandshake = tlsConn.GetHandshakeLog()
		connInfo.tlsConn = &dns.Conn{Conn: tlsConn}
	}
	err := connInfo.tlsConn.WriteMsg(m)
	if err != nil {
		return nil, "", errors.Wrap(err, "could not write query over DoT to server")
	}
	responseMsg, err := connInfo.tlsConn.ReadMsg()
	if err != nil {
		return nil, StatusError, errors.Wrap(err, "could not unpack DNS message from DoT server")
	}
	res := SingleQueryResult{
		Resolver:    connInfo.tlsConn.Conn.RemoteAddr().String(),
		Protocol:    DoTProtocol,
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
	return constructSingleQueryResultFromDNSMsg(&res, responseMsg)
}

func doDoHLookup(ctx context.Context, httpClient *http.Client, q Question, nameServer *NameServer, recursive bool, ednsOptions []dns.EDNS0, dnssec bool, checkingDisabled bool) (*SingleQueryResult, Status, error) {
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
		return nil, StatusError, errors.Wrap(err, "could not pack DNS message")
	}
	if strings.Contains(nameServer.DomainName, "http://") {
		return nil, StatusError, errors.New("DoH name server must use HTTPS")
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
		return nil, StatusError, errors.Wrap(err, "could not create HTTP request")
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req = req.WithContext(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, StatusError, errors.Wrap(err, "could not perform HTTP request")
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Errorf("error closing DoH response body: %v", err)
		}
	}(resp.Body)
	bytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, StatusError, errors.Wrap(err, "could not read HTTP response")
	}

	r := new(dns.Msg)
	err = r.Unpack(bytes)
	if err != nil {
		return nil, StatusError, errors.Wrap(err, "could not unpack DNS message")
	}
	res := SingleQueryResult{
		Resolver:    nameServer.DomainName,
		Protocol:    DoHProtocol,
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
	return constructSingleQueryResultFromDNSMsg(&res, r)
}

// wireLookupTCP performs a DNS lookup on-the-wire over TCP with the given parameters
func wireLookupTCP(ctx context.Context, connInfo *ConnectionInfo, q Question, nameServer *NameServer, ednsOptions []dns.EDNS0, recursive, dnssec, checkingDisabled bool) (*SingleQueryResult, Status, error) {
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
	if connInfo.tcpConn != nil && connInfo.tcpConn.RemoteAddr != nil && connInfo.tcpConn.RemoteAddr.String() == nameServer.String() {
		// we have a connection to this nameserver, use it
		res.Protocol = "tcp"
		var addr *net.TCPAddr
		addr, err = net.ResolveTCPAddr("tcp", nameServer.String())
		if err != nil {
			return nil, StatusError, fmt.Errorf("could not resolve TCP address %s: %v", nameServer.String(), err)
		}
		r, _, err = connInfo.tcpClient.ExchangeWithConnToContext(ctx, m, connInfo.tcpConn, addr)
		if err != nil && err.Error() == "EOF" {
			// EOF error means the connection was closed, we'll remove the connection (it'll be recreated on the next iteration)
			// and try again
			err = connInfo.tcpConn.Conn.Close()
			if err != nil {
				log.Errorf("error closing TCP connection: %v", err)
			}
			connInfo.tcpConn = nil
			r, _, err = connInfo.tcpClient.ExchangeContext(ctx, m, nameServer.String())
		}
	} else {
		// no pre-existing connection, create an ephemeral one
		res.Protocol = "tcp"
		r, _, err = connInfo.tcpClient.ExchangeContext(ctx, m, nameServer.String())
	}
	if err != nil || r == nil {
		if nerr, ok := err.(net.Error); ok {
			if nerr.Timeout() {
				return &res, StatusTimeout, nil
			}
		}
		return &res, StatusError, err
	}

	return constructSingleQueryResultFromDNSMsg(&res, r)
}

// wireLookupUDP performs a DNS lookup on-the-wire over UDP with the given parameters
func wireLookupUDP(ctx context.Context, connInfo *ConnectionInfo, q Question, nameServer *NameServer, ednsOptions []dns.EDNS0, recursive, dnssec, checkingDisabled bool) (*SingleQueryResult, Status, error) {
	res := SingleQueryResult{Answers: []interface{}{}, Authorities: []interface{}{}, Additional: []interface{}{}}
	res.Resolver = nameServer.String()
	res.Protocol = "udp"

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
	if connInfo.udpConn != nil {
		dst, _ := net.ResolveUDPAddr("udp", nameServer.String())
		r, _, err = connInfo.udpClient.ExchangeWithConnToContext(ctx, m, connInfo.udpConn, dst)
	} else {
		r, _, err = connInfo.udpClient.ExchangeContext(ctx, m, nameServer.String())
	}
	if r != nil && (r.Truncated || r.Rcode == dns.RcodeBadTrunc) {
		return &res, StatusTruncated, err
	}
	if err != nil || r == nil {
		if nerr, ok := err.(net.Error); ok {
			if nerr.Timeout() {
				return &res, StatusTimeout, nil
			}
		}
		return &res, StatusError, err
	}

	return constructSingleQueryResultFromDNSMsg(&res, r)
}

// fills out all the fields in a SingleQueryResult from a dns.Msg directly.
func constructSingleQueryResultFromDNSMsg(res *SingleQueryResult, r *dns.Msg) (*SingleQueryResult, Status, error) {
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

func (r *Resolver) iterateOnAuthorities(ctx context.Context, qWithMeta *QuestionWithMetadata, depth int, result *SingleQueryResult, layer string, trace Trace) (*SingleQueryResult, Trace, Status, error) {
	if len(result.Authorities) == 0 {
		return nil, trace, StatusNoAuth, nil
	}
	var newLayer string
	newTrace := trace
	nameServers := make([]NameServer, 0, len(result.Authorities))
	for i, elem := range result.Authorities {
		if util.HasCtxExpired(&ctx) {
			return &SingleQueryResult{}, newTrace, StatusTimeout, nil
		}
		var ns *NameServer
		var nsStatus Status
		r.verboseLog(depth+1, "Trying Authority: ", elem)
		ns, nsStatus, newLayer, newTrace = r.extractAuthority(ctx, elem, layer, qWithMeta.RetriesRemaining, depth, result, newTrace)
		r.verboseLog(depth+1, "Output from extract authorities: ", ns.String())
		if nsStatus == StatusIterTimeout {
			r.verboseLog(depth+2, "--> Hit iterative timeout: ")
			return &SingleQueryResult{}, newTrace, StatusIterTimeout, nil
		}
		if nsStatus != StatusNoError {
			var err error
			newStatus, err := handleStatus(nsStatus, err)
			if err != nil {
				r.verboseLog(depth+2, "--> Auth find failed for name ", qWithMeta.Q.Name, " with status: ", newStatus, " and error: ", err)
			} else {
				r.verboseLog(depth+2, "--> Auth find failed for name ", qWithMeta.Q.Name, " with status: ", newStatus)
			}
			if i+1 == len(result.Authorities) {
				r.verboseLog(depth+2, "--> No more authorities to try for name ", qWithMeta.Q.Name, ", terminating: ", nsStatus)
			}
		} else {
			// We have a valid nameserver
			nameServers = append(nameServers, *ns)
		}
	}

	if len(nameServers) == 0 {
		r.verboseLog(depth+1, fmt.Sprintf("--> Auth found no valid nameservers for name: %s Terminating", qWithMeta.Q.Name))
		return &SingleQueryResult{}, newTrace, StatusServFail, errors.New("no valid nameservers found")
	}

	iterateResult, newTrace, status, err := r.iterativeLookup(ctx, qWithMeta, nameServers, depth+1, newLayer, newTrace)
	if status == StatusNoNeededGlue {
		r.verboseLog((depth + 2), "--> Auth resolution of ", nameServers, " was unsuccessful. No glue to follow", status)
		return iterateResult, newTrace, status, err
	} else if isStatusAnswer(status) {
		r.verboseLog((depth + 1), "--> Auth Resolution of ", nameServers, " success: ", status)
		return iterateResult, newTrace, status, err
	} else {
		// We don't allow the continue fall through in order to report the last auth failure code, not STATUS_ERROR
		r.verboseLog((depth + 2), "--> Iterative resolution of ", qWithMeta.Q.Name, " at ", nameServers, " Failed. Last auth. Terminating: ", status)
		return iterateResult, newTrace, status, err
	}
}

func (r *Resolver) extractAuthority(ctx context.Context, authority interface{}, layer string, retriesRemaining *int, depth int, result *SingleQueryResult, trace Trace) (*NameServer, Status, string, Trace) {
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
	res, status := checkGlue(server, result, r.ipVersionMode, r.iterationIPPreference)
	if status != StatusNoError {
		//if ok, _ = nameIsBeneath(server, layer); ok {
		//	// Glue is optional, so if we don't have it try to lookup the server directly
		//	// Terminating
		//	return nil, StatusNoNeededGlue, "", trace
		//}
		// Fall through to normal query
		var q QuestionWithMetadata
		q.Q.Name = server
		q.Q.Class = dns.ClassINET
		if r.ipVersionMode != IPv4Only && r.iterationIPPreference == PreferIPv6 {
			q.Q.Type = dns.TypeAAAA
		} else {
			q.Q.Type = dns.TypeA
		}
		q.RetriesRemaining = retriesRemaining
		res, trace, status, _ = r.iterativeLookup(ctx, &q, r.rootNameServers, depth+1, ".", trace)
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
