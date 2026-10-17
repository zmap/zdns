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
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zmap/dns"
)

// This file provides a fake network for testing how a Resolver behaves on the wire (connection re-use, which
// servers get queried and how often) without touching a real network. Unlike MockLookupClient, which replaces the
// whole lookup, everything above the Dialer runs for real: connection management, caching, iteration, etc.
//
// Usage: register a handler per "ip:port" with AddServer, set ResolverConfig.Dialer to the mockNetwork, run lookups,
// then assert on Dials/Queries.
//
// Both UDP and TCP are served over in-memory pipes with TCP-style length framing, so UDP semantics like truncation
// and datagram loss are not modeled. A handler can still set the TC bit or return nil (no reply, the client times out).

// mockDNSHandler produces the response to a query. network is "udp" or "tcp". Returning nil drops the query.
type mockDNSHandler func(network string, req *dns.Msg) *dns.Msg

type mockDial struct {
	Network string
	Address string
}

type mockQuery struct {
	Network string
	Address string
	Name    string
	Type    uint16
}

type mockNetwork struct {
	mu      sync.Mutex
	servers map[string]mockDNSHandler
	dials   []mockDial
	queries []mockQuery
}

func newMockNetwork() *mockNetwork {
	return &mockNetwork{servers: make(map[string]mockDNSHandler)}
}

// AddServer registers a fake DNS server at address, formatted "ip:port"
func (mn *mockNetwork) AddServer(address string, handler mockDNSHandler) {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	mn.servers[address] = handler
}

// DialContext implements Dialer
func (mn *mockNetwork) DialContext(ctx context.Context, network string, _ net.IP, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mn.mu.Lock()
	mn.dials = append(mn.dials, mockDial{Network: network, Address: address})
	handler, ok := mn.servers[address]
	mn.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	clientEnd, serverEnd := net.Pipe()
	go mn.serve(network, address, handler, serverEnd)
	remote, err := resolveAddr(network, address)
	if err != nil {
		return nil, err
	}
	return &mockConn{Conn: clientEnd, remote: remote}, nil
}

func (mn *mockNetwork) serve(network, address string, handler mockDNSHandler, conn net.Conn) {
	defer conn.Close()
	dnsConn := &dns.Conn{Conn: conn}
	for {
		req, err := dnsConn.ReadMsg()
		if err != nil {
			return // client closed the connection
		}
		if len(req.Question) > 0 {
			mn.mu.Lock()
			mn.queries = append(mn.queries, mockQuery{
				Network: network,
				Address: address,
				Name:    strings.TrimSuffix(strings.ToLower(req.Question[0].Name), "."),
				Type:    req.Question[0].Qtype,
			})
			mn.mu.Unlock()
		}
		resp := handler(network, req)
		if resp == nil {
			continue
		}
		resp.Id = req.Id
		resp.Response = true
		resp.Question = req.Question
		if err = dnsConn.WriteMsg(resp); err != nil {
			return
		}
	}
}

// Dials returns every connection opened to address, in order
func (mn *mockNetwork) Dials(network, address string) []mockDial {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	var res []mockDial
	for _, d := range mn.dials {
		if d.Network == network && d.Address == address {
			res = append(res, d)
		}
	}
	return res
}

// Queries returns every query received by the server at address, in order
func (mn *mockNetwork) Queries(address string) []mockQuery {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	var res []mockQuery
	for _, q := range mn.queries {
		if q.Address == address {
			res = append(res, q)
		}
	}
	return res
}

// mockConn gives the in-memory pipe the remote address of the server it pretends to be connected to
type mockConn struct {
	net.Conn
	remote net.Addr
}

func (c *mockConn) RemoteAddr() net.Addr { return c.remote }

func resolveAddr(network, address string) (net.Addr, error) {
	if strings.HasPrefix(network, "udp") {
		return net.ResolveUDPAddr(network, address)
	}
	return net.ResolveTCPAddr(network, address)
}

// newMockResolverConfig returns a config for a Resolver that only talks to the given mockNetwork. Name servers are
// on 127.0.0.0/8 so no real socket is needed to pick a local address.
func newMockResolverConfig(mn *mockNetwork) *ResolverConfig {
	config := NewResolverConfig()
	config.Dialer = mn
	config.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
	config.IPVersionMode = IPv4Only
	config.NetworkTimeout = 2 * time.Second
	config.IterativeTimeout = 4 * time.Second
	config.Timeout = 8 * time.Second
	return config
}

func newMockResolver(t *testing.T, config *ResolverConfig) *Resolver {
	t.Helper()
	r, err := InitResolver(config)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return r
}

// mockAnswerA responds with an authoritative A record for each ip
func mockAnswerA(req *dns.Msg, ips ...string) *dns.Msg {
	resp := new(dns.Msg)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	for _, ip := range ips {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip),
		})
	}
	return resp
}

// mockReferral responds with a delegation of zone to nsName, with glue pointing nsName at glueIP
func mockReferral(zone, nsName, glueIP string) *dns.Msg {
	resp := new(dns.Msg)
	resp.Ns = append(resp.Ns, &dns.NS{
		Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  dns.Fqdn(nsName),
	})
	resp.Extra = append(resp.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(nsName), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(glueIP),
	})
	return resp
}

// mockNXDomain is the response a handler should give for a name it doesn't know about
func mockNXDomain() *dns.Msg {
	resp := new(dns.Msg)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeNameError
	return resp
}
