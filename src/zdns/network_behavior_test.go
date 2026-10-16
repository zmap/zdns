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
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zmap/dns"
)

// These tests check guarantees about how ZDNS uses the network, using the fake network in mock_network_test.go.

const (
	mockRootIP        = "127.0.0.10"
	mockGTLDIP        = "127.0.0.11"
	mockGoogleNSIP    = "127.0.0.12"
	mockYahooNSIP     = "127.0.0.13"
	mockExternalIP    = "127.0.0.20"
	mockRootAddr      = mockRootIP + ":53"
	mockGTLDAddr      = mockGTLDIP + ":53"
	mockGoogleNSAddr  = mockGoogleNSIP + ":53"
	mockYahooNSAddr   = mockYahooNSIP + ":53"
	mockExternalAddr  = mockExternalIP + ":53"
	mockExampleAnswer = "192.0.2.1"
)

// addMockExternalResolver registers a recursive resolver that answers every A query
func addMockExternalResolver(mn *mockNetwork) {
	mn.AddServer(mockExternalAddr, func(_ string, req *dns.Msg) *dns.Msg {
		return mockAnswerA(req, mockExampleAnswer)
	})
}

// addMockDNSHierarchy registers a root server, a .com gTLD server and authoritative servers for google.com and
// yahoo.com. All names below google.com/yahoo.com resolve.
func addMockDNSHierarchy(mn *mockNetwork) {
	mn.AddServer(mockRootAddr, func(_ string, req *dns.Msg) *dns.Msg {
		if strings.HasSuffix(strings.ToLower(req.Question[0].Name), "com.") {
			return mockReferral("com", "a.gtld-servers.net", mockGTLDIP)
		}
		return mockNXDomain()
	})
	mn.AddServer(mockGTLDAddr, func(_ string, req *dns.Msg) *dns.Msg {
		name := strings.ToLower(req.Question[0].Name)
		switch {
		case strings.HasSuffix(name, "google.com."):
			return mockReferral("google.com", "ns1.google.com", mockGoogleNSIP)
		case strings.HasSuffix(name, "yahoo.com."):
			return mockReferral("yahoo.com", "ns1.yahoo.com", mockYahooNSIP)
		}
		return mockNXDomain()
	})
	mn.AddServer(mockGoogleNSAddr, func(_ string, req *dns.Msg) *dns.Msg {
		return mockAnswerA(req, mockExampleAnswer)
	})
	mn.AddServer(mockYahooNSAddr, func(_ string, req *dns.Msg) *dns.Msg {
		return mockAnswerA(req, mockExampleAnswer)
	})
}

func newMockIterativeResolver(t *testing.T, mn *mockNetwork) *Resolver {
	config := newMockResolverConfig(mn)
	config.RootNameServersV4 = []NameServer{{IP: net.ParseIP(mockRootIP), Port: 53}}
	// socket recycling only matters for connection re-use, and the fake network doesn't implement UDP listeners
	config.ShouldRecycleSockets = false
	return newMockResolver(t, config)
}

func lookupAllIteratively(t *testing.T, r *Resolver, names ...string) {
	t.Helper()
	for _, name := range names {
		res, _, status, err := r.IterativeLookup(context.Background(), &Question{Name: name, Type: dns.TypeA, Class: dns.ClassINET})
		require.NoError(t, err, "lookup of %s failed", name)
		require.Equal(t, StatusNoError, status, "lookup of %s had status %s", name, status)
		require.NotEmpty(t, res.Answers, "lookup of %s had no answers", name)
	}
}

func TestTCPSessionIsReused(t *testing.T) {
	names := []string{"google.com", "yahoo.com", "microsoft.com", "apple.com", "ebay.com", "zdns-testing.com", "cloudflare.com"}

	lookupAll := func(t *testing.T, r *Resolver) {
		dst := &NameServer{IP: net.ParseIP(mockExternalIP), Port: 53}
		for _, name := range names {
			res, _, status, err := r.ExternalLookup(context.Background(), &Question{Name: name, Type: dns.TypeA, Class: dns.ClassINET}, dst)
			require.NoError(t, err, "lookup of %s failed", name)
			require.Equal(t, StatusNoError, status)
			require.Equal(t, "tcp", res.Protocol)
		}
	}

	t.Run("one handshake for all lookups when recycling sockets", func(t *testing.T) {
		mn := newMockNetwork()
		addMockExternalResolver(mn)
		config := newMockResolverConfig(mn)
		config.TransportMode = TCPOnly
		config.ShouldRecycleSockets = true
		// each lookup is a unique name, so the cache can't be what's avoiding the extra handshakes
		r := newMockResolver(t, config)

		lookupAll(t, r)

		require.Len(t, mn.Queries(mockExternalAddr), len(names), "every name should have gone to the wire")
		require.Len(t, mn.Dials("tcp", mockExternalAddr), 1, "TCP session should have been re-used")
		require.Empty(t, mn.Dials("udp", mockExternalAddr))
	})

	t.Run("handshake per lookup when not recycling sockets", func(t *testing.T) {
		// control for the above, shows the test can detect a handshake per lookup
		mn := newMockNetwork()
		addMockExternalResolver(mn)
		config := newMockResolverConfig(mn)
		config.TransportMode = TCPOnly
		config.ShouldRecycleSockets = false
		r := newMockResolver(t, config)

		lookupAll(t, r)

		require.Len(t, mn.Queries(mockExternalAddr), len(names))
		require.Len(t, mn.Dials("tcp", mockExternalAddr), len(names))
	})

	t.Run("each resolver (thread) holds its own session", func(t *testing.T) {
		mn := newMockNetwork()
		addMockExternalResolver(mn)
		for range 2 {
			config := newMockResolverConfig(mn)
			config.TransportMode = TCPOnly
			config.ShouldRecycleSockets = true
			lookupAll(t, newMockResolver(t, config))
		}

		require.Len(t, mn.Queries(mockExternalAddr), 2*len(names))
		require.Len(t, mn.Dials("tcp", mockExternalAddr), 2)
	})
}

func TestIterativeLookupsQueryRootOncePerGTLD(t *testing.T) {
	t.Run("different domains in the same gTLD", func(t *testing.T) {
		mn := newMockNetwork()
		addMockDNSHierarchy(mn)
		r := newMockIterativeResolver(t, mn)

		lookupAllIteratively(t, r, "google.com", "yahoo.com")

		require.Len(t, mn.Queries(mockRootAddr), 1, "root servers should only be asked about .com once")
		require.Len(t, mn.Queries(mockGTLDAddr), 2, "gTLD servers should be asked once per domain")
		require.Len(t, mn.Queries(mockGoogleNSAddr), 1)
		require.Len(t, mn.Queries(mockYahooNSAddr), 1)
	})

	t.Run("sub-domains of the same domain", func(t *testing.T) {
		mn := newMockNetwork()
		addMockDNSHierarchy(mn)
		r := newMockIterativeResolver(t, mn)

		lookupAllIteratively(t, r, "google.com", "www.google.com", "mail.google.com")

		require.Len(t, mn.Queries(mockRootAddr), 1, "root servers should only be asked about .com once")
		require.Len(t, mn.Queries(mockGTLDAddr), 1, ".com servers should only be asked about google.com once")
		require.Len(t, mn.Queries(mockGoogleNSAddr), 3)
	})

	t.Run("repeating a lookup is served from the cache", func(t *testing.T) {
		mn := newMockNetwork()
		addMockDNSHierarchy(mn)
		r := newMockIterativeResolver(t, mn)

		lookupAllIteratively(t, r, "google.com")
		queriesAfterFirst := len(mn.Queries(mockRootAddr)) + len(mn.Queries(mockGTLDAddr)) + len(mn.Queries(mockGoogleNSAddr))
		lookupAllIteratively(t, r, "google.com")
		queriesAfterSecond := len(mn.Queries(mockRootAddr)) + len(mn.Queries(mockGTLDAddr)) + len(mn.Queries(mockGoogleNSAddr))

		require.Equal(t, 3, queriesAfterFirst, "one query to each of root, .com and google.com")
		require.Equal(t, queriesAfterFirst, queriesAfterSecond, "second lookup should not touch the network")
	})

	t.Run("separate resolvers sharing no cache each query the root", func(t *testing.T) {
		// control, shows the test can detect root queries
		mn := newMockNetwork()
		addMockDNSHierarchy(mn)

		lookupAllIteratively(t, newMockIterativeResolver(t, mn), "google.com")
		lookupAllIteratively(t, newMockIterativeResolver(t, mn), "yahoo.com")

		require.Len(t, mn.Queries(mockRootAddr), 2)
	})
}
