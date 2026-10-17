/*
* ZDNS Copyright 2026 Regents of the University of Michigan
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
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zmap/dns"

	blacklist "github.com/zmap/zdns/v2/src/internal/safeblacklist"
)

// fakeHealthTracker is a NameServerHealthTracker with fixed scores that records what it is asked
type fakeHealthTracker struct {
	mu       sync.Mutex
	scores   map[netip.Addr]float64
	records  []fakeRecord
	scoreErr bool // fail the test if score is called
	t        *testing.T
}

type fakeRecord struct {
	ip     netip.Addr
	failed bool
}

func newFakeHealthTracker(t *testing.T) *fakeHealthTracker {
	return &fakeHealthTracker{scores: make(map[netip.Addr]float64), t: t}
}

func (f *fakeHealthTracker) record(ip netip.Addr, failed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, fakeRecord{ip: ip, failed: failed})
}

func (f *fakeHealthTracker) score(ip netip.Addr) float64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scoreErr {
		f.t.Errorf("score(%v) called, tracker should not have been consulted", ip)
	}
	return f.scores[ip]
}

func (f *fakeHealthTracker) getRecords() []fakeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeRecord(nil), f.records...)
}

// testNameServers returns n name servers 192.0.2.1..n on port 53
func testNameServers(n int) []NameServer {
	nses := make([]NameServer, n)
	for i := range nses {
		nses[i] = NameServer{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1)), Port: 53}
	}
	return nses
}

func mustAddr(t *testing.T, ns NameServer) netip.Addr {
	addr, ok := nameServerAddr(&ns)
	require.True(t, ok)
	return addr
}

// firstPickCounts returns how often each name server is the first pick of a fresh cycle over draws
func firstPickCounts(nses []NameServer, health NameServerHealthTracker, rng *rand.Rand, draws int) map[string]int {
	counts := make(map[string]int)
	for i := 0; i < draws; i++ {
		ns, _ := selectNameServer(nses, make(map[string]struct{}), health, rng)
		counts[ns.String()]++
	}
	return counts
}

// Without a health tracker, selection is uniformly random, as it was before health tracking
func TestSelectNameServer_NilTrackerIsUniform(t *testing.T) {
	nses := testNameServers(13)
	counts := firstPickCounts(nses, nil, rand.New(rand.NewSource(1)), 13000)
	for _, ns := range nses {
		require.InDelta(t, 1000, counts[ns.String()], 150, "name server %s", ns.String())
	}
}

// With a tracker but every score equal (e.g. no health data yet), selection is still uniform, so load stays spread
func TestSelectNameServer_EqualScoresAreUniform(t *testing.T) {
	nses := testNameServers(13)
	health := newFakeHealthTracker(t)
	for _, ns := range nses {
		health.scores[mustAddr(t, ns)] = 0.3
	}
	counts := firstPickCounts(nses, health, rand.New(rand.NewSource(1)), 13000)
	for _, ns := range nses {
		require.InDelta(t, 1000, counts[ns.String()], 150, "name server %s", ns.String())
	}
}

// Power-of-two choices never picks the worse of the two drawn, so a single dead server among 13 is never the first pick
func TestSelectNameServer_AvoidsDeadServer(t *testing.T) {
	nses := testNameServers(13)
	dead := nses[4]
	health := newFakeHealthTracker(t)
	health.scores[mustAddr(t, dead)] = 1.0

	counts := firstPickCounts(nses, health, rand.New(rand.NewSource(1)), 10000)
	require.Zero(t, counts[dead.String()], "dead name server chosen first")

	// baseline: without the tracker the dead server is the first pick about 1 in 13 times
	baseline := firstPickCounts(nses, nil, rand.New(rand.NewSource(1)), 10000)
	require.InDelta(t, 10000/13, baseline[dead.String()], 150)
}

// With two servers the healthy one goes first, and the dead one is still tried second, never excluded
func TestSelectNameServer_TwoServersOneDead(t *testing.T) {
	nses := testNameServers(2)
	health := newFakeHealthTracker(t)
	health.scores[mustAddr(t, nses[1])] = 1.0
	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 100; i++ {
		queried := make(map[string]struct{})
		var first, second *NameServer
		first, queried = selectNameServer(nses, queried, health, rng)
		second, _ = selectNameServer(nses, queried, health, rng)
		require.Equal(t, nses[0].String(), first.String())
		require.Equal(t, nses[1].String(), second.String())
	}
}

// A single remaining candidate is returned without consulting the tracker
func TestSelectNameServer_SingleCandidateSkipsTracker(t *testing.T) {
	health := newFakeHealthTracker(t)
	health.scoreErr = true
	rng := rand.New(rand.NewSource(1))

	// only one name server
	nses := testNameServers(1)
	ns, _ := selectNameServer(nses, make(map[string]struct{}), health, rng)
	require.Equal(t, nses[0].String(), ns.String())

	// one name server left unqueried in the cycle
	nses = testNameServers(3)
	queried := map[string]struct{}{nses[0].String(): {}, nses[2].String(): {}}
	ns, _ = selectNameServer(nses, queried, health, rng)
	require.Equal(t, nses[1].String(), ns.String())
}

// No repeats within a cycle, every server is queried even when all are failing, then the cycle resets
func TestSelectNameServer_CycleContract(t *testing.T) {
	nses := testNameServers(5)
	allDead := newFakeHealthTracker(t)
	for _, ns := range nses {
		allDead.scores[mustAddr(t, ns)] = 1.0
	}
	for name, health := range map[string]NameServerHealthTracker{"nil tracker": nil, "all dead": allDead} {
		t.Run(name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(1))
			queried := make(map[string]struct{})
			seen := make(map[string]struct{})
			var ns *NameServer
			for i := 0; i < len(nses); i++ {
				ns, queried = selectNameServer(nses, queried, health, rng)
				require.NotContains(t, seen, ns.String(), "repeated within a cycle")
				seen[ns.String()] = struct{}{}
			}
			require.Len(t, seen, len(nses))

			// all queried, the next selection starts a new cycle
			_, queried = selectNameServer(nses, queried, health, rng)
			require.Len(t, queried, 1)
		})
	}
}

// fakeClock is a manually advanced clock for the tracker
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestTracker(t *testing.T) (*TTLNameServerHealthTracker, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1_000_000, 0)}
	tracker := newTTLNameServerHealthTracker(nsHealthAlpha, nsHealthHalfLife, nsHealthTTL, clock.Now)
	t.Cleanup(tracker.cache.Stop)
	return tracker, clock
}

// An IP with no recorded outcomes scores 0, the same as a healthy one
func TestHealthTracker_UnknownIPScoresZero(t *testing.T) {
	tracker, _ := newTestTracker(t)
	require.Zero(t, tracker.score(netip.MustParseAddr("192.0.2.1")))
}

// The first outcome seeds the score unsmoothed, so a first failure registers fully
func TestHealthTracker_FirstOutcomeSeeds(t *testing.T) {
	tracker, _ := newTestTracker(t)
	failing, responding := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	tracker.record(failing, true)
	tracker.record(responding, false)
	require.Equal(t, 1.0, tracker.score(failing))
	require.Equal(t, 0.0, tracker.score(responding))
}

// Later outcomes follow score = α·sample + (1−α)·score, with sample 1 for a failure and 0 for a success
func TestHealthTracker_EWMA(t *testing.T) {
	tracker, _ := newTestTracker(t)
	ip := netip.MustParseAddr("192.0.2.1")
	want := 0.0
	for i, failed := range []bool{true, false, false, true, false, true, true} {
		tracker.record(ip, failed)
		sample := 0.0
		if failed {
			sample = 1.0
		}
		if i == 0 {
			want = sample
		} else {
			want = nsHealthAlpha*sample + (1-nsHealthAlpha)*want
		}
		require.InDelta(t, want, tracker.score(ip), 1e-9, "after outcome %d", i)
	}
}

// Idle decay halves the score per half-life, on reads and before folding in a new outcome
func TestHealthTracker_IdleDecay(t *testing.T) {
	tracker, clock := newTestTracker(t)
	ip := netip.MustParseAddr("192.0.2.1")
	tracker.record(ip, true)

	clock.Advance(nsHealthHalfLife)
	require.InDelta(t, 0.5, tracker.score(ip), 1e-9)
	clock.Advance(nsHealthHalfLife)
	require.InDelta(t, 0.25, tracker.score(ip), 1e-9)

	// a success folds into the decayed score, not the stale one
	tracker.record(ip, false)
	require.InDelta(t, (1-nsHealthAlpha)*0.25, tracker.score(ip), 1e-9)
}

// Entries are evicted after the TTL without outcomes, and reads don't keep them alive
func TestHealthTracker_EvictsAfterTTL(t *testing.T) {
	const ttl = 50 * time.Millisecond
	tracker := newTTLNameServerHealthTracker(nsHealthAlpha, time.Hour, ttl, time.Now)
	t.Cleanup(tracker.cache.Stop)
	ip := netip.MustParseAddr("192.0.2.1")
	tracker.record(ip, true)
	require.InDelta(t, 1.0, tracker.score(ip), 1e-6) // real clock, so a sliver of decay

	require.Eventually(t, func() bool {
		return tracker.score(ip) == 0 && tracker.cache.Len() == 0
	}, 2*time.Second, ttl/5)
}

// The TTL is at least 7 half-lives, so an evicted score had decayed below 1% and eviction doesn't change selection
func TestHealthTracker_TTLOutlastsDecay(t *testing.T) {
	require.GreaterOrEqual(t, nsHealthTTL, 7*nsHealthHalfLife)
}

// One score per IP, whatever the port, and IPv4 isn't split by its IPv4-mapped IPv6 form
func TestHealthTracker_KeyedByIP(t *testing.T) {
	tracker, _ := newTestTracker(t)
	dns53 := NameServer{IP: net.ParseIP("192.0.2.1"), Port: 53}
	dot853 := NameServer{IP: net.ParseIP("192.0.2.1").To4(), Port: 853}
	addr53, addr853 := mustAddr(t, dns53), mustAddr(t, dot853)
	require.Equal(t, addr53, addr853)

	tracker.record(addr53, true)
	require.Equal(t, 1.0, nameServerScore(tracker, &dot853))
	require.Equal(t, 1.0, tracker.score(netip.MustParseAddr("::ffff:192.0.2.1")))
}

// Concurrent records and reads of the same IPs, run under -race
func TestHealthTracker_Concurrent(t *testing.T) {
	tracker := NewNameServerHealthTracker()
	t.Cleanup(tracker.cache.Stop)
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1")}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := ips[(g+i)%len(ips)]
				tracker.record(ip, i%2 == 0)
				score := tracker.score(ip)
				if score < 0 || score > 1 {
					t.Errorf("score %f out of range", score)
				}
			}
		}(g)
	}
	wg.Wait()
}

// The score measures whether a name server responds, not the quality of its answer: no response (timeout or
// transport error) is a failure, any DNS response is a success whatever its RCODE, and an attempt cut short by
// the caller's budget records nothing, since the name server wasn't given its full network timeout
func TestClassifyWireOutcome(t *testing.T) {
	someErr := errors.New("some error")
	tests := []struct {
		name             string
		callerCtxExpired bool
		status           Status
		err              error
		want             wireOutcome
	}{
		{"timeout", false, StatusTimeout, nil, wireOutcomeFailure},
		{"transport error", false, StatusError, someErr, wireOutcomeFailure},
		{"error status without error", false, StatusError, nil, wireOutcomeSuccess},
		{"NOERROR", false, StatusNoError, nil, wireOutcomeSuccess},
		{"NXDOMAIN", false, StatusNXDomain, nil, wireOutcomeSuccess},
		{"SERVFAIL", false, StatusServFail, nil, wireOutcomeSuccess},
		{"REFUSED", false, StatusRefused, nil, wireOutcomeSuccess},
		{"FORMERR", false, StatusFormErr, nil, wireOutcomeSuccess},
		{"truncated with error", false, StatusTruncated, someErr, wireOutcomeSuccess},
		{"caller budget expired, timeout", true, StatusTimeout, nil, wireOutcomeNone},
		{"caller budget expired, error", true, StatusError, someErr, wireOutcomeNone},
		{"caller budget expired, response", true, StatusNoError, nil, wireOutcomeNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classifyWireOutcome(tc.callerCtxExpired, tc.status, tc.err))
		})
	}
}

// startLoopbackDNSServer serves handler over UDP on a free loopback port and returns its address
func startLoopbackDNSServer(t *testing.T, handler dns.HandlerFunc) NameServer {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	server := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() {
		_ = server.ActivateAndServe()
	}()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	return NameServer{IP: addr.IP, Port: uint16(addr.Port)}
}

// rcodeHandler answers every query with rcode, and with an A record for NOERROR
func rcodeHandler(rcode int) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, rcode)
		if rcode == dns.RcodeSuccess {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.53"),
			})
		}
		_ = w.WriteMsg(m)
	}
}

// startBlackHole returns a loopback UDP name server that reads queries and never replies
func startBlackHole(t *testing.T) NameServer {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	return NameServer{IP: addr.IP, Port: uint16(addr.Port)}
}

// newHealthTestResolver returns a resolver for loopback name servers with health tracking through a fake tracker
func newHealthTestResolver(t *testing.T, modify func(*ResolverConfig)) (*Resolver, *fakeHealthTracker) {
	health := newFakeHealthTracker(t)
	config := NewResolverConfig()
	config.ExternalNameServersV4 = []NameServer{{IP: net.ParseIP("127.0.0.1"), Port: 53}}
	config.RootNameServersV4 = []NameServer{{IP: net.ParseIP("127.0.0.1"), Port: 53}}
	config.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
	config.IPVersionMode = IPv4Only
	config.TransportMode = UDPOnly
	config.NetworkTimeout = 200 * time.Millisecond
	config.NameServerHealth = health
	if modify != nil {
		modify(config)
	}
	r, err := InitResolver(config)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return r, health
}

func lookupAgainst(r *Resolver, ctx context.Context, ns NameServer) (Status, error) {
	q := Question{Type: dns.TypeA, Class: dns.ClassINET, Name: "example.com"}
	_, _, status, _, err := r.cachedLookup(ctx, q, &ns, ".", 0, true, true, true, nil)
	return status, err
}

// Outcomes are recorded once per wire attempt, keyed by the name server's IP
func TestCachedLookup_RecordsWireOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		nameServer func(t *testing.T) NameServer
		wantFailed bool
	}{
		{"NOERROR", func(t *testing.T) NameServer { return startLoopbackDNSServer(t, rcodeHandler(dns.RcodeSuccess)) }, false},
		{"SERVFAIL", func(t *testing.T) NameServer { return startLoopbackDNSServer(t, rcodeHandler(dns.RcodeServerFailure)) }, false},
		{"REFUSED", func(t *testing.T) NameServer { return startLoopbackDNSServer(t, rcodeHandler(dns.RcodeRefused)) }, false},
		{"no response", startBlackHole, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, health := newHealthTestResolver(t, nil)
			ns := tc.nameServer(t)
			_, _ = lookupAgainst(r, context.Background(), ns)
			require.Equal(t, []fakeRecord{{ip: mustAddr(t, ns), failed: tc.wantFailed}}, health.getRecords())
		})
	}
}

// Attempts that don't reach the wire record nothing
func TestCachedLookup_NoRecordWithoutWireAttempt(t *testing.T) {
	t.Run("cache hit", func(t *testing.T) {
		r, health := newHealthTestResolver(t, nil)
		ns := startLoopbackDNSServer(t, rcodeHandler(dns.RcodeSuccess))
		status, err := lookupAgainst(r, context.Background(), ns)
		require.NoError(t, err)
		require.Equal(t, StatusNoError, status)
		require.Len(t, health.getRecords(), 1)

		_, _ = lookupAgainst(r, context.Background(), ns)
		require.Len(t, health.getRecords(), 1, "cache hit recorded an outcome")
	})
	t.Run("blacklisted", func(t *testing.T) {
		ns := startBlackHole(t)
		r, health := newHealthTestResolver(t, func(c *ResolverConfig) {
			c.Blacklist = blacklist.New()
			require.NoError(t, c.Blacklist.AddEntry(ns.IP.String()+"/32"))
		})
		status, _ := lookupAgainst(r, context.Background(), ns)
		require.Equal(t, StatusBlacklist, status)
		require.Empty(t, health.getRecords())
	})
	t.Run("invalid name server", func(t *testing.T) {
		r, health := newHealthTestResolver(t, nil)
		status, _ := lookupAgainst(r, context.Background(), NameServer{IP: net.ParseIP("127.0.0.1")})
		require.Equal(t, StatusIllegalInput, status)
		require.Empty(t, health.getRecords())
	})
}

// An attempt cut short by the caller's budget records nothing, even though the wire lookup reports a timeout
func TestCachedLookup_CallerBudgetExpiryRecordsNothing(t *testing.T) {
	r, health := newHealthTestResolver(t, func(c *ResolverConfig) { c.NetworkTimeout = 5 * time.Second })
	ns := startBlackHole(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	status, _ := lookupAgainst(r, ctx, ns)
	require.Equal(t, StatusTimeout, status)
	require.Empty(t, health.getRecords())
}

// With no tracker configured, lookups work as before
func TestCachedLookup_NilTracker(t *testing.T) {
	r, _ := newHealthTestResolver(t, func(c *ResolverConfig) { c.NameServerHealth = nil })
	require.Nil(t, r.nsHealth)
	status, err := lookupAgainst(r, context.Background(), startLoopbackDNSServer(t, rcodeHandler(dns.RcodeSuccess)))
	require.NoError(t, err)
	require.Equal(t, StatusNoError, status)
}
