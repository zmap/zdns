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
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.org/x/time/rate"
)

// The benchmarks below measure the cost the shared health tracker adds per query, and how it scales with goroutines
// contending on it. Run with -cpu to vary contention, e.g.
//
//	go test ./src/zdns -run '^$' -bench 'PerQuery|NameServerSelection' -cpu 1,4,8,16
//
// BenchmarkRateLimiterPerQuery is the baseline: the rate limiter is always on, also a shared ttlcache, and already
// on the hot path of every query.

// benchNameServers returns n distinct name servers with names, spread over 10.0.0.0/8
func benchNameServers(n int) []NameServer {
	nses := make([]NameServer, n)
	for i := range nses {
		nses[i] = NameServer{
			IP:         net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
			Port:       53,
			DomainName: fmt.Sprintf("ns%d.example.com", i),
		}
	}
	return nses
}

// benchNameServerCounts are the root servers (few IPs, every goroutine hits the same entries) and a scan's
// authoritative servers (many IPs, little per-entry contention)
var benchNameServerCounts = []int{13, 10_000}

// benchSeed gives each parallel goroutine its own deterministic random source
var benchSeed atomic.Int64

// One iteration is the tracker's work for one query: selection reads two scores, then the outcome is recorded.
// One outcome in ten is a failure.
func BenchmarkHealthTrackerPerQuery(b *testing.B) {
	for _, n := range benchNameServerCounts {
		b.Run(fmt.Sprintf("ips=%d", n), func(b *testing.B) {
			tracker := NewNameServerHealthTracker()
			b.Cleanup(tracker.cache.Stop)
			addrs := make([]netip.Addr, n)
			for i, ns := range benchNameServers(n) {
				addrs[i], _ = nameServerAddr(&ns)
			}
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(benchSeed.Add(1)))
				for i := 0; pb.Next(); i++ {
					first, second := addrs[rng.Intn(n)], addrs[rng.Intn(n)]
					chosen := first
					if tracker.score(second) < tracker.score(first) {
						chosen = second
					}
					tracker.record(chosen, i%10 == 0)
				}
			})
		})
	}
}

// One iteration is the rate limiter's work for one query at the CLI default of no limit
func BenchmarkRateLimiterPerQuery(b *testing.B) {
	for _, n := range benchNameServerCounts {
		b.Run(fmt.Sprintf("ips=%d", n), func(b *testing.B) {
			limiter := NewNameServerRateLimiter(rate.Inf, rate.Inf)
			nses := benchNameServers(n)
			ctx := context.Background()
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(benchSeed.Add(1)))
				for pb.Next() {
					if err := limiter.wait(ctx, nses[rng.Intn(n)]); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// Selection of the next name server in an iterative step among the 13 root servers, without and with a tracker
func BenchmarkNameServerSelection(b *testing.B) {
	nses := benchNameServers(13)
	tracker := NewNameServerHealthTracker()
	b.Cleanup(tracker.cache.Stop)
	// a realistic mix of scores: most healthy, a few failing
	for i, ns := range nses {
		addr, _ := nameServerAddr(&ns)
		tracker.record(addr, i%5 == 0)
	}
	for _, tc := range []struct {
		name   string
		health NameServerHealthTracker
	}{
		{"tracker=nil", nil},
		{"tracker=ttl", tracker},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				queried := make(map[string]struct{}, len(nses))
				for pb.Next() {
					_, queried = selectNameServer(nses, queried, tc.health, nil)
				}
			})
		})
	}
}
