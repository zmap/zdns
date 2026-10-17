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
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

const (
	nsHealthAlpha    = 0.2              // EWMA smoothing factor
	nsHealthHalfLife = 30 * time.Second // idle decay half-life
	nsHealthTTL      = 5 * time.Minute  // eviction after no outcomes; 10 half-lives, so an evicted score has decayed below 0.1%
)

// NameServerHealthTracker records whether nameservers respond and scores them for selection.
// Implementations must be safe for concurrent use, since one tracker is shared by all resolver threads.
type NameServerHealthTracker interface {
	// record folds one on-wire outcome for the nameserver IP into its score
	record(ip netip.Addr, failed bool)
	// score returns the IP's failure score in [0, 1]: 0 is healthy or unknown, 1 is always failing
	score(ip netip.Addr) float64
}

// nsHealth is the failure score of one nameserver IP
type nsHealth struct {
	mu         sync.Mutex
	score      float64   // EWMA of failure, as of lastRecord
	lastRecord time.Time // time of the last recorded outcome, decay is measured from here
}

// TTLNameServerHealthTracker keeps a per-IP exponentially weighted moving average of failure, decaying lazily
// toward healthy while an IP is idle. Entries are evicted after a TTL with no outcomes to bound memory.
type TTLNameServerHealthTracker struct {
	alpha    float64
	halfLife time.Duration
	now      func() time.Time
	cache    *ttlcache.Cache[netip.Addr, *nsHealth]
}

func NewNameServerHealthTracker() *TTLNameServerHealthTracker {
	return newTTLNameServerHealthTracker(nsHealthAlpha, nsHealthHalfLife, nsHealthTTL, time.Now)
}

func newTTLNameServerHealthTracker(alpha float64, halfLife, ttl time.Duration, now func() time.Time) *TTLNameServerHealthTracker {
	t := &TTLNameServerHealthTracker{
		alpha:    alpha,
		halfLife: halfLife,
		now:      now,
		cache: ttlcache.New[netip.Addr, *nsHealth](
			ttlcache.WithTTL[netip.Addr, *nsHealth](ttl),
			// only recorded outcomes keep an entry alive, reads must not
			ttlcache.WithDisableTouchOnHit[netip.Addr, *nsHealth](),
		),
	}
	go t.cache.Start() // starts automatic expired item deletion
	return t
}

func (t *TTLNameServerHealthTracker) record(ip netip.Addr, failed bool) {
	ip = ip.Unmap()
	sample := 0.0
	if failed {
		sample = 1.0
	}
	item, found := t.cache.GetOrSet(ip, &nsHealth{})
	t.cache.Touch(ip)
	h := item.Value()
	now := t.now()

	h.mu.Lock()
	defer h.mu.Unlock()
	if !found {
		// the first outcome seeds the score, otherwise one failure against a zero seed would barely register
		h.score = sample
	} else {
		h.score = t.alpha*sample + (1-t.alpha)*t.decay(h.score, now.Sub(h.lastRecord))
	}
	h.lastRecord = now
}

func (t *TTLNameServerHealthTracker) score(ip netip.Addr) float64 {
	item := t.cache.Get(ip.Unmap())
	if item == nil {
		return 0
	}
	h := item.Value()
	h.mu.Lock()
	defer h.mu.Unlock()
	return t.decay(h.score, t.now().Sub(h.lastRecord))
}

// decay halves the score for every half-life of idleness
func (t *TTLNameServerHealthTracker) decay(score float64, idle time.Duration) float64 {
	if idle <= 0 {
		return score
	}
	return score * math.Exp2(-float64(idle)/float64(t.halfLife))
}
