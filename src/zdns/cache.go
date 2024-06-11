/* ZDNS Copyright 2024 Regents of the University of Michigan
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
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/internal/cachehash"
)

type IsCached bool

type TimedAnswer struct {
	Answer    interface{}
	ExpiresAt time.Time
}

type CachedResult struct {
	Answers map[interface{}]TimedAnswer
}

type Cache struct {
	IterativeCache cachehash.ShardedCacheHash
}

func (s *Cache) Init(cacheSize int) {
	s.IterativeCache.Init(cacheSize, 4096)
}

func (s *Cache) VerboseLog(depth int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth), args)
}

func (s *Cache) AddCachedAnswer(answer interface{}, depth int) {
	a, ok := answer.(Answer)
	if !ok {
		// we can't cache this entry because we have no idea what to name it
		return
	}
	q := questionFromAnswer(a)

	// only cache records that can help prevent future iteration: A(AAA), NS, (C|D)NAME.
	// This will prevent some entries that will never help future iteration (e.g., PTR)
	// from causing unnecessary cache evictions.
	// TODO: this is overly broad right now and will unnecessarily cache some leaf A/AAAA records. However,
	// it's a lot of work to understand _why_ we're doing a specific lookup and this will still help
	// in other cases, e.g., PTR lookups
	if !(q.Type == dns.TypeA || q.Type == dns.TypeAAAA || q.Type == dns.TypeNS || q.Type == dns.TypeDNAME || q.Type == dns.TypeCNAME) {
		return
	}
	expiresAt := time.Now().Add(time.Duration(a.TTL) * time.Second)
	s.IterativeCache.Lock(q)
	defer s.IterativeCache.Unlock(q)
	// don't bother to move this to the top of the linked list. we're going
	// to add this record back in momentarily and that will take care of this
	ca := CachedResult{}
	ca.Answers = make(map[interface{}]TimedAnswer)
	i, ok := s.IterativeCache.GetNoMove(q)
	if ok {
		// record found, check type on interface
		ca, ok = i.(CachedResult)
		if !ok {
			log.Panic("unable to cast cached result")
		}
	}
	// we have an existing record. Let's add this answer to it.
	ta := TimedAnswer{
		Answer:    answer,
		ExpiresAt: expiresAt}
	ca.Answers[a] = ta
	s.IterativeCache.Add(q, ca)
	s.VerboseLog(depth+1, "Upsert cached answer ", q, " ", ca)
}

func (s *Cache) GetCachedResult(q Question, isAuthCheck bool, depth int) (SingleQueryResult, bool) {
	s.VerboseLog(depth+1, "Cache request for: ", q.Name, " (", q.Type, ")")
	var retv SingleQueryResult
	s.IterativeCache.Lock(q)
	unres, ok := s.IterativeCache.Get(q)
	if !ok { // nothing found
		s.VerboseLog(depth+2, "-> no entry found in cache")
		s.IterativeCache.Unlock(q)
		return retv, false
	}
	retv.Authorities = make([]interface{}, 0)
	retv.Answers = make([]interface{}, 0)
	retv.Additional = make([]interface{}, 0)
	cachedRes, ok := unres.(CachedResult)
	if !ok {
		log.Panic("unable to cast cached result")
	}
	// great we have a result. let's go through the entries and build
	// and build a result. In the process, throw away anything that's expired
	now := time.Now()
	for k, cachedAnswer := range cachedRes.Answers {
		if cachedAnswer.ExpiresAt.Before(now) {
			// if we have a write lock, we can perform the necessary actions
			// and then write this back to the cache. However, if we don't,
			// we need to start this process over with a write lock
			s.VerboseLog(depth+2, "Expiring cache entry ", k)
			delete(cachedRes.Answers, k)
		} else {
			// this result is valid. append it to the SingleQueryResult we're going to hand to the user
			if isAuthCheck {
				retv.Authorities = append(retv.Authorities, cachedAnswer.Answer)
			} else {
				retv.Answers = append(retv.Answers, cachedAnswer.Answer)
			}
		}
	}
	s.IterativeCache.Unlock(q)
	// Don't return an empty response.
	if len(retv.Answers) == 0 && len(retv.Authorities) == 0 && len(retv.Additional) == 0 {
		s.VerboseLog(depth+2, "-> no entry found in cache, after expiration")
		var emptyRetv SingleQueryResult
		return emptyRetv, false
	}

	s.VerboseLog(depth+2, "Cache hit: ", retv)
	return retv, true
}

func (s *Cache) SafeAddCachedAnswer(a interface{}, layer string, debugType string, depth int) {
	ans, ok := a.(Answer)
	if !ok {
		s.VerboseLog(depth+1, "unable to cast ", debugType, ": ", layer, ": ", a)
		return
	}
	if ok, _ := nameIsBeneath(ans.Name, layer); !ok {
		log.Info("detected poison ", debugType, ": ", ans.Name, "(", ans.Type, "): ", layer, ": ", a)
		return
	}
	s.AddCachedAnswer(a, depth)
}

func (s *Cache) CacheUpdate(layer string, result SingleQueryResult, depth int) {
	for _, a := range result.Additional {
		s.SafeAddCachedAnswer(a, layer, "additional", depth)
	}
	for _, a := range result.Authorities {
		s.SafeAddCachedAnswer(a, layer, "authority", depth)
	}
	if result.Flags.Authoritative {
		for _, a := range result.Answers {
			s.SafeAddCachedAnswer(a, layer, "answer", depth)
		}
	}
}
