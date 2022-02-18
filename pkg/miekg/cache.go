/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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

package miekg

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/cachehash"
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

func (s *Cache) VerboseGlobalLog(depth int, threadID int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth, threadID), args)
}

func (s *Cache) VerboseLog(depth int, threadID int, args ...interface{}) {
	log.Debug(makeVerbosePrefix(depth, threadID), args)
}

func (s *Cache) AddCachedAnswer(answer interface{}, depth int, threadID int) {
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
	expiresAt := time.Now().Add(time.Duration(a.Ttl) * time.Second)
	s.IterativeCache.Lock(q)
	// don't bother to move this to the top of the linked list. we're going
	// to add this record back in momentarily and that will take care of this
	i, ok := s.IterativeCache.GetNoMove(q)
	ca, ok := i.(CachedResult)
	if !ok && i != nil {
		panic("unable to cast cached result")
	}
	if !ok {
		ca = CachedResult{}
		ca.Answers = make(map[interface{}]TimedAnswer)
	}
	// we have an existing record. Let's add this answer to it.
	ta := TimedAnswer{
		Answer:    answer,
		ExpiresAt: expiresAt}
	ca.Answers[a] = ta
	s.IterativeCache.Add(q, ca)
	s.VerboseGlobalLog(depth+1, threadID, "Add cached answer ", q, " ", ca)
	s.IterativeCache.Unlock(q)
}

func (s *Cache) GetCachedResult(q Question, isAuthCheck bool, depth int, threadID int) (Result, bool) {
	s.VerboseGlobalLog(depth+1, threadID, "Cache request for: ", q.Name, " (", q.Type, ")")
	var retv Result
	s.IterativeCache.Lock(q)
	unres, ok := s.IterativeCache.Get(q)
	if !ok { // nothing found
		s.VerboseGlobalLog(depth+2, threadID, "-> no entry found in cache")
		s.IterativeCache.Unlock(q)
		return retv, false
	}
	retv.Authorities = make([]interface{}, 0)
	retv.Answers = make([]interface{}, 0)
	retv.Additional = make([]interface{}, 0)
	cachedRes, ok := unres.(CachedResult)
	if !ok {
		panic("bad cache entry")
	}
	// great we have a result. let's go through the entries and build
	// and build a result. In the process, throw away anything that's expired
	now := time.Now()
	for k, cachedAnswer := range cachedRes.Answers {
		if cachedAnswer.ExpiresAt.Before(now) {
			// if we have a write lock, we can perform the necessary actions
			// and then write this back to the cache. However, if we don't,
			// we need to start this process over with a write lock
			s.VerboseGlobalLog(depth+2, threadID, "Expiring cache entry ", k)
			delete(cachedRes.Answers, k)
		} else {
			// this result is valid. append it to the Result we're going to hand to the user
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
		s.VerboseGlobalLog(depth+2, threadID, "-> no entry found in cache, after expiration")
		var emptyRetv Result
		return emptyRetv, false
	}

	s.VerboseGlobalLog(depth+2, threadID, "Cache hit: ", retv)
	return retv, true
}

func (s *Cache) SafeAddCachedAnswer(a interface{}, layer string, debugType string, depth int, threadID int) {
	ans, ok := a.(Answer)
	if !ok {
		s.VerboseLog(depth+1, threadID, "unable to cast ", debugType, ": ", layer, ": ", a)
		return
	}
	if ok, _ := nameIsBeneath(ans.Name, layer); !ok {
		log.Info("detected poison ", debugType, ": ", ans.Name, "(", ans.Type, "): ", layer, ": ", a)
		return
	}
	s.AddCachedAnswer(a, depth, threadID)
}

func (s *Cache) CacheUpdate(layer string, result Result, depth int, threadID int) {
	for _, a := range result.Additional {
		s.SafeAddCachedAnswer(a, layer, "additional", depth, threadID)
	}
	for _, a := range result.Authorities {
		s.SafeAddCachedAnswer(a, layer, "authority", depth, threadID)
	}
	if result.Flags.Authoritative == true {
		for _, a := range result.Answers {
			s.SafeAddCachedAnswer(a, layer, "anwer", depth, threadID)
		}
	}
}
