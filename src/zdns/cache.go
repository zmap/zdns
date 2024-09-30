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
	"github.com/zmap/zdns/src/internal/util"
)

type IsCached bool

type CachedKey struct {
	Question    Question
	NameServer  string // optional
	IsAuthority bool
}

type CachedResult struct {
	Answers     []TimedAnswer
	Authorities []TimedAnswer
	Additionals []TimedAnswer
}

type TimedAnswer struct {
	Answer    Answer
	ExpiresAt time.Time
}

type Cache struct {
	IterativeCache cachehash.ShardedCacheHash
	Stats          CacheStatistics
}

// Init initializes the cache with a maximum cacheSize.
func (s *Cache) Init(cacheSize int) {
	s.IterativeCache.Init(cacheSize, 4096)
}

func (s *Cache) VerboseLog(depth int, args ...interface{}) {
	// the makeVerbosePrefix is expensive, so only do it if we're going to log
	if log.GetLevel() >= log.DebugLevel {
		log.Debug(makeVerbosePrefix(depth), args)
	}
}

func (s *Cache) addCachedAnswer(q Question, nameServer string, isAuthority bool, result *CachedResult, depth int) {
	cacheKey := CachedKey{q, nameServer, isAuthority}
	s.IterativeCache.Lock(cacheKey)
	// this record will replace any existing record with the exact same cache key
	didExist, didEject := s.IterativeCache.Add(cacheKey, *result)
	s.IterativeCache.Unlock(cacheKey)
	if didExist && didEject {
		log.Panic("cache entry shouldn't be both replaced and evicted: ", q, " ", nameServer, " ", isAuthority)
	} else if didExist {
		s.VerboseLog(depth+1, "replaced existing cache entry for ", q, " ", nameServer, " is authority: ", isAuthority)
	} else if didEject {
		s.VerboseLog(depth+1, "inserting cache entry caused eviction, entry: ", q, " ", nameServer, " is authority: ", isAuthority)
	} else {
		s.VerboseLog(depth+1, "inserted new cache entry for ", q, " ", nameServer, " is authority: ", isAuthority)
	}
	if didEject {
		s.Stats.IncrementEjects()
	}
	s.Stats.IncrementAdds()
}

func (s *Cache) GetCachedAuthority(authorityName string, ns *NameServer, depth int) (retv *SingleQueryResult, isFound bool) {
	retv, isFound, partiallyExpired := s.getCachedResult(Question{Name: authorityName, Type: dns.TypeNS, Class: dns.ClassINET}, ns, true, depth)
	if partiallyExpired {
		// if the authority is partially expired, we'll re-query it and update the cache. This prevents a cache with only part of a non-expired answer
		return nil, false
	}
	return retv, isFound
}

func (s *Cache) GetCachedResults(q Question, ns *NameServer, depth int) (retv *SingleQueryResult, isFound bool) {
	retv, isFound, partiallyExpired := s.getCachedResult(q, ns, false, depth)
	if partiallyExpired {
		// if the authority is partially expired, we'll re-query it and update the cache. This prevents a cache with only part of a non-expired answer
		return nil, false
	}
	return retv, isFound
}

func (s *Cache) getCachedResult(q Question, ns *NameServer, isAuthority bool, depth int) (retv *SingleQueryResult, isFound, partiallyExpired bool) {
	retv = &SingleQueryResult{}
	isFound = false
	partiallyExpired = false
	cacheKey := CachedKey{q, "", isAuthority}
	if ns != nil {
		cacheKey.NameServer = ns.String()
		retv.Resolver = ns.String()
		if isAuthority {
			s.VerboseLog(depth+1, "Cache authority request for: ", q.Name, " (", q.Type, ") @", cacheKey.NameServer)
		} else {
			s.VerboseLog(depth+1, "Cache request for: ", q.Name, " (", q.Type, ") @", cacheKey.NameServer)
		}
	} else if isAuthority {
		s.VerboseLog(depth+1, "Cache authority request for: ", q.Name, " (", q.Type, ")")
	} else {
		s.VerboseLog(depth+1, "Cache request for: ", q.Name, " (", q.Type, ")")
	}
	s.IterativeCache.Lock(cacheKey)
	defer s.IterativeCache.Unlock(cacheKey)
	unres, ok := s.IterativeCache.Get(cacheKey)
	if !ok { // nothing found
		s.VerboseLog(depth+2, "-> no entry found in cache for ", q.Name)
		s.Stats.IncrementMisses()
		return retv, false, false
	}
	s.Stats.IncrementHits()
	cachedRes, ok := unres.(CachedResult)
	if !ok {
		log.Panic("unable to cast cached result for ", q.Name)
	}
	retv = new(SingleQueryResult)
	retv.Answers = make([]interface{}, 0, len(cachedRes.Answers))
	retv.Authorities = make([]interface{}, 0, len(cachedRes.Authorities))
	retv.Additional = make([]interface{}, 0, len(cachedRes.Additionals))
	// great we have a result. let's go through the entries and build a result. In the process, throw away anything
	// that's expired
	now := time.Now()
	for _, cachedAnswer := range cachedRes.Answers {
		if cachedAnswer.ExpiresAt.Before(now) {
			partiallyExpired = true
			s.VerboseLog(depth+2, "expiring cache answer ", cachedAnswer.Answer.Name)
		} else {
			retv.Answers = append(retv.Answers, cachedAnswer.Answer)
		}
	}
	for _, cachedAuthority := range cachedRes.Authorities {
		if cachedAuthority.ExpiresAt.Before(now) {
			partiallyExpired = true
			s.VerboseLog(depth+2, "expiring cache authority ", cachedAuthority.Answer.Name)
		} else {
			retv.Authorities = append(retv.Authorities, cachedAuthority.Answer)
		}
	}
	for _, cachedAdditional := range cachedRes.Additionals {
		if cachedAdditional.ExpiresAt.Before(now) {
			partiallyExpired = true
			s.VerboseLog(depth+2, "expiring cache additional ", cachedAdditional.Answer.Name)
		} else {
			retv.Additional = append(retv.Additional, cachedAdditional.Answer)
		}
	}
	// Don't return an empty response.
	if len(retv.Answers) == 0 && len(retv.Authorities) == 0 && len(retv.Additional) == 0 {
		// remove from cache since it's completely expired
		s.IterativeCache.Delete(cacheKey)
		s.VerboseLog(depth+2, "-> no entry found in cache, after expiration for ", cacheKey, ", removing from cache")
		return nil, false, false
	}

	s.VerboseLog(depth+2, "Cache hit for ", q.Name, ": ", retv)
	return retv, true, partiallyExpired
}

func isCacheableType(ans *Answer) bool {
	// only cache records that can help prevent future iteration: A(AAA), NS, (C|D)NAME.
	// This will prevent some entries that will never help future iteration (e.g., PTR)
	// from causing unnecessary cache evictions.
	//// TODO: this is overly broad right now and will unnecessarily cache some leaf A/AAAA records. However,
	return ans.RrType == dns.TypeA || ans.RrType == dns.TypeAAAA || ans.RrType == dns.TypeNS || ans.RrType == dns.TypeDNAME || ans.RrType == dns.TypeCNAME
}

func (s *Cache) buildCachedResult(res *SingleQueryResult, depth int, layer string) *CachedResult {
	now := time.Now()
	cachedRes := CachedResult{}
	cachedRes.Answers = make([]TimedAnswer, 0, len(res.Answers))
	for _, a := range res.Answers {
		castAns, ok := a.(Answer)
		if !ok {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: unable to cast to Answer: ", layer, ": ", a)
			continue
		}
		if !isCacheableType(&castAns) {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: ignoring non-cacheable type: ", layer, ": ", castAns)
			continue
		}
		cachedRes.Answers = append(cachedRes.Answers, TimedAnswer{
			Answer:    castAns,
			ExpiresAt: now.Add(time.Duration(castAns.TTL) * time.Second),
		})
	}
	cachedRes.Authorities = make([]TimedAnswer, 0, len(res.Authorities))
	for _, a := range res.Authorities {
		castAns, ok := a.(Answer)
		if !ok {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: unable to cast to Answer: ", layer, ": ", a)
			continue
		}
		if !isCacheableType(&castAns) {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: ignoring non-cacheable type: ", layer, ": ", castAns)
			continue
		}
		cachedRes.Authorities = append(cachedRes.Authorities, TimedAnswer{
			Answer:    castAns,
			ExpiresAt: now.Add(time.Duration(castAns.TTL) * time.Second),
		})
	}
	cachedRes.Additionals = make([]TimedAnswer, 0, len(res.Additional))
	for _, a := range res.Additional {
		castAns, ok := a.(Answer)
		if !ok {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: unable to cast to Answer: ", layer, ": ", a)
			continue
		}
		if !isCacheableType(&castAns) {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: ignoring non-cacheable type: ", layer, ": ", castAns)
			continue
		}
		cachedRes.Additionals = append(cachedRes.Additionals, TimedAnswer{
			Answer:    castAns,
			ExpiresAt: now.Add(time.Duration(castAns.TTL) * time.Second),
		})
	}
	return &cachedRes
}

func (s *Cache) SafeAddCachedAnswer(q Question, res *SingleQueryResult, ns *NameServer, layer string, depth int, cacheNonAuthoritative bool) {
	nsString := ""
	if ns != nil {
		nsString = ns.String()
	}
	// check for poison
	for _, a := range util.Concat(res.Answers, res.Authorities, res.Additional) {
		castAns, ok := a.(Answer)
		if !ok {
			// if we can't cast, it won't be added to the cache. We'll log in buildCachedResult
			continue
		}
		if ok, _ = nameIsBeneath(castAns.Name, layer); !ok {
			if len(nsString) > 0 {
				s.VerboseLog(depth+1, "SafeAddCachedAnswer: detected poison: ", castAns.Name, "(", castAns.Type, "): @", nsString, ", ", layer, " , aborting")
			} else {
				s.VerboseLog(depth+1, "SafeAddCachedAnswer: detected poison: ", castAns.Name, "(", castAns.Type, "): ", layer, " , aborting")
			}
			return
		}
	}

	if !res.Flags.Authoritative && !cacheNonAuthoritative {
		// don't want to cache non-authoritative responses
		if len(nsString) > 0 {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: aborting since response is non-authoritative: ", q, " @", nsString)
		} else {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: aborting since response is non-authoritative: ", q)
		}
		return
	}
	cachedRes := s.buildCachedResult(res, depth, layer)
	if len(cachedRes.Answers) == 0 && len(cachedRes.Authorities) == 0 && len(cachedRes.Additionals) == 0 {
		s.VerboseLog(depth+1, "SafeAddCachedAnswer: no cacheable records found, aborting")
		return
	}
	s.addCachedAnswer(q, nsString, false, cachedRes, depth)
}

// SafeAddCachedAuthority Writes an authority to the cache. This is a special case where the result should only have
// authorities and additionals records. What layer this authority is for is gathered from the Authority.Name field.
// This Authority.Name must be below the current layer.
// Will be cached under an NS record for the authority.
func (s *Cache) SafeAddCachedAuthority(res *SingleQueryResult, ns *NameServer, depth int, layer string) {
	if len(res.Answers) > 0 {
		// authorities should not have answers
		res.Answers = make([]interface{}, 0)
	}
	authName := ""
	for _, auth := range res.Authorities {
		castAuth, ok := auth.(Answer)
		if !ok {
			// if we can't cast, it won't be added to the cache. We'll log in buildCachedResult
			continue
		}
		if len(authName) == 0 {
			authName = castAuth.Name
		} else if authName != castAuth.Name {
			s.VerboseLog(depth+1, "SafeAddCachedAuthority: multiple authority names: ", layer, ": ", authName, " ", castAuth.Name, " , aborting")
			return
		}
	}
	// check for poison
	if ok, _ := nameIsBeneath(authName, layer); !ok {
		s.VerboseLog(depth+1, "SafeAddCachedAuthority: detected poison: ", authName, "(", dns.TypeNS, "): ", layer, " , aborting")
		return
	}
	nsString := ""
	if ns != nil {
		nsString = ns.String()
	}

	cachedRes := s.buildCachedResult(res, depth, layer)
	if len(cachedRes.Answers) == 0 && len(cachedRes.Authorities) == 0 && len(cachedRes.Additionals) == 0 {
		s.VerboseLog(depth+1, "SafeAddCachedAnswer: no cacheable records found, aborting")
		return
	}
	s.addCachedAnswer(Question{Name: authName, Type: dns.TypeNS, Class: dns.ClassINET}, nsString, true, cachedRes, depth)
}
