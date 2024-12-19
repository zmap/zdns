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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"

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
	Answers      []TimedAnswer
	Authorities  []TimedAnswer
	Additionals  []TimedAnswer
	Flags        DNSFlags
	DNSSECResult *DNSSECResult
}

type TimedAnswer struct {
	Answer    WithBaseAnswer
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
		s.VerboseLog(depth+1, "inserted new cache entry for ", q, " ", nameServer, " is authority: ", isAuthority, " ", result.Answers)
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
	retv.Additionals = make([]interface{}, 0, len(cachedRes.Additionals))
	retv.Flags = cachedRes.Flags
	retv.DNSSECResult = cachedRes.DNSSECResult
	// great we have a result. let's go through the entries and build a result. In the process, throw away anything
	// that's expired
	now := time.Now()
	for _, cachedAnswer := range cachedRes.Answers {
		if cachedAnswer.ExpiresAt.Before(now) {
			partiallyExpired = true
			s.VerboseLog(depth+2, "expiring cache answer ", cachedAnswer.Answer.BaseAns().Name)
		} else {
			retv.Answers = append(retv.Answers, cachedAnswer.Answer)
		}
	}
	for _, cachedAuthority := range cachedRes.Authorities {
		if cachedAuthority.ExpiresAt.Before(now) {
			partiallyExpired = true
			s.VerboseLog(depth+2, "expiring cache authority ", cachedAuthority.Answer.BaseAns().Name)
		} else {
			retv.Authorities = append(retv.Authorities, cachedAuthority.Answer)
		}
	}
	for _, cachedAdditional := range cachedRes.Additionals {
		if cachedAdditional.ExpiresAt.Before(now) {
			partiallyExpired = true
			s.VerboseLog(depth+2, "expiring cache additional ", cachedAdditional.Answer.BaseAns().Name)
		} else {
			retv.Additionals = append(retv.Additionals, cachedAdditional.Answer)
		}
	}
	// Don't return an empty response.
	if len(retv.Answers) == 0 && len(retv.Authorities) == 0 && len(retv.Additionals) == 0 {
		// remove from cache since it's completely expired
		s.IterativeCache.Delete(cacheKey)
		s.VerboseLog(depth+2, "-> no entry found in cache, after expiration for ", cacheKey, ", removing from cache")
		return nil, false, false
	}

	s.VerboseLog(depth+2, "Cache hit for ", q.Name, ": ", *retv)
	return retv, true, partiallyExpired
}

func isCacheableType(ans WithBaseAnswer) bool {
	// only cache records that can help prevent future iteration: A(AAA), NS, (C|D)NAME.
	// This will prevent some entries that will never help future iteration (e.g., PTR)
	// from causing unnecessary cache evictions.
	//// TODO: this is overly broad right now and will unnecessarily cache some leaf A/AAAA records. However,

	rrType := ans.BaseAns().RrType
	return rrType == dns.TypeA || rrType == dns.TypeAAAA || rrType == dns.TypeNS || rrType == dns.TypeDNAME || rrType == dns.TypeCNAME || rrType == dns.TypeDS || rrType == dns.TypeDNSKEY || rrType == dns.TypeNSEC || rrType == dns.TypeNSEC3
}

func (s *Cache) buildCachedResult(res *SingleQueryResult, depth int, layer string) *CachedResult {
	now := time.Now()
	cachedRes := CachedResult{}
	cachedRes.Flags = res.Flags
	cachedRes.DNSSECResult = res.DNSSECResult

	cachedRes.Answers = make([]TimedAnswer, 0, len(res.Answers))
	var getExpirationForSafeAnswer = func(a any) (WithBaseAnswer, time.Time) {
		castAns, ok := a.(WithBaseAnswer)
		if !ok {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: unable to cast to WithBaseAnswer: ", layer, ": ", a)
			return nil, time.Time{}
		}

		if !isCacheableType(castAns) {
			s.VerboseLog(depth+1, "SafeAddCachedAnswer: ignoring non-cacheable type: ", layer, ": ", castAns)
			return nil, time.Time{}
		}

		return castAns, now.Add(time.Duration(castAns.BaseAns().TTL) * time.Second)
	}

	for _, a := range res.Answers {
		castAns, expiresAt := getExpirationForSafeAnswer(a)
		if castAns != nil {
			cachedRes.Answers = append(cachedRes.Answers, TimedAnswer{
				Answer:    castAns,
				ExpiresAt: expiresAt,
			})
		}
	}
	cachedRes.Authorities = make([]TimedAnswer, 0, len(res.Authorities))
	for _, a := range res.Authorities {
		castAns, expiresAt := getExpirationForSafeAnswer(a)
		if castAns != nil {
			cachedRes.Authorities = append(cachedRes.Authorities, TimedAnswer{
				Answer:    castAns,
				ExpiresAt: expiresAt,
			})
		}
	}
	cachedRes.Additionals = make([]TimedAnswer, 0, len(res.Additionals))
	for _, a := range res.Additionals {
		castAns, expiresAt := getExpirationForSafeAnswer(a)
		if castAns != nil {
			cachedRes.Additionals = append(cachedRes.Additionals, TimedAnswer{
				Answer:    castAns,
				ExpiresAt: expiresAt,
			})
		}
	}
	return &cachedRes
}

func (s *Cache) SafeAddCachedAnswer(q Question, res *SingleQueryResult, ns *NameServer, layer string, depth int, cacheNonAuthoritative bool) {
	if res.DNSSECResult != nil && res.DNSSECResult.Status == DNSSECBogus {
		panic("attempting to cache a bogus result")
	}

	nsString := ""
	if ns != nil {
		nsString = ns.String()
	}
	// check for poison
	for _, a := range util.Concat(res.Answers, res.Authorities, res.Additionals) {
		castAns, ok := a.(WithBaseAnswer)
		if !ok {
			// if we can't cast, it won't be added to the cache. We'll log in buildCachedResult
			continue
		}
		baseAns := castAns.BaseAns()
		if ok, _ = nameIsBeneath(baseAns.Name, layer); !ok && baseAns.Type != dns.TypeToString[dns.TypeNSEC3] {
			if len(nsString) > 0 {
				s.VerboseLog(depth+1, "SafeAddCachedAnswer: detected poison: ", baseAns.Name, "(", baseAns.Type, "): @", nsString, ", ", layer, " , aborting")
			} else {
				s.VerboseLog(depth+1, "SafeAddCachedAnswer: detected poison: ", baseAns.Name, "(", baseAns.Type, "): ", layer, " , aborting")
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
	if res.DNSSECResult != nil && res.DNSSECResult.Status == DNSSECBogus {
		panic("attempting to cache a bogus result")
	}

	if len(res.Answers) > 0 {
		// authorities should not have answers
		res.Answers = make([]interface{}, 0)
	}
	authName := ""
	for _, auth := range res.Authorities {
		castAuth, ok := auth.(Answer)
		if !ok {
			// if we can't cast, it won't be added to the cache
			// unless it's DS, NSEC, or NSEC3 (which may be under different names so checking for poison doesn't make sense)
			// We'll log in buildCachedResult
			continue
		}
		currName := strings.ToLower(castAuth.BaseAns().Name)
		if len(authName) == 0 {
			authName = currName
		} else if authName != currName {
			s.VerboseLog(depth+1, "SafeAddCachedAuthority: multiple authority names: ", layer, ": ", authName, " ", currName, " , aborting")
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

	// Referrals may contain DS records in the authority section. These need to be cached under the child name.
	delegateToDSRRs := make(map[string][]interface{})
	var otherRRs []interface{}
	for _, rr := range res.Authorities {
		switch rr := rr.(type) {
		case DSAnswer, NSECAnswer, NSEC3Answer:
			delegateToDSRRs[authName] = append(delegateToDSRRs[authName], rr)
		default:
			otherRRs = append(otherRRs, rr)
		}
	}

	if len(delegateToDSRRs) > 0 {
		s.VerboseLog(depth+1, "SafeAddCachedAuthority: found DS records in authority section, caching under child names")

		// So, it's guaranteed that DNSSEC-related records are secure even the entire response is not.
		// Otherwise the result would be bogus and it won't make it's way here.
		secureDNSSECResult := makeDNSSECResult()
		secureDNSSECResult.Status = DNSSECSecure

		for delegateName, dsRRs := range delegateToDSRRs {
			dsRes := &SingleQueryResult{
				Authorities:        dsRRs,
				Protocol:           res.Protocol,
				Resolver:           res.Resolver,
				Flags:              res.Flags,
				TLSServerHandshake: res.TLSServerHandshake,
				DNSSECResult:       secureDNSSECResult,
			}
			dsRes.Flags.Authoritative = true
			dsCachedRes := s.buildCachedResult(dsRes, depth, layer)
			s.addCachedAnswer(Question{Name: delegateName, Type: dns.TypeDS, Class: dns.ClassINET}, nsString, false, dsCachedRes, depth)
		}
	}

	copiedRes := *res
	copiedRes.Authorities = otherRRs
	cachedRes := s.buildCachedResult(&copiedRes, depth, layer)
	if len(cachedRes.Answers) == 0 && len(cachedRes.Authorities) == 0 && len(cachedRes.Additionals) == 0 {
		s.VerboseLog(depth+1, "SafeAddCachedAnswer: no cacheable records found, aborting")
		return
	}
	s.addCachedAnswer(Question{Name: authName, Type: dns.TypeNS, Class: dns.ClassINET}, nsString, true, cachedRes, depth)
}
