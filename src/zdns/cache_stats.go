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
	"fmt"
	"sync/atomic"
)

type CacheStatistics struct {
	ShouldCaptureStatistics bool
	Hits                    atomic.Uint64 // number of reads to the cache that result in a hit
	Misses                  atomic.Uint64 // number of reads to the cache that result in a miss
	Adds                    atomic.Uint64 // number of writes to the cache
	Ejects                  atomic.Uint64 // number of cache entries that are ejected due to insertions
}

func (s *Cache) incrementHits() {
	if s.stats.ShouldCaptureStatistics {
		s.stats.Hits.Add(1)
	}
}

func (s *Cache) incrementMisses() {
	if s.stats.ShouldCaptureStatistics {
		s.stats.Misses.Add(1)
	}
}

func (s *Cache) incrementAdds() {
	if s.stats.ShouldCaptureStatistics {
		s.stats.Adds.Add(1)
	}
}

func (s *Cache) incrementEjects() {
	if s.stats.ShouldCaptureStatistics {
		s.stats.Ejects.Add(1)
	}
}

func (s *Cache) PrintStatistics() {
	hits := s.stats.Hits.Load()
	misses := s.stats.Misses.Load()
	adds := s.stats.Adds.Load()
	ejects := s.stats.Ejects.Load()
	total := hits + misses
	hitRate := float64(hits) / float64(total)
	missRate := float64(misses) / float64(total)
	fmt.Printf("Cache statistics: hits=%d misses=%d adds=%d ejects=%d hitRate=%f missRate=%f\n", hits, misses, adds, ejects, hitRate, missRate)
}
