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
	shouldCaptureStatistics bool
	hits                    atomic.Uint64 // number of reads to the cache that result in a hit
	misses                  atomic.Uint64 // number of reads to the cache that result in a miss
	adds                    atomic.Uint64 // number of writes to the cache
	ejects                  atomic.Uint64 // number of cache entries that are ejected due to insertions
}

func (s *CacheStatistics) IncrementHits() {
	if s.shouldCaptureStatistics {
		s.hits.Add(1)
	}
}

func (s *CacheStatistics) CaptureStatistics() {
	s.shouldCaptureStatistics = true
}

func (s *CacheStatistics) IncrementMisses() {
	if s.shouldCaptureStatistics {
		s.misses.Add(1)
	}
}

func (s *CacheStatistics) IncrementAdds() {
	if s.shouldCaptureStatistics {
		s.adds.Add(1)
	}
}

func (s *CacheStatistics) IncrementEjects() {
	if s.shouldCaptureStatistics {
		s.ejects.Add(1)
	}
}

func (s *CacheStatistics) PrintStatistics() {
	hits := s.hits.Load()
	misses := s.misses.Load()
	adds := s.adds.Load()
	ejects := s.ejects.Load()
	total := hits + misses
	hitRate := float64(hits) / float64(total)
	missRate := float64(misses) / float64(total)
	fmt.Printf("Cache statistics: hits=%d misses=%d adds=%d ejects=%d hitRate=%f%% missRate=%f%%\n", hits, misses, adds, ejects, hitRate*100, missRate*100)
}
