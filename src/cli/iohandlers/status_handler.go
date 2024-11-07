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

package iohandlers

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zdns/src/zdns"
)

// Notes
// time elapsed, domains scanned total, avg. per second, per status entry, ordered largest to smallest

type scanStats struct {
	scanStartTime     time.Time
	domainsScanned    int
	statusCardinality map[zdns.Status]int
}

// statusHandler prints a per-second update to the user scan progress and per-status statistics
func StatusHandler(statusChan <-chan zdns.Status, wg *sync.WaitGroup) {
	stats := scanStats{}
	stats.scanStartTime = time.Now()
	timer := time.Tick(time.Second)
statusLoop:
	for {
		select {
		case <-timer:
			// print per-second summary
			scanDuration := time.Since(stats.scanStartTime)
			fmt.Printf("%s; %d domains scanned; %f domains/sec.; %s\n",
				scanDuration,
				stats.domainsScanned,
				float64(stats.domainsScanned)/scanDuration.Seconds(),
				getStatusOccuranceString(stats.statusCardinality))
		case status, ok := <-statusChan:
			if !ok {
				// TODO check that this syntax is valid
				// status chan closed, exiting
				break statusLoop
			}
			stats.domainsScanned += 1
			incrementStatus(stats, status)
		}
	}
	fmt.Printf("%s; Scan Complete, no more input. %d domains scanned; %f domains/sec.; %s\n",
		time.Since(stats.scanStartTime),
		stats.domainsScanned,
		float64(stats.domainsScanned)/time.Since(stats.scanStartTime).Seconds(),
		getStatusOccuranceString(stats.statusCardinality))
	wg.Done()
}

func incrementStatus(stats scanStats, status zdns.Status) {
	if _, ok := stats.statusCardinality[status]; !ok {
		stats.statusCardinality[status] = 0
	}
	stats.statusCardinality[status] += 1
}

func getStatusOccuranceString(statusOccurances map[zdns.Status]int) string {
	type statusAndCardinality struct {
		status    zdns.Status
		occurance int
	}
	statusesAndCards := make([]statusAndCardinality, 0, len(statusOccurances))
	for status, occurance := range statusOccurances {
		statusesAndCards = append(statusesAndCards, statusAndCardinality{
			status:    status,
			occurance: occurance,
		})
	}
	// TODO Sort these by occurance, largest to smallest
	returnStr := ""
	for _, statusAndOccurance := range statusesAndCards {
		returnStr += fmt.Sprintf("%s: %d, ", statusAndOccurance.status, statusAndOccurance.occurance)
	}
	// remove trailing comma
	returnStr = strings.TrimSuffix(returnStr, ", ")
	return returnStr
}
