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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zdns/src/zdns"
)

// Notes
// time elapsed, domains scanned total, avg. per second, per status entry, ordered largest to smallest

type scanStats struct {
	scanStartTime   time.Time
	domainsScanned  int
	statusOccurance map[zdns.Status]int
}

// statusHandler prints a per-second update to the user scan progress and per-status statistics
func StatusHandler(statusChan <-chan zdns.Status, wg *sync.WaitGroup) {
	stats := scanStats{
		statusOccurance: make(map[zdns.Status]int),
		scanStartTime:   time.Now(),
	}
	ticker := time.NewTicker(time.Second)
statusLoop:
	for {
		select {
		case <-ticker.C:
			// print per-second summary
			timeSinceStart := time.Since(stats.scanStartTime)
			fmt.Printf("%02dh:%02dm:%02ds; %d domains scanned; %.02f domains/sec.; %s\n",
				int(timeSinceStart.Hours()),
				int(timeSinceStart.Minutes())%60,
				int(timeSinceStart.Seconds())%60,
				stats.domainsScanned,
				float64(stats.domainsScanned)/timeSinceStart.Seconds(),
				getStatusOccuranceString(stats.statusOccurance))
		case status, ok := <-statusChan:
			if !ok {
				// status chan closed, exiting
				break statusLoop
			}
			stats.domainsScanned += 1
			incrementStatus(stats, status)
		}
	}
	timeSinceStart := time.Since(stats.scanStartTime)
	fmt.Printf("%02dh:%02dm:%02ds; Scan Complete, no more input. %d domains scanned; %.02f domains/sec.; %s\n",
		int(timeSinceStart.Hours()),
		int(timeSinceStart.Minutes())%60,
		int(timeSinceStart.Seconds())%60,
		stats.domainsScanned,
		float64(stats.domainsScanned)/time.Since(stats.scanStartTime).Seconds(),
		getStatusOccuranceString(stats.statusOccurance))
	wg.Done()
}

func incrementStatus(stats scanStats, status zdns.Status) {
	if _, ok := stats.statusOccurance[status]; !ok {
		stats.statusOccurance[status] = 0
	}
	stats.statusOccurance[status] += 1
}

func getStatusOccuranceString(statusOccurances map[zdns.Status]int) string {
	type statusAndOccurance struct {
		status    zdns.Status
		occurance int
	}
	statusesAndOccurances := make([]statusAndOccurance, 0, len(statusOccurances))
	for status, occurance := range statusOccurances {
		statusesAndOccurances = append(statusesAndOccurances, statusAndOccurance{
			status:    status,
			occurance: occurance,
		})
	}
	// sort by occurance
	sort.Slice(statusesAndOccurances, func(i, j int) bool {
		return statusesAndOccurances[i].occurance > statusesAndOccurances[j].occurance
	})
	returnStr := ""
	for _, statusOccurance := range statusesAndOccurances {
		returnStr += fmt.Sprintf("%s: %d, ", statusOccurance.status, statusOccurance.occurance)
	}
	// remove trailing comma
	returnStr = strings.TrimSuffix(returnStr, ", ")
	return returnStr
}
