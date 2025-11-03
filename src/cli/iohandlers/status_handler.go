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
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/v2/src/internal/util"
	"github.com/zmap/zdns/v2/src/zdns"
)

type StatusHandler struct {
	filePath string
}

type scanStats struct {
	scanStartTime   time.Time
	domainsScanned  int
	domainsSuccess  int // number of domains that returned either NXDOMAIN or NOERROR
	statusOccurance map[zdns.Status]int
}

func NewStatusHandler(filePath string) *StatusHandler {
	return &StatusHandler{
		filePath: filePath,
	}
}

// LogPeriodicUpdates prints a per-second update to the user scan progress and per-status statistics
func (h *StatusHandler) LogPeriodicUpdates(statusChan <-chan zdns.Status, statusAbortChan <-chan struct{}, wg *sync.WaitGroup) error {
	defer wg.Done()
	// open file for writing
	var f *os.File
	if h.filePath == "" || h.filePath == "-" {
		f = os.Stderr
	} else {
		// open file for writing
		var err error
		f, err = os.OpenFile(h.filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, util.DefaultFilePermissions)
		if err != nil {
			return errors.Wrap(err, "unable to open status file")
		}
		defer func(f *os.File) {
			if err := f.Close(); err != nil {
				log.Errorf("unable to close status file: %v", err)
			}
		}(f)
	}
	if err := h.statusLoop(statusChan, statusAbortChan, f); err != nil {
		return errors.Wrap(err, "error encountered in status loop")
	}
	return nil
}

// statusLoop will print a per-second summary of the scan progress and per-status statistics
// statusChan is a channel that will receive the statuses from each lookup and updates it's internal state stats
// statusAbortChan is used for the main thread to notify the status loop that it has aborted and we should notify the
// user appropriately
// statusFile is where to write the status updates to
func (h *StatusHandler) statusLoop(statusChan <-chan zdns.Status, statusAbortChan <-chan struct{}, statusFile *os.File) error {
	// initialize stats
	stats := scanStats{
		statusOccurance: make(map[zdns.Status]int),
		scanStartTime:   time.Now(),
	}
	ticker := time.NewTicker(time.Second)
	scanAborted := false
statusLoop:
	for {
		select {
		case <-ticker.C:
			// print per-second summary
			timeSinceStart := time.Since(stats.scanStartTime)
			s := fmt.Sprintf("%02dh:%02dm:%02ds; %d names scanned; %.02f names/sec; %.01f%% success rate; %s\n",
				int(timeSinceStart.Hours()),
				int(timeSinceStart.Minutes())%60,
				int(timeSinceStart.Seconds())%60,
				stats.domainsScanned,
				float64(stats.domainsScanned)/timeSinceStart.Seconds(),
				float64(stats.domainsSuccess*100)/float64(stats.domainsScanned),
				getStatusOccurrenceString(stats.statusOccurance))
			if _, err := statusFile.WriteString(s); err != nil {
				return errors.Wrap(err, "unable to write periodic status update")
			}
		case status, ok := <-statusChan:
			if !ok {
				// status chan closed, exiting
				break statusLoop
			}
			stats.domainsScanned += 1
			if status == zdns.StatusNoError || status == zdns.StatusNXDomain {
				stats.domainsSuccess += 1
			}
			if _, ok = stats.statusOccurance[status]; !ok {
				// initialize status if not seen before
				stats.statusOccurance[status] = 0
			}
			stats.statusOccurance[status] += 1
		case _, ok := <-statusAbortChan:
			if ok {
				// We can't exit the loop here because the lookup threads will block on writing to the status channel.
				// Instead, we'll set a flag and when we break out of this loop later (because the status channel is closed)
				// we'll print an abort message for the user.
				scanAborted = true
			}
		}
	}
	scanStateString := "Scan Complete"
	if scanAborted {
		scanStateString = "Scan Aborted"
	}

	timeSinceStart := time.Since(stats.scanStartTime)
	s := fmt.Sprintf("%02dh:%02dm:%02ds; %s; %d names scanned; %.02f names/sec; %.01f%% success rate; %s\n",
		int(timeSinceStart.Hours()),
		int(timeSinceStart.Minutes())%60,
		int(timeSinceStart.Seconds())%60,
		scanStateString,
		stats.domainsScanned,
		float64(stats.domainsScanned)/time.Since(stats.scanStartTime).Seconds(),
		float64(stats.domainsSuccess*100)/float64(stats.domainsScanned),
		getStatusOccurrenceString(stats.statusOccurance))
	if _, err := statusFile.WriteString(s); err != nil {
		return errors.Wrap(err, "unable to write final status update")
	}
	return nil
}

func getStatusOccurrenceString(statusOccurrences map[zdns.Status]int) string {
	type statusAndOccurrence struct {
		status     zdns.Status
		occurrence int
	}
	statusesAndOccurrences := make([]statusAndOccurrence, 0, len(statusOccurrences))
	for status, occurrence := range statusOccurrences {
		statusesAndOccurrences = append(statusesAndOccurrences, statusAndOccurrence{
			status:     status,
			occurrence: occurrence,
		})
	}
	// sort by occurrence
	sort.Slice(statusesAndOccurrences, func(i, j int) bool {
		return statusesAndOccurrences[i].occurrence > statusesAndOccurrences[j].occurrence
	})
	strSlice := make([]string, 0, len(statusesAndOccurrences)) // we'll use a slice to avoid reallocating strings
	for _, statusOccurrence := range statusesAndOccurrences {
		strSlice = append(strSlice, fmt.Sprintf("%s: %d, ", statusOccurrence.status, statusOccurrence.occurrence))
	}
	returnStr := strings.Join(strSlice, "")
	// remove trailing comma
	returnStr = strings.TrimSuffix(returnStr, ", ")
	return returnStr
}
