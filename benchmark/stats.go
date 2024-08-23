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
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/src/zdns"
)

// Stats holds the statistics for the benchmark
type Stats struct {
	StartTime             time.Time                // when the benchmark started
	EndTime               time.Time                // when the benchmark ended
	MinResolveTime        time.Duration            // minimum resolution time for a single domain
	MaxResolveTime        time.Duration            // maximum resolution time for a single domain
	AverageResolveTime    time.Duration            // average resolution time for all domains
	TenLongestResolutions map[string]time.Duration // ten longest resolution times and the domain they belong to

	fastestResolveOfLongest time.Duration // fastest resolution time of the ten longest resolutions, used to know if a new resolution time is in the top ten
	numberOfResolutions     int           // number of resolutions, used to calculate rolling average

	SuccessfulResolutions int                    // number of successful resolutions
	TimedOutDomains       []string               // domains that timed out
	FailedDomains         map[string]zdns.Status // domains that failed and why
}

func printStats(s *Stats) {
	// Define the width for alignment
	titleWidth := 60
	timeWidth := 15

	// Print the benchmark duration
	fmt.Printf("%-*s %*v\n", titleWidth, "Benchmark took:", timeWidth, formatTime(s.EndTime.Sub(s.StartTime)))

	// Print the min, max, and average resolution times
	fmt.Printf("%-*s %*v\n", titleWidth, "Min resolution time:", timeWidth, formatTime(s.MinResolveTime))
	fmt.Printf("%-*s %*v\n", titleWidth, "Max resolution time:", timeWidth, formatTime(s.MaxResolveTime))
	fmt.Printf("%-*s %*v\n", titleWidth, "Average resolution time:", timeWidth, formatTime(s.AverageResolveTime))
	fmt.Printf("\n")

	// Print the ten longest resolutions with formatting for alignment
	// Convert the map to a slice of key-value pairs
	type DomainTime struct {
		Domain string
		Time   time.Duration
	}
	sortedResolutions := make([]DomainTime, 0, len(s.TenLongestResolutions))
	for domain, t := range s.TenLongestResolutions {
		sortedResolutions = append(sortedResolutions, DomainTime{domain, t})
	}

	// Sort the slice based on the time in decreasing order
	sort.Slice(sortedResolutions, func(i, j int) bool {
		return sortedResolutions[i].Time > sortedResolutions[j].Time
	})

	fmt.Println("Ten longest resolutions:")
	for _, entry := range sortedResolutions {
		fmt.Printf("\t%-*s %*v\n", titleWidth-8, entry.Domain+":", timeWidth, formatTime(entry.Time))
	}
	fmt.Printf("\n")

	fmt.Printf("%-*s %*v\n", titleWidth, "Domains resolved successfully:", timeWidth, fmt.Sprintf("%d/%d", s.SuccessfulResolutions, linesOfInput))
	if len(s.TimedOutDomains) > 0 {
		fmt.Printf("%-*s %*v\n", titleWidth, "Domains that timed out:", timeWidth, len(s.TimedOutDomains))
		sort.Strings(s.TimedOutDomains)
		for _, domain := range s.TimedOutDomains {
			fmt.Printf("\t%s\n", domain)
		}
		fmt.Printf("\n")
	}
	if len(s.FailedDomains) > 0 {
		type DomainStatus struct {
			Domain string
			Status zdns.Status
		}
		var sortedFailedDomains []DomainStatus
		for domain, status := range s.FailedDomains {
			sortedFailedDomains = append(sortedFailedDomains, DomainStatus{domain, status})
		}
		sort.Slice(sortedFailedDomains, func(i, j int) bool {
			return sortedFailedDomains[i].Domain < sortedFailedDomains[j].Domain
		})

		fmt.Printf("%-*s %*v\n\n", titleWidth, "Domains that failed:", timeWidth, len(s.FailedDomains))
		for _, domainStatus := range sortedFailedDomains {
			fmt.Printf("\t%-*s %*v\n", titleWidth-8, domainStatus.Domain+":", timeWidth, domainStatus.Status)
		}
		fmt.Printf("\n")
	}
}

// formatTime takes a time.Duration and formats it with 2 decimal places
func formatTime(d time.Duration) string {
	decimalPlaces := 2
	switch {
	case d >= time.Second:
		formatStr := fmt.Sprintf("%%.%dfs", decimalPlaces)
		return fmt.Sprintf(formatStr, d.Seconds())
	case d >= time.Millisecond:
		formatStr := fmt.Sprintf("%%.%dfms", decimalPlaces)
		return fmt.Sprintf(formatStr, float64(d.Microseconds())/1000)
	case d >= time.Microsecond:
		formatStr := fmt.Sprintf("%%.%dfµs", decimalPlaces)
		return fmt.Sprintf(formatStr, float64(d.Nanoseconds())/1000)
	default:
		formatStr := fmt.Sprintf("%%.%dfns", decimalPlaces)
		return fmt.Sprintf(formatStr, float64(d.Nanoseconds()))
	}
}

func updateStats(line string, s *Stats) {
	var res zdns.Result
	// parse the line, extracting the domain and resolution time
	// Unmarshal the JSON string into the struct
	err := json.Unmarshal([]byte(line), &res)
	if err != nil {
		log.Panicf("failed to unmarshal JSON (%s): %v", line, err)
	}
	domainName := res.Name
	// TODO - this will only work for a single module benchmark, we'll need to adjust this if we want to benchmark multi-module
	var duration float64
	var status zdns.Status
	for _, moduleResult := range res.Results {
		duration = moduleResult.Duration
		status = zdns.Status(moduleResult.Status)
	}
	resolveTime := time.Duration(duration * float64(time.Second))

	if resolveTime < s.MinResolveTime || s.MinResolveTime == 0 {
		s.MinResolveTime = resolveTime
	}
	if resolveTime > s.MaxResolveTime {
		s.MaxResolveTime = resolveTime
	}
	// Average calculation
	if s.numberOfResolutions == 0 {
		s.AverageResolveTime = resolveTime
	} else {
		s.AverageResolveTime = (s.AverageResolveTime*time.Duration(s.numberOfResolutions) + resolveTime) / time.Duration(s.numberOfResolutions+1)
	}
	// update the ten longest resolutions
	if len(s.TenLongestResolutions) < 10 {
		s.TenLongestResolutions[domainName] = resolveTime
		if resolveTime > s.fastestResolveOfLongest {
			s.fastestResolveOfLongest = resolveTime
		}
	} else if resolveTime > s.fastestResolveOfLongest {
		// find the fastest resolution time of the ten longest resolutions to remove
		minTime := time.Hour
		domainWithFastest := ""
		// find the domain with the fastest resolution time
		for domain, time := range s.TenLongestResolutions {
			if time < minTime {
				domainWithFastest = domain
				minTime = time
			}
		}
		// remove the domain with the fastest resolution time
		delete(s.TenLongestResolutions, domainWithFastest)
		// add the new domain to the ten longest resolutions
		s.TenLongestResolutions[domainName] = resolveTime
	}
	s.numberOfResolutions++

	if status == zdns.StatusNoError {
		s.SuccessfulResolutions++
	} else if status == zdns.StatusTimeout || status == zdns.StatusIterTimeout {
		s.TimedOutDomains = append(s.TimedOutDomains, domainName)
	} else {
		s.FailedDomains[domainName] = status
	}
}
