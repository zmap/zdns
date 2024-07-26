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
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"
	"io"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"time"

	"github.com/zmap/zdns/src/zdns"
)

const (
	linesOfInput = 10 // number of lines to read from input file to feed to ZDNS
	ZDNSThreads  = 10
)

func feedZDNS(inputLines int, stdin io.WriteCloser) {
	// read in input to stdin
	go func() {
		f, err := os.Open("10k_domains.input")
		if err != nil {
			log.Panicf("failed to open input file: %v", err)
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				log.Panicf("failed to close input file: %v", err)
			}
		}(f)
		defer func(stdin io.WriteCloser) {
			err := stdin.Close()
			if err != nil {
				log.Panicf("failed to close stdin: %v", err)
			}
		}(stdin)
		// Create a new scanner
		scanner := bufio.NewScanner(f)

		// Read the file line by line
		linesRead := 0
		for scanner.Scan() {
			if linesRead >= inputLines {
				break
			}
			linesRead++
			line := scanner.Text() // Get the current line as a string
			_, err = stdin.Write([]byte(line + "\n"))
			if err != nil {
				log.Panicf("failed to write (%v) to stdin: %v", line, err)
			}
		}
	}()
}

type Stats struct {
	StartTime             time.Time                // when the benchmark started
	MinResolveTime        time.Duration            // minimum resolution time for a single domain
	MaxResolveTime        time.Duration            // maximum resolution time for a single domain
	AverageResolveTime    time.Duration            // average resolution time for all domains
	TenLongestResolutions map[string]time.Duration // ten longest resolution times and the domain they belong to

	fastestResolveOfLongest time.Duration // fastest resolution time of the ten longest resolutions, used to know if a new resolution time is in the top ten
	numberOfResolutions     int           // number of resolutions, used to calculate rolling average
}

func printStats(s *Stats) {
	// Define the width for alignment
	titleWidth := 40
	timeWidth := 15

	// Print the benchmark duration
	fmt.Printf("%-*s %*v\n", titleWidth, "Benchmark took:", timeWidth, time.Since(s.StartTime))

	// Print the min, max, and average resolution times
	fmt.Printf("%-*s %*v\n", titleWidth, "Min resolution time:", timeWidth, s.MinResolveTime)
	fmt.Printf("%-*s %*v\n", titleWidth, "Max resolution time:", timeWidth, s.MaxResolveTime)
	fmt.Printf("%-*s %*v\n", titleWidth, "Average resolution time:", timeWidth, s.AverageResolveTime)

	// Print the ten longest resolutions with formatting for alignment
	fmt.Println("Ten longest resolutions:")
	for domain, t := range s.TenLongestResolutions {
		fmt.Printf("\t%-*s %*v\n", titleWidth-8, domain+":", timeWidth, t)
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
	resolveTime := time.Duration(res.Duration * float64(time.Second))

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
}

func processOutput(stdout io.ReadCloser, s *Stats) {
	go func() {
		// update user with progress of benchmark
		bar := progressbar.Default(linesOfInput)
		bar.Describe(fmt.Sprintf("Benchmarking ZDNS, Resolving %d domains...", linesOfInput))
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if err := bar.Add(1); err != nil {
				log.Panicf("failed to update progress bar: %v", err)
			}
			updateStats(scanner.Text(), s)
		}
	}()
}

func main() {
	s := Stats{
		StartTime:             time.Now(),
		TenLongestResolutions: make(map[string]time.Duration, 10),
		numberOfResolutions:   0,
	}
	// ZDNS can start a pprof server if the ZDNS_PPROF environment variable is set
	if err := os.Setenv("ZDNS_PPROF", "true"); err != nil {
		log.Panicf("failed to set ZDNS_PPROF environment variable: %v", err)
	}

	cmd := exec.Command("../zdns", "A", "--iterative", "--verbosity=3", "--threads", fmt.Sprintf("%d", ZDNSThreads))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Panicf("failed to create stdin pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Panicf("failed to create stderr pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Panicf("failed to create stdout pipe: %v", err)
	}

	feedZDNS(linesOfInput, stdin)
	processOutput(stdout, &s)

	// start the command

	err = cmd.Start()
	if err != nil {
		log.Panicf("failed to start command: %v", err)
	}

	outputScanner := bufio.NewScanner(stderr)
	for outputScanner.Scan() {
		fmt.Println("StdErr: " + outputScanner.Text())
	}

	// Wait for the command to finish
	if err = cmd.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "Command finished with error:", err)
		return
	}

	printStats(&s)

}
