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
	"context"
	"flag"
	"fmt"
	"io"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"time"

	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/v2/src/zdns"
)

const (
	linesOfInput  = 7000 // number of lines to read from input file to feed to ZDNS
	inputFileName = "./10k_crux_top_domains.input"
)

func feedZDNS(ctx context.Context, inputLines int, stdin io.WriteCloser) {
	// read in input to stdin
	go func() {
		f, err := os.Open(inputFileName)
		if err != nil {
			log.Panicf("failed to open input file: %v", err)
		}
		defer func(f *os.File) {
			err = f.Close()
			if err != nil {
				log.Panicf("failed to close input file: %v", err)
			}
		}(f)
		defer func(stdin io.WriteCloser) {
			err = stdin.Close()
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
				if deadline, ok := ctx.Deadline(); ok && time.Now().After(deadline) {
					log.Warnf("timeout exceeded while attempting to write to zdns stdin")
					return
				}
				log.Panicf("failed to write (%v) to stdin: %v", line, err)
			}
		}
	}()
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
		s.EndTime = time.Now()
	}()
}

func main() {
	// Parse command-line flags
	minSuccessRate := flag.Float64("minimum-success-rate", 0, "Minimum success rate (0-1) required for successful exit.")
	timeout := flag.Duration("timeout", 0, "Timeout duration for the benchmark, ex: 5m")
	flag.Parse()

	// ZDNS can start a pprof server if the ZDNS_PPROF environment variable is set
	if err := os.Setenv("ZDNS_PPROF", "true"); err != nil {
		log.Panicf("failed to set ZDNS_PPROF environment variable: %v", err)
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout != nil && *timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "../zdns", "A", "--iterative", "--verbosity=3", "--threads=100", "--status-updates-file", "/dev/null")

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

	feedZDNS(ctx, linesOfInput, stdin)

	// Collect stats
	s := Stats{
		StartTime:             time.Now(),
		TenLongestResolutions: make(map[string]time.Duration, 10),
		numberOfResolutions:   0,
		TimedOutDomains:       make([]string, 0),
		FailedDomains:         make(map[string]zdns.Status),
	}
	processOutput(stdout, &s)

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
		if deadline, ok := ctx.Deadline(); timeout != nil && ok && time.Now().After(deadline) {
			log.Errorf("timeout %v exceeded while waiting for zdns to finish", *timeout)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "Command finished with error:", err)
		os.Exit(1)
	}

	printStats(&s)

	// Check success rate
	successRate := calculateSuccessRate(&s)
	if minSuccessRate != nil && successRate < *minSuccessRate {
		fmt.Fprintf(os.Stderr, "Success rate %.2f%% is below threshold %.2f%%n", successRate*100, *minSuccessRate*100)
		os.Exit(1)
	}
}

func calculateSuccessRate(s *Stats) float64 {
	total := s.numberOfResolutions
	if total == 0 {
		return 0.0
	}
	return float64(s.SuccessfulResolutions) / float64(total)
}
