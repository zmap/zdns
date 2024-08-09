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
	"fmt"
	"io"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"time"

	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/src/zdns"
)

const (
	linesOfInput  = 7000 // number of lines to read from input file to feed to ZDNS
	inputFileName = "./10k_crux_top_domains.input"
)

func feedZDNS(inputLines int, stdin io.WriteCloser) {
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
	// ZDNS can start a pprof server if the ZDNS_PPROF environment variable is set
	if err := os.Setenv("ZDNS_PPROF", "true"); err != nil {
		log.Panicf("failed to set ZDNS_PPROF environment variable: %v", err)
	}

	cmd := exec.Command("../zdns", "A", "--iterative", "--verbosity=3", "--threads=100")

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
	// stats to collect on ZDNS performance
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
		fmt.Fprintln(os.Stderr, "Command finished with error:", err)
		return
	}

	printStats(&s)

}
