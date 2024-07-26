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
	log "github.com/sirupsen/logrus"
	"io"
	_ "net/http/pprof"
	"os"
	"os/exec"
)

func initZDNS() (cmd *exec.Cmd, stdin io.WriteCloser, stderr io.ReadCloser, err error) {
	return cmd, stdin, stderr, nil
}

func main() {
	// ZDNS can start a pprof server if the ZDNS_PPROF environment variable is set
	if err := os.Setenv("ZDNS_PPROF", "true"); err != nil {
		log.Panicf("failed to set ZDNS_PPROF environment variable: %v", err)
	}

	cmd := exec.Command("../zdns", "A", "--iterative", "--verbosity=3", "--threads=1")
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

	go func() {
		// Constantly read from stdout and print
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fmt.Println("StdOut: " + scanner.Text())
		}
	}()

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
		// read each line of the file
		// testing: only read 10 lines
		lines := 0
		// Create a new scanner
		scanner := bufio.NewScanner(f)

		// Read the file line by line
		for scanner.Scan() {
			if lines == 10 {
				break
			}
			lines++
			line := scanner.Text() // Get the current line as a string
			fmt.Println(line)      // Print the line (or process it as needed)
			_, err = stdin.Write([]byte(line + "\n"))
			if err != nil {
				log.Panicf("failed to write (%v) to stdin: %v", line, err)
			}
		}
	}()

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

}
