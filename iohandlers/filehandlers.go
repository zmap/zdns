/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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
	"bufio"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

type FileInputHandler struct {
	filepath string
}

func NewFileInputHandler(filepath string) *FileInputHandler {
	return &FileInputHandler{
		filepath: filepath,
	}
}

func (h *FileInputHandler) FeedChannel(in chan<- interface{}, wg *sync.WaitGroup) error {
	defer close(in)
	defer (*wg).Done()

	var f *os.File
	if h.filepath == "" || h.filepath == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(h.filepath)
		if err != nil {
			log.Fatalf("unable to open input file: %v", err)
		}
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		in <- s.Text()
	}
	if err := s.Err(); err != nil {
		log.Fatalf("input unable to read file: %v", err)
	}
	return nil
}

type FileOutputHandler struct {
	filepath string
}

func NewFileOutputHandler(filepath string) *FileOutputHandler {
	return &FileOutputHandler{
		filepath: filepath,
	}
}

func (h *FileOutputHandler) WriteResults(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()

	var f *os.File
	if h.filepath == "" || h.filepath == "-" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(h.filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("unable to open output file: %v", err)
		}
		defer f.Close()
	}
	for n := range results {
		f.WriteString(n + "\n")
	}
	return nil
}
