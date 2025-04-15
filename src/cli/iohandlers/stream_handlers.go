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
	"context"
	"io"
	"sync"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/v2/src/internal/util"
)

type StreamInputHandler struct {
	reader io.Reader
}

func NewStreamInputHandler(r io.Reader) *StreamInputHandler {
	return &StreamInputHandler{
		reader: r,
	}
}

func (h *StreamInputHandler) FeedChannel(ctx context.Context, in chan<- string, wg *sync.WaitGroup) error {
	defer close(in)
	defer (*wg).Done()

	s := bufio.NewScanner(h.reader)
	for s.Scan() {
		if util.HasCtxExpired(ctx) {
			return nil // context expired, exiting
		}
		in <- s.Text()
	}
	if err := s.Err(); err != nil {
		log.Fatalf("unable to read input stream: %v", err)
	}
	return nil
}

type StreamOutputHandler struct {
	writer io.Writer
}

func NewStreamOutputHandler(w io.Writer) *StreamOutputHandler {
	return &StreamOutputHandler{
		writer: w,
	}
}

func (h *StreamOutputHandler) WriteResults(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()
	for n := range results {
		_, err := io.WriteString(h.writer, n+"\n")
		if err != nil {
			return errors.Wrap(err, "unable to write to output stream")
		}
	}
	return nil
}
