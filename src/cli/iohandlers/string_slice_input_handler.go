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
	"sync"

	log "github.com/sirupsen/logrus"
)

// StringSliceInputHandler Feeds a channel with the strings in the slice.
type StringSliceInputHandler struct {
	Names []string
}

func NewStringSliceInputHandler(domains []string) *StringSliceInputHandler {
	if len(domains) == 0 {
		log.Fatal("No domains provided, cannot create a string slice input handler")
	}
	return &StringSliceInputHandler{Names: domains}
}

func (h *StringSliceInputHandler) FeedChannel(in chan<- string, wg *sync.WaitGroup) error {
	defer close(in)
	defer wg.Done()
	for _, name := range h.Names {
		in <- name
	}
	return nil
}
