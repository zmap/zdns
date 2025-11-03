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
	"bufio"
	"context"
	"os"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/v2/src/internal/util"
)

type ZoneFileInputHandler struct {
	filepath       string
	includeTargets bool
}

func NewZoneFileInputHandler(filepath string, includeTargets bool) *ZoneFileInputHandler {
	return &ZoneFileInputHandler{
		filepath:       filepath,
		includeTargets: includeTargets,
	}
}

// parseZoneLine parses a zone file record and returns domains to query.
func (h *ZoneFileInputHandler) parseZoneLine(line string) []string {
	line = strings.TrimSpace(line)

	if line == "" || strings.HasPrefix(line, ";") {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	domains := make([]string, 0, 2)

	name := strings.ToLower(fields[0])
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		domains = append(domains, name)
	}

	// Find the record type by skipping TTL (numeric) and CLASS (IN)
	// Standard format: NAME TTL CLASS TYPE RDATA
	typeIndex := -1
	for i := 1; i < len(fields) && i < 4; i++ {
		upperField := strings.ToUpper(fields[i])
		// Skip CLASS field (IN only)
		if upperField == "IN" || upperField == "INET" {
			continue
		}
		// Skip TTL field (numeric)
		isNumeric := true
		for _, r := range upperField {
			if r < '0' || r > '9' {
				isNumeric = false
				break
			}
		}
		if !isNumeric {
			typeIndex = i
			break
		}
	}

	if typeIndex == -1 || typeIndex >= len(fields)-1 {
		return domains
	}

	recordType := strings.ToUpper(fields[typeIndex])
	rdataStart := typeIndex + 1

	if h.includeTargets && rdataStart < len(fields) {
		var target string
		switch recordType {
		case "NS", "CNAME", "DNAME", "PTR", "SOA":
			if len(fields) > rdataStart {
				target = strings.ToLower(fields[rdataStart])
				target = strings.TrimSuffix(target, ".")
			}
		case "MX":
			if len(fields) > rdataStart+1 {
				target = strings.ToLower(fields[rdataStart+1])
				target = strings.TrimSuffix(target, ".")
			}
		case "SRV":
			if len(fields) > rdataStart+3 {
				target = strings.ToLower(fields[rdataStart+3])
				target = strings.TrimSuffix(target, ".")
			}
		}

		if target != "" {
			domains = append(domains, target)
		}
	}

	return domains
}

func (h *ZoneFileInputHandler) FeedChannel(ctx context.Context, in chan<- string, wg *sync.WaitGroup) error {
	defer close(in)
	defer (*wg).Done()

	var f *os.File
	if h.filepath == "" || h.filepath == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(h.filepath)
		if err != nil {
			log.Fatalf("unable to open zone file: %v", err)
		}
		defer f.Close()
	}

	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 1024*1024)

	for s.Scan() {
		if util.HasCtxExpired(ctx) {
			return nil
		}

		domains := h.parseZoneLine(s.Text())
		for _, domain := range domains {
			in <- domain
		}
	}

	if err := s.Err(); err != nil {
		log.Fatalf("unable to read zone file: %v", err)
	}
	return nil
}
