/*
 * ZDNS Copyright 2016 Regents of the University of Michigan
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

package zone

import (
	"errors"
	"flag"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
)

type Result struct {
	IPv4Addresses []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	return nil, zdns.STATUS_SUCCESS, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	miekg.RoutineLookupFactory
	Factory *GlobalLookupFactory
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
	IPv4Lookup bool
	IPv6Lookup bool
	Glue       *map[string][]string
	GlueLock   sync.Mutex
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.IPv4Lookup, "ipv4-lookup", true, "perform A lookups for each server")
	f.BoolVar(&s.IPv6Lookup, "ipv6-lookup", true, "perform AAAA record lookups for each server")
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	if c.InputFilePath == "-" {
		return errors.New("Input to ZONE must be a file, not STDIN")
	}
	return s.ParseGlue(c.InputFilePath)
}

func (s *GlobalLookupFactory) ParseGlue(glueFile string) error {
	f, err := os.Open(glueFile)
	if err != nil {
		log.Fatal("unable to open output file:", err.Error())
	}
	glue := make(map[string][]string)
	s.Glue = &glue
	tokens := dns.ParseZone(f, ".", glueFile)
	for t := range tokens {
		if t.Error != nil {
			continue
		}
		switch record := t.RR.(type) {
		case *dns.AAAA:
			(*s.Glue)[t.RR.Header().Name] = append((*s.Glue)[t.RR.Header().Name], record.AAAA.String())
		case *dns.A:
			(*s.Glue)[t.RR.Header().Name] = append((*s.Glue)[t.RR.Header().Name], record.A.String())
		default:
			continue
		}
	}

	return nil
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) MakeRoutineFactory() (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Factory = s
	r.Initialize(s.GlobalConf.Timeout)
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("ZONE", s)
}
