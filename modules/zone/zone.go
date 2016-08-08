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
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/alookup"
	"github.com/zmap/zdns/modules/miekg"
)

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func LookupHelper(domain string, nsIPs []string, lookup *alookup.Lookup) (interface{}, zdns.Status, error) {
	var result interface{}
	var status zdns.Status
	var err error
	for _, location := range nsIPs {
		result, status, err := lookup.DoTargetedLookup(domain, location+":53")
		if status == zdns.STATUS_SUCCESS && err == nil {
			return result, status, err
		}
	}
	return result, status, err
}

//Lookup is an attempt to perform ALOOKUP directly from a domain nameserver.
//It completes once a single result comes back, and will attempt lookups of
//nameservers' IPs when no glue record was present.
func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	lookup, _ := s.Factory.Subfactory.MakeLookup()
	var targeted zdns.TargetedDomain
	json.Unmarshal([]byte(name), &targeted)
	//First pass looking for a nameserver we know the IP for
	s.Factory.Factory.GlueLock.RLock()
	for _, nameserver := range targeted.Nameservers {
		if locations, ok := (*s.Factory.Factory.Glue)[strings.ToLower(nameserver)]; ok {
			result, status, err := LookupHelper(targeted.Domain, locations, lookup.(*alookup.Lookup))
			if status == zdns.STATUS_SUCCESS && err == nil {
				s.Factory.Factory.GlueLock.RUnlock()
				return result, status, err
			}
		}
	}
	s.Factory.Factory.GlueLock.RUnlock()
	//Second pass performing lookups to find a nameserver
	s.Factory.Factory.GlueLock.Lock()
	for _, nameserver := range targeted.Nameservers {
		if _, ok := (*s.Factory.Factory.Glue)[strings.ToLower(nameserver)]; !ok {
			result, status, err := lookup.(*alookup.Lookup).DoLookup(nameserver[0 : len(nameserver)-1])
			if status != zdns.STATUS_SUCCESS || err != nil {
				continue
			}
			addresses := append(result.(alookup.Result).IPv4Addresses, result.(alookup.Result).IPv6Addresses...)
			(*s.Factory.Factory.Glue)[strings.ToLower(nameserver)] = addresses
			result, status, err = LookupHelper(targeted.Domain, addresses, lookup.(*alookup.Lookup))
			if status == zdns.STATUS_SUCCESS && err == nil {
				s.Factory.Factory.GlueLock.Unlock()
				return result, status, err
			}
		}
	}
	s.Factory.Factory.GlueLock.Unlock()
	return nil, zdns.STATUS_ERROR, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	miekg.RoutineLookupFactory
	Factory    *GlobalLookupFactory
	Subfactory zdns.RoutineLookupFactory
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
	Glue       *map[string][]string
	GlueLock   sync.RWMutex
	Subfactory alookup.GlobalLookupFactory
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.Subfactory.IPv4Lookup, "ipv4-lookup", true, "perform A lookups for each server")
	f.BoolVar(&s.Subfactory.IPv6Lookup, "ipv6-lookup", true, "perform AAAA record lookups for each server")
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	if c.InputFilePath == "-" {
		return errors.New("Input to ZONE must be a file, not STDIN")
	}
	err := s.Subfactory.Initialize(c)
	if err != nil {
		return err
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
			(*s.Glue)[strings.ToLower(t.RR.Header().Name)] = append((*s.Glue)[strings.ToLower(t.RR.Header().Name)], record.AAAA.String())
		case *dns.A:
			(*s.Glue)[strings.ToLower(t.RR.Header().Name)] = append((*s.Glue)[strings.ToLower(t.RR.Header().Name)], record.A.String())
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
	var err error
	r := new(RoutineLookupFactory)
	r.Factory = s
	r.Initialize(s.GlobalConf.Timeout)
	r.Subfactory, err = s.Subfactory.MakeRoutineFactory()
	return r, err
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("ZONE", s)
}
