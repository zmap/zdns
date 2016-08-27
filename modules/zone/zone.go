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
	"os"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
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
		result, status, err = lookup.DoTargetedLookup(domain, location+":53")
		if status == zdns.STATUS_SUCCESS && err == nil {
			return result, status, err
		}
	}
	return result, status, err
}

//Lookup is an attempt to perform ALOOKUP directly from a domain nameserver.
//It completes once a single result comes back, and will attempt lookups of
//nameservers' IPs when no glue record was present.
func (s *Lookup) DoZonefileLookup(record *dns.Token) (interface{}, zdns.Status, error) {
	lookup, _ := s.Factory.Subfactory.MakeLookup()
	var nameserver string
	var domain string
	var waiting []*dns.Token
	prefix := s.Factory.Factory.GlobalConf.NamePrefix
	iterations := 0
	for {
		switch typ := record.RR.(type) {
		case *dns.NS:
			nameserver = strings.ToLower(typ.Ns)
			domain = record.RR.Header().Name
			domain = strings.Join([]string{prefix, domain}, "")
		default:
			return nil, zdns.STATUS_NO_OUTPUT, nil
		}
		if strings.Count(record.RR.Header().Name, ".") < 2 {
			return nil, zdns.STATUS_NO_OUTPUT, nil
		}
		if domain[len(domain)-1] == '.' {
			domain = domain[0 : len(domain)-1]
		}
		s.Factory.Factory.CHmu.Lock()
		tmp, found := s.Factory.Factory.Hash[domain]
		if !found {
			waiting = []*dns.Token{}
			s.Factory.Factory.Hash[domain] = waiting
			s.Factory.Factory.CHmu.Unlock()
		} else {
			waiting = tmp.([]*dns.Token)
			waiting = append(waiting, record)
			s.Factory.Factory.Hash[domain] = waiting
			s.Factory.Factory.CHmu.Unlock()
			return nil, zdns.STATUS_NO_OUTPUT, nil
		}
		//First pass looking for a nameserver we know the IP for
		var result interface{}
		var status zdns.Status
		var err error
		s.Factory.Factory.GlueLock.RLock()
		locations, ok := (*s.Factory.Factory.Glue)[nameserver]
		s.Factory.Factory.GlueLock.RUnlock()
		if ok {
			result, status, err = LookupHelper(domain, locations, lookup.(*alookup.Lookup))
			if status == zdns.STATUS_SUCCESS && err == nil {
				return result, status, err
			}
		}
		//Second pass performing lookups to find a nameserver
		s.Factory.Factory.GlueLock.Lock()
		_, ok = (*s.Factory.Factory.Glue)[nameserver]
		s.Factory.Factory.GlueLock.Unlock()
		if !ok {
			result, status, err = lookup.(*alookup.Lookup).DoLookup(nameserver[0 : len(nameserver)-1])
			if status == zdns.STATUS_SUCCESS && err == nil {
				addresses := append(result.(alookup.Result).IPv4Addresses, result.(alookup.Result).IPv6Addresses...)
				s.Factory.Factory.GlueLock.Lock()
				(*s.Factory.Factory.Glue)[nameserver] = addresses
				s.Factory.Factory.GlueLock.Unlock()
				result, status, err = LookupHelper(domain, []string{}, lookup.(*alookup.Lookup))
				if status == zdns.STATUS_SUCCESS && err == nil {
					return result, status, err
				}
			}
		}
		s.Factory.Factory.CHmu.Lock()
		tmp, found = s.Factory.Factory.Hash[domain]
		if found {
			waiting = tmp.([]*dns.Token)
			if len(waiting) > 0 {
				record = waiting[0]
				waiting = waiting[1:]
				s.Factory.Factory.Hash[domain] = waiting
				s.Factory.Factory.CHmu.Unlock()
				continue
			} else {
				s.Factory.Factory.CHmu.Unlock()
				return nil, status, err
			}
		} else {
			s.Factory.Factory.CHmu.Unlock()
			return nil, status, err
		}
		iterations++
	}
	return nil, zdns.STATUS_NO_OUTPUT, nil
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
	Glue         *map[string][]string
	GlueLock     sync.RWMutex
	Subfactory   alookup.GlobalLookupFactory
	CacheFactor  int
	GlueFilePath string
	Hash         map[string]interface{}
	CHmu         sync.Mutex
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.Subfactory.IPv4Lookup, "ipv4-lookup", true, "perform A lookups for each server")
	f.BoolVar(&s.Subfactory.IPv6Lookup, "ipv6-lookup", true, "perform AAAA record lookups for each server")
	f.IntVar(&s.CacheFactor, "cache-size-factor", 25, "number of times larger than the number of threads to make the cache of successes")
	f.StringVar(&s.GlueFilePath, "glue-file", "", "glue file path")
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
	s.Hash = make(map[string]interface{})
	if s.GlueFilePath == "" {
		s.GlueFilePath = c.InputFilePath
	}
	return s.ParseGlue(s.GlueFilePath)
}

func (s *GlobalLookupFactory) Finalize() error {
	return nil
}

func (s *GlobalLookupFactory) ParseGlue(glueFile string) error {
	f, err := os.Open(glueFile)
	if err != nil {
		log.Fatal("unable to open output file:", err.Error())
	}
	glue := make(map[string][]string)
	s.Glue = &glue
	tokens := dns.ParseZone(f, ".", glueFile)
	log.Info("Beginning to parse glue file")
	i := 0
	for t := range tokens {
		if t.Error != nil {
			continue
		}
		i++
		if i%100000 == 0 {
			log.Infof("Processed %d glue records", i)
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
	log.Info("Ending parse zonefile")
	return nil
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) AllowStdIn() bool {
	return false
}

func (s *GlobalLookupFactory) ZonefileInput() bool {
	return true
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
