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
	"github.com/zmap/zdns/cachehash"
	"github.com/zmap/zdns/modules/alookup"
	"github.com/zmap/zdns/modules/miekg"
)

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

type CallbackManager struct {
	Conf       *zdns.GlobalConf
	OutputFile *os.File
}

func (c *CallbackManager) Evict(key, value interface{}) {
	valChan := value.(chan bool)
	wasClosed := false
EmptyChan:
	for {
		select {
		case v := <-valChan:
			if v {
			} else {
				wasClosed = true
				break EmptyChan
			}
		default:
			break EmptyChan
		}
	}
	close(valChan)
	if wasClosed {
		return
	}
	domain := key.(string)
	var res zdns.Result
	res.Name = domain
	res.Status = string(zdns.STATUS_ERROR)
	jsonRes, err := json.Marshal(res)
	if err != nil {
		log.Fatal("Unable to marshal JSON result", err)
	}
	c.OutputFile.WriteString(string(jsonRes) + "\n")
}

func LookupHelper(domain string, nsIPs []string, lookup *alookup.Lookup) (interface{}, zdns.Status, error) {
	var result interface{}
	var status zdns.Status
	var err error
	for _, location := range nsIPs {
		if location[0:1] != "[" && strings.Contains(location, ":") {
			location = "[" + location + "]"
		}
		result, status, err = lookup.DoTargetedLookup(domain, location+":53")
		if status == zdns.STATUS_NOERROR && err == nil {
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
	var notify chan bool
	prefix := s.Factory.Factory.GlobalConf.NamePrefix
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
	//Verify this didn't succeed before
	//Make sure it is in Cachehash- if we added it, proceed
	//if we didn't add it, listen on the chan
	//	new bool, true-> return no output, false-> proceed
	//  closed channel-> return no output
	proceed := false
	s.Factory.Factory.CHmu.Lock()
	tmp, found := s.Factory.Factory.CacheHash.Get(domain)
	if !found {
		notify = make(chan bool, 10)
		s.Factory.Factory.CacheHash.Add(domain, notify)
		s.Factory.Factory.CHmu.Unlock()
		proceed = true
	} else {
		notify = tmp.(chan bool)
		s.Factory.Factory.CHmu.Unlock()
		for unsolved := range notify {
			if unsolved {
				proceed = true
				break
			} else {
				notify <- false
				break
			}
		}
	}
	if !proceed {
		return nil, zdns.STATUS_NO_OUTPUT, nil
	}
	//First pass looking for a nameserver we know the IP for
	var result interface{}
	var status zdns.Status
	var err error
	s.Factory.Factory.GlueLock.RLock()
	if locations, ok := (*s.Factory.Factory.Glue)[nameserver]; ok {
		result, status, err = LookupHelper(domain, locations, lookup.(*alookup.Lookup))
		if status == zdns.STATUS_NOERROR && err == nil {
			s.Factory.Factory.GlueLock.RUnlock()
			notify <- false
			return result, status, err
		}
	}
	s.Factory.Factory.GlueLock.RUnlock()
	//Second pass performing lookups to find a nameserver
	s.Factory.Factory.GlueLock.Lock()
	if _, ok := (*s.Factory.Factory.Glue)[nameserver]; !ok {
		result, status, err = lookup.(*alookup.Lookup).DoLookup(nameserver[0 : len(nameserver)-1])
		if status == zdns.STATUS_NOERROR && err == nil {
			addresses := append(result.(alookup.Result).IPv4Addresses, result.(alookup.Result).IPv6Addresses...)
			(*s.Factory.Factory.Glue)[nameserver] = addresses
			result, status, err = LookupHelper(domain, addresses, lookup.(*alookup.Lookup))
			if status == zdns.STATUS_NOERROR && err == nil {
				s.Factory.Factory.GlueLock.Unlock()
				notify <- false
				return result, status, err
			}
		}
	}
	s.Factory.Factory.GlueLock.Unlock()
	notify <- true
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
	Glue        *map[string][]string
	GlueLock    sync.RWMutex
	Subfactory  alookup.GlobalLookupFactory
	CacheFactor int
	CacheHash   *cachehash.CacheHash
	CHmu        sync.Mutex
	Manager     CallbackManager
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.BoolVar(&s.Subfactory.IPv4Lookup, "ipv4-lookup", true, "perform A lookups for each server")
	f.BoolVar(&s.Subfactory.IPv6Lookup, "ipv6-lookup", true, "perform AAAA record lookups for each server")
	f.IntVar(&s.CacheFactor, "cache-size-factor", 25, "number of times larger than the number of threads to make the cache of successes")
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	cacheSize := c.Threads * s.CacheFactor
	if c.InputFilePath == "-" {
		return errors.New("Input to ZONE must be a file, not STDIN")
	}
	err := s.Subfactory.Initialize(c)
	if err != nil {
		return err
	}
	s.CacheHash = new(cachehash.CacheHash)
	s.CacheHash.Init(cacheSize)
	s.Manager = CallbackManager{c, nil}
	if c.OutputFilePath == "" || c.OutputFilePath == "-" {
		s.Manager.OutputFile = os.Stdout
	} else {
		var err error
		s.Manager.OutputFile, err = os.OpenFile(c.OutputFilePath, os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("unable to open output file:", err.Error())
		}
	}
	s.CacheHash.RegisterCB(s.Manager.Evict)
	return s.ParseGlue(c.InputFilePath)
}

func (s *GlobalLookupFactory) Finalize() error {
	for s.CacheHash.Len() > 0 {
		s.CacheHash.Eject()
	}
	s.Manager.OutputFile.Close()
	return nil
}

func (s *GlobalLookupFactory) ParseGlue(glueFile string) error {
	f, err := os.Open(glueFile)
	if err != nil {
		log.Fatal("unable to open input file:", err.Error())
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
