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

package zdns

import (
	"flag"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

/* Each lookup module registers a single GlobalLookupFactory, which is
 * instantiated once.  This global factory is responsible for providing command
 * line arguments and performing any configuration that should only occur once.
 * For each thread in the worker pool, the framework calls
 * MakePerRoutineFactory(), which should return a second factory, which should
 * perform any "per-thread" initialization. Within each "thread", the framework
 * will then call MakeLookup() for each connection it will make, on which it
 * will call DoLookup().  While two layers of factories is a bit... obnoxious,
 * this allows each module to maintain global, per-thread, and per-connection
 * state.
 *
 * Each layer has access to one proceeding layer (e.g., RoutineLookupFactory
 * knows the GlobalLookupFactory, from which it was created. Therefore, modules
 * should refer to this configuration instead of copying all configuration
 * values for every connection. The Base structs implement these basic
 * pieces of functionality and should be inherited in most situations.
 */

// one Lookup per IP/name/connection ==========================================
//
type Lookup interface {
	DoLookup(name string, nameServer string) (interface{}, []interface{}, Status, error)
	DoZonefileLookup(record *dns.Token) (interface{}, Status, error)
}

type BaseLookup struct {
}

func (base *BaseLookup) DoLookup(name string, class uint16) (interface{}, Status, error) {
	log.Fatal("Unimplemented DoLookup")
	return nil, STATUS_ERROR, nil
}

func (base *BaseLookup) DoZonefileLookup(record *dns.Token) (interface{}, Status, error) {
	log.Fatal("Unimplemented DoZonefileLookup")
	return nil, STATUS_ERROR, nil
}

// one RoutineLookupFactory per goroutine =====================================
//
type RoutineLookupFactory interface {
	MakeLookup() (Lookup, error)
}

// one RoutineLookupFactory per execution =====================================
//
type GlobalLookupFactory interface {
	// expected to add any necessary commandline flags if being
	// run as a standalone scanner
	AddFlags(flags *flag.FlagSet)
	// global initialization. Gets called once globally
	// This is called after command line flags have been parsed
	Initialize(conf *GlobalConf) error
	Finalize() error
	// We can't set variables on an interface, so write functions
	// that define any settings for the factory
	AllowStdIn() bool
	// Some modules have Zonefile inputs
	ZonefileInput() bool
	// Help text for the CLI
	Help() string
	// Return a single scanner which will scan a single host
	MakeRoutineFactory(int) (RoutineLookupFactory, error)
	RandomNameServer() string
}

// handle domain input
type InputHandler interface {
	// give the InputHandler access to the global config in case it needs any of the settings
	Initialize(conf *GlobalConf)
	// FeedChannel takes a channel to write domains to, the WaitGroup managing them, and if it's a zonefile input
	FeedChannel(in chan<- interface{}, wg *sync.WaitGroup, zonefileInput bool) error
}

// handle output results
type OutputHandler interface {
	// give the OutputHandler access to the global config in case it needs any of the settings
	Initialize(conf *GlobalConf)
	// takes a channel (results) to write the query results to, and the WaitGroup managing the handlers
	WriteResults(results <-chan string, wg *sync.WaitGroup) error
}

type BaseGlobalLookupFactory struct {
	GlobalConf *GlobalConf
}

func (f *BaseGlobalLookupFactory) Initialize(c *GlobalConf) error {
	f.GlobalConf = c
	return nil
}

func (f *BaseGlobalLookupFactory) Finalize() error {
	return nil
}

func (s *BaseGlobalLookupFactory) AddFlags(f *flag.FlagSet) {
}

func (s *BaseGlobalLookupFactory) Help() string {
	return ""
}

func (f *BaseGlobalLookupFactory) RandomNameServer() string {
	if f.GlobalConf == nil {
		log.Fatal("no global conf initialized")
	}
	l := len(f.GlobalConf.NameServers)
	if l == 0 {
		log.Fatal("No name servers specified")
	}
	return f.GlobalConf.NameServers[rand.Intn(l)]
}

func (f *BaseGlobalLookupFactory) RandomLocalAddr() net.IP {
	if f.GlobalConf == nil {
		log.Fatal("no global conf initialized")
	}
	l := len(f.GlobalConf.LocalAddrs)
	if l == 0 {
		log.Fatal("No local addresses specified")
	}
	return f.GlobalConf.LocalAddrs[rand.Intn(l)]
}

func (s *BaseGlobalLookupFactory) AllowStdIn() bool {
	return true
}

func (s *BaseGlobalLookupFactory) ZonefileInput() bool {
	return false
}

// keep a mapping from name to factory
var lookups map[string]GlobalLookupFactory

// keep a mapping from name to input handler
var inputHandlers map[string]InputHandler

// keep a mapping from name to output handler
var outputHandlers map[string]OutputHandler

func RegisterLookup(name string, s GlobalLookupFactory) {
	if lookups == nil {
		lookups = make(map[string]GlobalLookupFactory, 100)
	}
	lookups[name] = s
}

func RegisterInputHandler(name string, h InputHandler) {
	if inputHandlers == nil {
		inputHandlers = make(map[string]InputHandler)
	}
	inputHandlers[name] = h
}

func RegisterOutputHandler(name string, h OutputHandler) {
	if outputHandlers == nil {
		outputHandlers = make(map[string]OutputHandler)
	}
	outputHandlers[name] = h
}

func ValidlookupsString() string {
	valid := make([]string, len(lookups))
	i := 0
	for k := range lookups {
		valid[i] = k
		i++
	}
	sort.Strings(valid)
	return strings.Join(valid, ", ")
}

func GetLookup(name string) GlobalLookupFactory {

	factory, ok := lookups[name]
	if !ok {
		return nil
	}
	return factory
}

func GetInputHandler(name string) InputHandler {
	inHandler, ok := inputHandlers[name]
	if !ok {
		return nil
	}
	return inHandler
}

func GetOutputHandler(name string) OutputHandler {
	outHandler, ok := outputHandlers[name]
	if !ok {
		return nil
	}
	return outHandler
}
