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

package bindversion

import (
	"github.com/zmap/dns"
	"github.com/zmap/zdns/modules/miekg"
	"github.com/zmap/zdns/zdns"
)

// result to be returned by scan of host
type Result struct {
	BindVersion string `json:"version,omitempty" groups:"short,normal,long,trace"`
	Resolver    string `json:"resolver" groups:"resolver,short,normal,long,trace"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func (s *Lookup) DoLookup(_, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	var res Result
	res.Resolver = nameServer
	innerRes, trace, status, err := s.DoTxtLookup("VERSION.BIND", nameServer)
	if status != zdns.STATUS_NOERROR {
		return res, trace, status, err
	}
	res.BindVersion = innerRes
	return res, trace, zdns.STATUS_NOERROR, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	miekg.RoutineLookupFactory
	Factory *GlobalLookupFactory
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	nameServer := s.Factory.RandomNameServer()
	a.Initialize(nameServer, dns.TypeTXT, dns.ClassCHAOS, &s.RoutineLookupFactory)
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	miekg.GlobalLookupFactory
}

func (f *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	f.GlobalLookupFactory.Initialize(c)
	c.Class = dns.ClassCHAOS
	return nil
}

func (s *GlobalLookupFactory) MakeRoutineFactory(threadID int) (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Initialize(s.GlobalConf)
	r.RoutineLookupFactory.Factory = &s.GlobalLookupFactory
	r.Factory = s
	r.ThreadID = threadID
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("BINDVERSION", s)
}
