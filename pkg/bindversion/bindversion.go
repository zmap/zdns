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
	"github.com/zmap/zdns/pkg/miekg"
	"github.com/zmap/zdns/pkg/zdns"
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
	innerRes, trace, status, err := s.DoMiekgLookup(miekg.Question{Name: "VERSION.BIND", Type: s.DNSType, Class: s.DNSClass}, nameServer)
	resString, resStatus, err := s.CheckTxtRecords(innerRes, status, err)
	res := Result{BindVersion: resString}
	return res, trace, resStatus, err
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

func (glf *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	glf.GlobalLookupFactory.Initialize(c)
	c.Class = dns.ClassCHAOS
	return nil
}

func (glf *GlobalLookupFactory) MakeRoutineFactory(threadID int) (zdns.RoutineLookupFactory, error) {
	rlf := new(RoutineLookupFactory)
	rlf.RoutineLookupFactory.Factory = &glf.GlobalLookupFactory
	rlf.Factory = glf
	rlf.ThreadID = threadID
	rlf.Initialize(glf.GlobalConf)

	return rlf, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("BINDVERSION", s)
}
