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

package dmarc

import (
	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
)

// result to be returned by scan of host
type Result struct {
	Dmarc string `json:"dmarc,omitempty" groups:"short,normal,long,trace"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func (s *Lookup) DoLookup(name string, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	var res Result
	innerRes, trace, status, err := s.DoTxtLookup(name, nameServer)
	if status != zdns.STATUS_NOERROR {
		return res, nil, status, err
	}
	res.Dmarc = innerRes
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
	a.Initialize(nameServer, dns.TypeTXT, dns.ClassINET, &s.RoutineLookupFactory)
	a.Prefix = "v=DMARC"
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	miekg.GlobalLookupFactory
}

func (s *GlobalLookupFactory) MakeRoutineFactory(threadID int) (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.RoutineLookupFactory.Factory = &s.GlobalLookupFactory
	r.Initialize(s.GlobalConf)
	r.Factory = s
	r.ThreadID = threadID
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("DMARC", s)
}
