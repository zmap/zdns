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

package alookup

import (
	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
)

// result to be returned by scan of host
type Result struct {
	Answers []miekg.Answer `json:"answers"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	miekg.Lookup
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	nameServer := s.Factory.Factory.RandomNameServer()
	miekgResult, status, err := miekg.DoLookup(s.Factory.Client, s.Factory.TCPClient, nameServer, dns.TypeA, name)
	if status != zdns.STATUS_SUCCESS {
		return nil, status, err
	}
	res := Result{}
	names := map[string]bool{name: true}
	searchSet := []miekg.Answer{}
	searchSet = append(searchSet, miekgResult.(miekg.Result).Additional...)
	searchSet = append(searchSet, miekgResult.(miekg.Result).Answers...)

	for _, add := range searchSet {
		if add.Type == "CNAME" {
			if _, ok := names[add.Name]; ok {
				names[add.Answer] = true
			}
		}
	}
	for _, add := range searchSet {
		if add.Type == "A" {
			if _, ok := names[add.Name]; ok {
				res.Answers = append(res.Answers, add)
			}
		}
	}
	return res, status, err
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
	zdns.RegisterLookup("ALOOKUP", s)
}
