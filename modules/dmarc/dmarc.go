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

package spf

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
)

// result to be returned by scan of host
type Result struct {
	Dmarc    string `json:"dmarc,omitempty"`
	Protocol string `json:"protocol"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	// get a name server to use for this connection
	nameServer := s.Factory.Factory.RandomNameServer()
	// this is where we do scanning
	var res Result

	m := new(dns.Msg)
	m.SetQuestion(dotName(name), dns.TypeTXT)
	m.RecursionDesired = true
	tcp := false
	res.Protocol = "udp"
	r, _, err := s.Factory.Client.Exchange(m, nameServer)
	if err == dns.ErrTruncated {
		r, _, err = s.Factory.TCPClient.Exchange(m, nameServer)
		tcp = true
		res.Protocol = "tcp"
	}
	if err != nil {
		return nil, zdns.STATUS_ERROR, err
	}
	if r.Rcode == dns.RcodeBadTrunc && !tcp {
		r, _, err = s.Factory.TCPClient.Exchange(m, nameServer)
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, zdns.STATUS_BAD_RCODE, nil
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.TXT); ok {
			v := strings.Join(a.Txt, "\n")
			if strings.HasPrefix(v, "v=DMARC") {
				res.Dmarc = v
				return &res, zdns.STATUS_SUCCESS, err
			}
		}
	}
	return &res, zdns.STATUS_SUCCESS, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	Factory   *GlobalLookupFactory
	Client    *dns.Client
	TCPClient *dns.Client
}

func (s *RoutineLookupFactory) Initialize(f *GlobalLookupFactory) {
	s.Factory = f
	s.Client = new(dns.Client)
	s.TCPClient = new(dns.Client)
	s.TCPClient.Net = "tcp"
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

func (s *GlobalLookupFactory) MakeRoutineFactory() (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Initialize(s)
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("DMARC", s)
}
