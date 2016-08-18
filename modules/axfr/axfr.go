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

package axfr

import (
	"flag"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/zmap/go-iptree/blacklist"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
	"github.com/zmap/zdns/modules/nslookup"
)

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
	zdns.BaseLookup
}

type AXFRServerResult struct {
	Server  string         `json:"server"`
	Status  string         `json:"status"`
	Error   string         `json:"error,omitempty"`
	Records []miekg.Answer `json:"records,omitempty"`
}

type AXFRResult struct {
	Servers []AXFRServerResult `json:"servers"`
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func (s *Lookup) DoAXFR(name string, server string) AXFRServerResult {
	var retv AXFRServerResult
	retv.Server = server
	// check if the server address is blacklisted and if so, exclude
	if s.Factory.Factory.Blacklist != nil {
		s.Factory.Factory.BlMu.Lock()
		if blacklisted, err := s.Factory.Factory.Blacklist.IsBlacklisted(server); err != nil {
			s.Factory.Factory.BlMu.Unlock()
			retv.Status = "error"
			retv.Error = "blacklist-error"
			return retv
		} else if blacklisted {
			s.Factory.Factory.BlMu.Unlock()
			retv.Status = "error"
			retv.Error = "blacklisted"
			return retv
		}
		s.Factory.Factory.BlMu.Unlock()
	}
	m := new(dns.Msg)
	m.SetAxfr(dotName(name))
	tr := new(dns.Transfer)
	if a, err := tr.In(m, net.JoinHostPort(server, "53")); err != nil {
		retv.Status = "error"
		retv.Error = err.Error()
		return retv
	} else {
		for ex := range a {
			if ex.Error != nil {
				retv.Status = "error"
				retv.Error = ex.Error.Error()
				return retv
			} else {
				retv.Status = "success"
				for _, rr := range ex.RR {
					ans := miekg.ParseAnswer(rr)
					if ans != nil {
						retv.Records = append(retv.Records, *ans)
					}
				}
			}
		}
	}
	return retv
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	nameServer := s.Factory.Factory.RandomNameServer()
	parsedNS, _, _ := nslookup.DoNSLookup(name, nameServer, s.Factory.Client, s.Factory.TCPClient, true, false)
	var retv AXFRResult
	for _, server := range parsedNS.Servers {
		if len(server.IPv4Addresses) > 0 {
			retv.Servers = append(retv.Servers, s.DoAXFR(name, server.IPv4Addresses[0]))
		}
	}
	return retv, zdns.STATUS_SUCCESS, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	Factory *GlobalLookupFactory
	miekg.RoutineLookupFactory
}

func (s *RoutineLookupFactory) Initialize(t time.Duration) {
	s.Client = new(dns.Client)
	s.Client.Timeout = t
	s.TCPClient = new(dns.Client)
	s.TCPClient.Net = "tcp"
	s.TCPClient.Timeout = t
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
	BlacklistPath string
	Blacklist     *blacklist.Blacklist
	BlMu          sync.Mutex
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	f.StringVar(&s.BlacklistPath, "blacklist", "", "blacklist file for servers to exclude from AXFR lookups")
}

func (s *GlobalLookupFactory) MakeRoutineFactory() (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Factory = s
	r.Initialize(s.GlobalConf.Timeout)
	return r, nil
}

func (s *GlobalLookupFactory) Initialize(c *zdns.GlobalConf) error {
	s.GlobalConf = c
	if s.BlacklistPath != "" {
		s.Blacklist = blacklist.New()
		if err := s.Blacklist.ParseFromFile(s.BlacklistPath); err != nil {
			return err
		}
	}
	return nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("AXFR", s)
}
