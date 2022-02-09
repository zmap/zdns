/*
 * ZDNS Copyright 2019 Regents of the University of Michigan
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
	"reflect"
	"testing"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/miekg"
	"github.com/zmap/zdns/pkg/zdns"
)

type minimalRes struct {
	IPv4Addresses []string
	IPv6Addresses []string
}

var mockResults = make(map[string]minimalRes)

var status = zdns.STATUS_NOERROR

// Mock the actual DoProtocolLookup
func (s *Lookup) DoProtocolLookup(lc LookupClient, name, nameServer string, dnsType uint16, candidateSet map[string][]miekg.Answer, cnameSet map[string][]miekg.Answer, origName string, depth int) ([]string, []interface{}, zdns.Status, error) {
	if res, ok := mockResults[name]; ok {
		if dnsType == dns.TypeA {
			return res.IPv4Addresses, nil, status, nil
		} else {
			return res.IPv6Addresses, nil, status, nil
		}
	} else {
		return nil, nil, zdns.STATUS_NXDOMAIN, nil
	}
}

func InitTest(t *testing.T) (*zdns.GlobalConf, *GlobalLookupFactory, *RoutineLookupFactory, zdns.Lookup) {
	mockResults = make(map[string]minimalRes)
	gc := new(zdns.GlobalConf)
	gc.NameServers = []string{"127.0.0.1"}

	glf := new(GlobalLookupFactory)
	glf.GlobalConf = gc

	rlf := new(RoutineLookupFactory)
	rlf.Factory = glf
	rlf.Client = new(dns.Client)

	l, err := rlf.MakeLookup()
	if l == nil || err != nil {
		t.Error("Failed to initialize lookup")
	}
	return gc, glf, rlf, l
}

func TestOneA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	mockResults["example.com"] = minimalRes{
		IPv4Addresses: []string{"192.0.2.1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, nil)
}

func TestTwoA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	mockResults["example.com"] = minimalRes{
		IPv4Addresses: []string{"192.0.2.1", "192.0.2.2"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1", "192.0.2.2"}, nil)
}

func TestQuadAWithoutFlag(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	mockResults["example.com"] = minimalRes{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, nil)
}

func TestOnlyQuadA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv6Lookup = true
	mockResults["example.com"] = minimalRes{
		IPv6Addresses: []string{"2001:db8::1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::1"})
}

func TestAandQuadA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
	mockResults["example.com"] = minimalRes{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, []string{"2001:db8::1"})
}

func TestTwoQuadA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
	mockResults["example.com"] = minimalRes{
		IPv6Addresses: []string{"2001:db8::1", "2001:db8::2"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::1", "2001:db8::2"})
}

func TestNoResults(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	mockResults["example.com"] = minimalRes{}
	res, _, status, _ := l.DoLookup("example.com", "")
	if status != zdns.STATUS_NOERROR {
		t.Errorf("Expected NOERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

func verifyResult(t *testing.T, res Result, ipv4 []string, ipv6 []string) {
	if ipv4 == nil && res.IPv4Addresses != nil && len(res.IPv4Addresses) > 0 {
		t.Error("Received IPv4 addresses while none expected")
	} else if ipv4 != nil {
		if res.IPv4Addresses == nil || len(res.IPv4Addresses) == 0 {
			t.Error("Received no IPv4 addresses while expected")
		} else if len(res.IPv4Addresses) != len(ipv4) {
			t.Errorf("Received %v IPv4 addresses while %v is expected", len(res.IPv4Addresses), len(ipv4))
		} else if !reflect.DeepEqual(res.IPv4Addresses, ipv4) {
			t.Error("Received unexpected IPv4 address(es)")
		}
	}

	if ipv6 == nil && res.IPv6Addresses != nil && len(res.IPv6Addresses) > 0 {
		t.Error("Received IPv6 addresses while none expected")
	} else if ipv6 != nil {
		if res.IPv6Addresses == nil || len(res.IPv6Addresses) == 0 {
			t.Error("Received no IPv6 addresses while expected")
		} else if len(res.IPv6Addresses) != len(ipv6) {
			t.Errorf("Received %v IPv6 addresses while %v is expected", len(res.IPv6Addresses), len(ipv6))
		} else if !reflect.DeepEqual(res.IPv6Addresses, ipv6) {
			t.Error("Received unexpected IPv6 address(es)")
		}
	}
}
