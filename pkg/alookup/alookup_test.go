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

var mockResults = make(map[string]miekg.IpResult)

var status = zdns.STATUS_NOERROR

func (s *Lookup) DoTargetedLookup(l LookupClient, name, nameServer string, lookupIpv4 bool, lookupIpv6 bool) (interface{}, []interface{}, zdns.Status, error) {
	retv := miekg.IpResult{}
	if res, ok := mockResults[name]; ok {
		if lookupIpv4 {
			retv.IPv4Addresses = res.IPv4Addresses
		}
		if lookupIpv6 {
			retv.IPv6Addresses = res.IPv6Addresses
		}
		return retv, nil, status, nil
	} else {
		return nil, nil, zdns.STATUS_NXDOMAIN, nil
	}
}

func InitTest(t *testing.T) (*GlobalLookupFactory, zdns.Lookup) {
	mockResults = make(map[string]miekg.IpResult)
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
	return glf, l
}

func TestIPv4Lookup(t *testing.T) {
	_, l := InitTest(t)
	mockResults["example.com"] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(miekg.IpResult), []string{"192.0.2.1"}, nil)
}

func TestIPv6Lookup(t *testing.T) {
	glf, l := InitTest(t)
	glf.IPv6Lookup = true
	mockResults["example.com"] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(miekg.IpResult), nil, []string{"2001:db8::1"})
}

func TestBothLookup(t *testing.T) {
	glf, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
	mockResults["example.com"] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(miekg.IpResult), []string{"192.0.2.1"}, []string{"2001:db8::1"})
}

func verifyResult(t *testing.T, res miekg.IpResult, ipv4 []string, ipv6 []string) {
	if !reflect.DeepEqual(ipv4, res.IPv4Addresses) {
		t.Errorf("Expected %v, Received %v IPv4 address(es)", ipv4, res.IPv4Addresses)
	}
	if !reflect.DeepEqual(ipv6, res.IPv6Addresses) {
		t.Errorf("Expected %v, Received %v IPv6 address(es)", ipv6, res.IPv6Addresses)
	}
}
