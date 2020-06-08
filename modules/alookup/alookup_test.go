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

	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
)

// Mock the actual Miekg lookup.
func (s *Lookup) DoTypedMiekgLookup(name string, dnsType uint16, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	if res, ok := mockResults[name]; ok {
		return res, nil, zdns.STATUS_NOERROR, nil
	} else {
		return nil, nil, zdns.STATUS_NO_ANSWER, nil
	}
}

var mockResults = make(map[string]miekg.Result)

func TestDoLookup(t *testing.T) {
	gc := new(zdns.GlobalConf)
	gc.NameServers = []string{"127.0.0.1"}

	glf := new(GlobalLookupFactory)
	glf.GlobalConf = gc
	glf.IPv4Lookup = true
	glf.IPv6Lookup = false

	rlf := new(RoutineLookupFactory)
	rlf.Factory = glf
	rlf.Client = new(dns.Client)

	l, err := rlf.MakeLookup()
	if l == nil || err != nil {
		t.Error("Failed to initialize lookup")
	}

	// Case 1: single A response
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.1",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, nil)

	// Case 2: double A response
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.1",
		},
			miekg.Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com",
				Answer: "192.0.2.2",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, _, _ = l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1", "192.0.2.2"}, nil)

	// Case 3: mixed A and AAAA response
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.1",
		},
			miekg.Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::1",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, _, _ = l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, nil)

	// Case 4: same mixed response, but both types requested.
	glf.IPv6Lookup = true

	res, _, _, _ = l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, []string{"2001:db8::1"})

	// Case 5: double AAAA response
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   "example.com",
			Answer: "2001:db8::1",
		},
			miekg.Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::2",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, _, _ = l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::1", "2001:db8::2"})

	// Case 6: CNAME
	mockResults["cname.example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   "cname.example.com",
			Answer: "example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, _, _ = l.DoLookup("cname.example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::1", "2001:db8::2"})

	// Case 7: AAAA + CNAME (if this ever happens to be returned)
	mockResults["cname.example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   "cname.example.com",
			Answer: "2001:db8::3",
		},
			miekg.Answer{
				Ttl:    3600,
				Type:   "CNAME",
				Class:  "IN",
				Name:   "cname.example.com",
				Answer: "example.com.",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, _, _ = l.DoLookup("cname.example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::3"})

	// Case 8: unexpected MX record only
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "MX",
			Class:  "IN",
			Name:   "example.com",
			Answer: "mail.example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, status, _ := l.DoLookup("example.com", "")
	if status != zdns.STATUS_NO_ANSWER {
		t.Errorf("Expected NO_ANSWER status, got %v", status)
	} else if res != nil {
		t.Error("Received results where expected none")
	}

	// Case 3: unexpected MX record in answer section, but valid A record in additionals
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "MX",
			Class:  "IN",
			Name:   "example.com",
			Answer: "mail.example.com.",
		}},
		Additional: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.3",
		},
			miekg.Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::4",
			}},
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, _, _ = l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.3"}, []string{"2001:db8::4"})
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

	if ipv6 == nil && res.IPv6Addresses != nil && len(res.IPv4Addresses) > 0 {
		t.Error("Received no IPv6 addresses while expected")
	} else if ipv6 != nil {
		if res.IPv6Addresses == nil || len(res.IPv6Addresses) == 0 {
			t.Error("Received no IPv6 addresses while expected")
		} else if len(res.IPv4Addresses) != len(ipv4) {
			t.Errorf("Received %v IPv6 addresses while %v is expected", len(res.IPv6Addresses), len(ipv6))
		} else if !reflect.DeepEqual(res.IPv6Addresses, ipv6) {
			t.Error("Received unexpected IPv6 address(es)")
		}
	}
}
