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

package mxlookup

import (
	"reflect"
	"testing"

	"github.com/zmap/dns"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
)

var mockResults = make(map[string]miekg.Result)

var errCode = zdns.STATUS_NOERROR

// Mock the actual Miekg lookup.
func (s *Lookup) DoMiekgLookup(question miekg.Question, nameServer string) (interface{}, []interface{}, zdns.Status, error) {
	if res, ok := mockResults[question.Name]; ok {
		return res, nil, errCode, nil
	} else {
		return nil, nil, zdns.STATUS_NXDOMAIN, nil
	}
}

type minimalServerRecords struct {
	recType       string
	IPv4Addresses []string
	IPv6Addresses []string
}

func InitTest(t *testing.T) (*zdns.GlobalConf, *GlobalLookupFactory, *RoutineLookupFactory, zdns.Lookup) {
	mockResults = make(map[string]miekg.Result)
	gc := new(zdns.GlobalConf)
	gc.NameServers = []string{"127.0.0.1"}

	glf := new(GlobalLookupFactory)
	glf.GlobalConf = gc
	glf.IPv4Lookup = false
	glf.IPv6Lookup = false

	rlf := new(RoutineLookupFactory)
	rlf.Factory = glf
	rlf.Client = new(dns.Client)

	l, err := rlf.MakeLookup()
	if l == nil || err != nil {
		t.Error("Failed to initialize lookup")
	}

	if err := glf.Initialize(gc); err != nil {
		t.Errorf("Factory was unable to initialize: %v", err.Error())
	}
	return gc, glf, rlf, l
}

func TestA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true

	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.PrefAnswer{
			Answer: miekg.Answer{
				Ttl:    3600,
				Type:   "MX",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "mail.example.com.",
			},
			Preference: 1,
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail.example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "mail.example.com.",
			Answer: "192.0.2.3",
		},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	expectedServersMap := make(map[string]minimalServerRecords)
	expectedServersMap["mail.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).Servers, expectedServersMap)
}

func TestTwoMx(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true

	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.PrefAnswer{
				Answer: miekg.Answer{
					Ttl:    3600,
					Type:   "MX",
					Class:  "IN",
					Name:   "example.com.",
					Answer: "mail1.example.com.",
				},
				Preference: 1,
			},
			miekg.PrefAnswer{
				Answer: miekg.Answer{
					Ttl:    3600,
					Type:   "MX",
					Class:  "IN",
					Name:   "example.com.",
					Answer: "mail2.example.com.",
				},
				Preference: 2,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail1.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "mail1.example.com.",
				Answer: "192.0.2.3",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail2.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "mail2.example.com.",
				Answer: "192.0.2.4",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	expectedServersMap := make(map[string]minimalServerRecords)
	expectedServersMap["mail1.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	expectedServersMap["mail2.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: []string{"192.0.2.4"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).Servers, expectedServersMap)
}

func TestAandQuadA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true

	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.PrefAnswer{
			Answer: miekg.Answer{
				Ttl:    3600,
				Type:   "MX",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "mail.example.com.",
			},
			Preference: 1,
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "mail.example.com.",
				Answer: "2001:db8::4",
			},
			miekg.Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "mail.example.com.",
				Answer: "192.0.2.3",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	expectedServersMap := make(map[string]minimalServerRecords)
	expectedServersMap["mail.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: []string{"2001:db8::4"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).Servers, expectedServersMap)
}

func TestMismatchIpType(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true

	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.PrefAnswer{
			Answer: miekg.Answer{
				Ttl:    3600,
				Type:   "MX",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "mail.example.com.",
			},
			Preference: 1,
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "mail.example.com.",
				Answer: "2001:db8::4",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	expectedServersMap := make(map[string]minimalServerRecords)
	expectedServersMap["mail.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).Servers, expectedServersMap)
}

func TestCname(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = false
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.PrefAnswer{
			Answer: miekg.Answer{
				Ttl:    3600,
				Type:   "MX",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "mail.example.com.",
			},
			Preference: 1,
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "CNAME",
				Class:  "IN",
				Name:   "mail.example.com.",
				Answer: "mail1.example.com.",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail1.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "mail1.example.com.",
				Answer: "192.0.2.3",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	expectedServersMap := make(map[string]minimalServerRecords)
	expectedServersMap["mail.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).Servers, expectedServersMap)
}

func TestMxAndAdditionals(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.PrefAnswer{
			Answer: miekg.Answer{
				Ttl:    3600,
				Type:   "MX",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "mail.example.com.",
			},
			Preference: 1,
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail.example.com"] = miekg.Result{
		Answers: nil,
		Additional: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "mail.example.com.",
			Answer: "192.0.2.3",
		}},
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	expectedServersMap := make(map[string]minimalServerRecords)
	expectedServersMap["mail.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).Servers, expectedServersMap)
}

func TestNXDomain(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	res, _, status, _ := l.DoLookup("nonexistent.example.com", "")
	if status != zdns.STATUS_NXDOMAIN {
		t.Errorf("Expected STATUS_NXDOMAIN status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

func TestCnameLoops(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	// CName loops should terminate and just give the MX record
	// without IP addresses
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.PrefAnswer{
			Answer: miekg.Answer{
				Ttl:    3600,
				Type:   "MX",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "mail1.example.com.",
			},
			Preference: 1,
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail1.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "CNAME",
				Class:  "IN",
				Name:   "mail1.example.com.",
				Answer: "mail2.example.com.",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["mail2.example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{
				Ttl:    3600,
				Type:   "CNAME",
				Class:  "IN",
				Name:   "mail2.example.com.",
				Answer: "mail1.example.com.",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	expectedServersMap := make(map[string]minimalServerRecords)
	expectedServersMap["mail1.example.com"] = minimalServerRecords{
		recType:       "MX",
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	verifyResult(t, res.(Result).Servers, expectedServersMap)

}

func verifyResult(t *testing.T, servers []MXRecord, expectedServersMap map[string]minimalServerRecords) {
	serversLength := len(servers)
	expectedServersLength := len(expectedServersMap)

	if serversLength != expectedServersLength {
		t.Errorf("Expected %v servers, found %v", expectedServersLength, serversLength)
	}

	for _, server := range servers {
		name := server.Name
		expectedRecords, ok := expectedServersMap[name]
		if !ok {
			t.Errorf("Did not find server %v in expected servers.", name)
		}
		if !reflect.DeepEqual(server.IPv4Addresses, expectedRecords.IPv4Addresses) {
			t.Errorf("IPv4 addresses not matching for %v, expected %v, found %v", name, expectedRecords.IPv4Addresses, server.IPv4Addresses)
		}
		if !reflect.DeepEqual(server.IPv6Addresses, expectedRecords.IPv6Addresses) {
			t.Errorf("IPv6 addresses not matching for %v, expected %v, found %v", name, expectedRecords.IPv6Addresses, server.IPv6Addresses)
		}
	}
}
