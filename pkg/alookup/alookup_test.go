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

func InitTest(t *testing.T) (*zdns.GlobalConf, *GlobalLookupFactory, *RoutineLookupFactory, zdns.Lookup) {
	mockResults = make(map[string]miekg.Result)
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
}

func TestTwoA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
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
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1", "192.0.2.2"}, nil)
}

func TestQuadAWithoutFlag(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
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

	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, nil)
}

func TestOnlyQuadA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv6Lookup = true
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
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::1"})
}

func TestAandQuadA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
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
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, []string{"2001:db8::1"})
}

func TestTwoQuadA(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
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

	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::1", "2001:db8::2"})
}

func TestCname(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
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

	res, _, _, _ := l.DoLookup("cname.example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.1"}, nil)
}

func TestQuadAWithCname(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
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

	res, _, _, _ := l.DoLookup("cname.example.com", "")
	verifyResult(t, res.(Result), nil, []string{"2001:db8::3"})
}

func TestUnexpectedMxOnly(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
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

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

func TestMxAndAdditionals(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
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

	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.3"}, []string{"2001:db8::4"})
}

func TestNoResults(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	mockResults["example.com"] = miekg.Result{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, status, _ := l.DoLookup("example.com", "")
	if status != zdns.STATUS_NOERROR {
		t.Errorf("Expected NOERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

func TestMismatchIpType(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "2001:db8::4",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, status, _ := l.DoLookup("example.com", "")
	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected NOERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

func TestCnameLoops(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
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
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   "example.com",
			Answer: "cname.example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}

	res, _, status, _ := l.DoLookup("example.com", "")
	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

func TestEmptyNonTerminal(t *testing.T) {
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	mockResults["leaf.intermediate.example.com"] = miekg.Result{
		Answers: []interface{}{miekg.Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "leaf.intermediate.example.com",
			Answer: "192.0.2.3",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	mockResults["intermediate.example.com"] = miekg.Result{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	// Verify leaf returns correctly
	res, _, _, _ := l.DoLookup("leaf.intermediate.example.com", "")
	verifyResult(t, res.(Result), []string{"192.0.2.3"}, nil)

	// Verify empty non-terminal returns no answer
	res, _, status, _ := l.DoLookup("intermediate.example.com", "")
	if status != zdns.STATUS_NOERROR {
		t.Errorf("Expected STATUS_NOERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
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

func TestServFail(t *testing.T) {
	errCode = zdns.STATUS_SERVFAIL
	_, glf, _, l := InitTest(t)
	glf.IPv4Lookup = true
	mockResults["example.com"] = miekg.Result{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       miekg.DNSFlags{},
	}
	res, _, status, _ := l.DoLookup("example.com", "")

	if status != errCode {
		t.Errorf("Expected %v status, got %v", errCode, status)
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
