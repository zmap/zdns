/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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
package miekg

import (
	"net"
	"reflect"
	"regexp"
	"strconv"
	"testing"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"
	"gotest.tools/v3/assert"
)

type domain_ns struct {
	domain string
	ns     string
}

type minimalRecords struct {
	Status        zdns.Status
	IPv4Addresses []string
	IPv6Addresses []string
}

var mockResults = make(map[domain_ns]Result)

var protocolStatus = make(map[domain_ns]zdns.Status)

type MockLookupClient struct{}

func (mc MockLookupClient) ProtocolLookup(s *Lookup, q Question, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	cur_domain_ns := domain_ns{domain: q.Name, ns: nameServer}
	if res, ok := mockResults[cur_domain_ns]; ok {
		var status = zdns.STATUS_NOERROR
		if protStatus, ok := protocolStatus[cur_domain_ns]; ok {
			status = protStatus
		}
		return res, nil, status, nil
	} else {
		return nil, nil, zdns.STATUS_NXDOMAIN, nil
	}
}

func InitTest(t *testing.T) (*zdns.GlobalConf, Lookup, MockLookupClient) {
	protocolStatus = make(map[domain_ns]zdns.Status)
	mockResults = make(map[domain_ns]Result)

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

	a := Lookup{Factory: rlf}
	mc := MockLookupClient{}

	return gc, a, mc
}

// Test specifying neither ipv4 not ipv6 flag looks up ipv4 by default
func TestOneA(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain1 + ".",
			Answer: "192.0.2.1",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", ns1, true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, nil)
}

// Test two ipv4 addresses
func TestTwoA(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain1 + ".",
			Answer: "192.0.2.1",
		},
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com",
				Answer: "192.0.2.2",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, domain1, ns1, true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1", "192.0.2.2"}, nil)
}

// Test ipv6 results not returned when lookupIpv6 is false
func TestQuadAWithoutFlag(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain1 + ".",
			Answer: "192.0.2.1",
		},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::1",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, _, _ := a.DoTargetedLookup(mc, domain1, ns1, true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, nil)
}

// Test ipv6 results
func TestOnlyQuadA(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   "example.com",
			Answer: "2001:db8::1",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", ns1, false, true)
	verifyResult(t, res.(IpResult), nil, []string{"2001:db8::1"})
}

// Test both ipv4 and ipv6 results are returned
func TestAandQuadA(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.1",
		},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::1",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", ns1, true, true)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, []string{"2001:db8::1"})
}

// Test two ipv6 addresses are returned
func TestTwoQuadA(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   "example.com",
			Answer: "2001:db8::1",
		},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::2",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", ns1, false, true)
	verifyResult(t, res.(IpResult), nil, []string{"2001:db8::1", "2001:db8::2"})
}

// Test that when miekg lookup returns no IPv4 or IPv6 addresses (empty record),
// we get empty result
func TestNoResults(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", ns1, true, true)
	verifyResult(t, res.(IpResult), nil, nil)
}

// Test CName lookup returns ipv4 address
func TestCname(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "cname.example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   "cname.example.com",
			Answer: "example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	dom2 := "example.com"

	domain_ns_2 := domain_ns{domain: dom2, ns: ns1}

	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.1",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, "cname.example.com", ns1, true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, nil)
}

// Test CName with lookupIpv6 as true returns ipv6 addresses
func TestQuadAWithCname(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "cname.example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   "cname.example.com",
			Answer: "2001:db8::3",
		},
			Answer{
				Ttl:    3600,
				Type:   "CNAME",
				Class:  "IN",
				Name:   "cname.example.com",
				Answer: "example.com.",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, "cname.example.com", ns1, false, true)
	verifyResult(t, res.(IpResult), nil, []string{"2001:db8::3"})
}

// Test that MX record with no A or AAAA records gives error
func TestUnexpectedMxOnly(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "MX",
			Class:  "IN",
			Name:   "example.com",
			Answer: "mail.example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, status, _ := a.DoTargetedLookup(mc, "example.com", ns1, true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test A and AAAA records in additionals
func TestMxAndAdditionals(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "MX",
			Class:  "IN",
			Name:   "example.com",
			Answer: "mail.example.com.",
		}},
		Additional: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.3",
		},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::4",
			}},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", ns1, true, true)
	verifyResult(t, res.(IpResult), []string{"192.0.2.3"}, []string{"2001:db8::4"})
}

// Test A record with IPv6 address gives error
func TestMismatchIpType(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "2001:db8::4",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, status, _ := a.DoTargetedLookup(mc, "example.com", ns1, true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test cname loops terminate with error
func TestCnameLoops(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "cname1.example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   "cname1.example.com.",
			Answer: "cname2.example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	dom2 := "cname2.example.com"

	domain_ns_2 := domain_ns{domain: dom2, ns: ns1}

	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   "cname2.example.com.",
			Answer: "cname1.example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, status, _ := a.DoTargetedLookup(mc, "cname1.example.com", ns1, true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test recursion in cname lookup with length > 10 terminate with error
func TestExtendedRecursion(t *testing.T) {
	gc, a, mc := InitTest(t)

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	// Create a CNAME chain of length > 10
	for i := 1; i < 12; i++ {
		domain_ns := domain_ns{
			domain: "cname" + strconv.Itoa(i) + ".example.com",
			ns:     ns1,
		}
		mockResults[domain_ns] = Result{
			Answers: []interface{}{Answer{
				Ttl:    3600,
				Type:   "CNAME",
				Class:  "IN",
				Name:   "cname" + strconv.Itoa(i) + ".example.com",
				Answer: "cname" + strconv.Itoa(i+1) + ".example.com",
			}},
			Additional:  nil,
			Authorities: nil,
			Protocol:    "",
			Flags:       DNSFlags{},
		}
	}

	res, _, status, _ := a.DoTargetedLookup(mc, "cname1.example.com", ns1, true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test empty non-terminal returns no error
func TestEmptyNonTerminal(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "leaf.intermediate.example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "leaf.intermediate.example.com.",
			Answer: "192.0.2.3",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	dom2 := "intermediate.example.com"

	domain_ns_2 := domain_ns{domain: dom2, ns: ns1}

	mockResults[domain_ns_2] = Result{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	// Verify leaf returns correctly
	res, _, _, _ := a.DoTargetedLookup(mc, "leaf.intermediate.example.com", ns1, true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.3"}, nil)

	// Verify empty non-terminal returns no answer
	res, _, _, _ = a.DoTargetedLookup(mc, "intermediate.example.com", ns1, true, true)
	verifyResult(t, res.(IpResult), nil, nil)
}

// Test Non-existent domain in the zone returns NXDOMAIN
func TestNXDomain(t *testing.T) {
	gc, a, mc := InitTest(t)
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	res, _, status, _ := a.DoTargetedLookup(mc, "nonexistent.example.com", ns1, true, true)
	if status != zdns.STATUS_NXDOMAIN {
		t.Errorf("Expected STATUS_NXDOMAIN status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test both ipv4 and ipv6 results are deduplicated before returning
func TestAandQuadADedup(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "cname1.example.com"
	domain2 := "cname2.example.com"
	domain3 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
	domain_ns_2 := domain_ns{domain: domain2, ns: ns1}
	domain_ns_3 := domain_ns{domain: domain3, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   domain1,
			Answer: domain2 + ".",
		}, Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   domain2,
			Answer: domain3 + ".",
		}, Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain3,
			Answer: "192.0.2.1",
		}, Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   domain3,
			Answer: "2001:db8::3",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   domain2,
			Answer: domain3 + ".",
		}, Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain3,
			Answer: "192.0.2.1",
		}, Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   domain3,
			Answer: "2001:db8::3",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	mockResults[domain_ns_3] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain3,
			Answer: "192.0.2.1",
		}, Answer{
			Ttl:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   domain3,
			Answer: "2001:db8::3",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, _, _ := a.DoTargetedLookup(mc, domain1, ns1, true, true)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, []string{"2001:db8::3"})
}

// Test server failure returns SERVFAIL
func TestServFail(t *testing.T) {
	gc, a, mc := InitTest(t)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{}
	name := "example.com"
	protocolStatus[domain_ns_1] = zdns.STATUS_SERVFAIL

	res, _, final_status, _ := a.DoTargetedLookup(mc, name, ns1, true, true)

	if final_status != protocolStatus[domain_ns_1] {
		t.Errorf("Expected %v status, got %v", protocolStatus, final_status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

/*NS lookup tests*/
func TestNsAInAdditional(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := false

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedServersMap := make(map[string]IpResult)
	expectedServersMap["ns1.example.com"] = IpResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := a.DoNSLookup(mc, "example.com", lookupIpv4, lookupIpv6, ns1)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestTwoNSInAdditional(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := false

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns2.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns2.example.com.",
				Answer: "192.0.2.4",
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedServersMap := make(map[string]IpResult)
	expectedServersMap["ns1.example.com"] = IpResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	expectedServersMap["ns2.example.com"] = IpResult{
		IPv4Addresses: []string{"192.0.2.4"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := a.DoNSLookup(mc, "example.com", lookupIpv4, lookupIpv6, ns1)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestAandQuadAInAdditional(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := true

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "2001:db8::4",
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedServersMap := make(map[string]IpResult)
	expectedServersMap["ns1.example.com"] = IpResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: []string{"2001:db8::4"},
	}
	res, _, _, _ := a.DoNSLookup(mc, "example.com", lookupIpv4, lookupIpv6, ns1)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestNsMismatchIpType(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := true

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "2001:db8::4",
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedServersMap := make(map[string]IpResult)
	expectedServersMap["ns1.example.com"] = IpResult{
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	res, _, _, _ := a.DoNSLookup(mc, "example.com", lookupIpv4, lookupIpv6, ns1)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestAandQuadALookup(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := true

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	dom2 := "ns1.example.com"

	domain_ns_2 := domain_ns{domain: dom2, ns: ns1}

	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "2001:db8::4",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedServersMap := make(map[string]IpResult)
	expectedServersMap["ns1.example.com"] = IpResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: []string{"2001:db8::4"},
	}
	res, _, _, _ := a.DoNSLookup(mc, "example.com", lookupIpv4, lookupIpv6, ns1)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestNsNXDomain(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := false

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")

	_, _, status, _ := a.DoNSLookup(mc, "nonexistent.example.com", lookupIpv4, lookupIpv6, ns1)

	assert.Equal(t, status, zdns.STATUS_NXDOMAIN)
}

func TestNsServFail(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := false

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{}
	protocolStatus[domain_ns_1] = zdns.STATUS_SERVFAIL

	res, _, status, _ := a.DoNSLookup(mc, "example.com", lookupIpv4, lookupIpv6, ns1)
	serversLength := len(res.Servers)

	assert.Equal(t, status, protocolStatus[domain_ns_1])
	assert.Equal(t, serversLength, 0)
}

func TestErrorInTargetedLookup(t *testing.T) {
	gc, a, mc := InitTest(t)
	lookupIpv4 := true
	lookupIpv6 := true

	domain1 := "example.com"
	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	protocolStatus[domain_ns_1] = zdns.STATUS_ERROR

	res, _, status, _ := a.DoNSLookup(mc, "example.com", lookupIpv4, lookupIpv6, ns1)
	assert.Equal(t, len(res.Servers), 0)
	assert.Equal(t, status, protocolStatus[domain_ns_1])
}

// Test One NS with one IP with only ipv4-lookup
func TestAllNsLookupOneNs(t *testing.T) {
	gc, a, mc := InitTest(t)

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain1 := "example.com"
	ns_domain1 := "ns1.example.com"
	ipv4_1 := "192.0.2.1"
	ipv6_1 := "2001:db8::3"

	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ns_domain1 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   ns_domain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   ns_domain1 + ".",
				Answer: ipv6_1,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domain_ns_2 := domain_ns{domain: domain1, ns: ns2}
	ipv4_2 := "192.0.2.1"
	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_2,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns3 := net.JoinHostPort(ipv6_1, "53")
	domain_ns_3 := domain_ns{domain: domain1, ns: ns3}
	ipv4_3 := "192.0.2.2"
	mockResults[domain_ns_3] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_3,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedRes := []ExtendedResult{
		{
			Nameserver: ns_domain1,
			Status:     zdns.STATUS_NOERROR,
			Res:        mockResults[domain_ns_2],
		},
		{
			Nameserver: ns_domain1,
			Status:     zdns.STATUS_NOERROR,
			Res:        mockResults[domain_ns_3],
		},
	}

	res, _, _, _ := a.DoLookupAllNameservers(mc, "example.com", ns1)
	verifyCombinedResult(t, res.(CombinedResult).Results, expectedRes)
}

// Test One NS with two IPs with only ipv4-lookup
func TestAllNsLookupOneNsMultipleIps(t *testing.T) {
	gc, a, mc := InitTest(t)

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain1 := "example.com"
	ns_domain1 := "ns1.example.com"
	ipv4_1 := "192.0.2.1"
	ipv4_2 := "192.0.2.2"

	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ns_domain1 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   ns_domain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   ns_domain1 + ".",
				Answer: ipv4_2,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domain_ns_2 := domain_ns{domain: domain1, ns: ns2}
	ipv4_3 := "192.0.2.3"
	ipv6_1 := "2001:db8::1"
	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_3,
			},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv6_1,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns3 := net.JoinHostPort(ipv4_2, "53")
	domain_ns_3 := domain_ns{domain: domain1, ns: ns3}
	ipv4_4 := "192.0.2.4"
	ipv6_2 := "2001:db8::2"
	mockResults[domain_ns_3] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_4,
			},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv6_2,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedRes := []ExtendedResult{
		{
			Nameserver: ns_domain1,
			Status:     zdns.STATUS_NOERROR,
			Res:        mockResults[domain_ns_2],
		},
		{
			Nameserver: ns_domain1,
			Status:     zdns.STATUS_NOERROR,
			Res:        mockResults[domain_ns_3],
		},
	}

	res, _, _, _ := a.DoLookupAllNameservers(mc, "example.com", ns1)
	verifyCombinedResult(t, res.(CombinedResult).Results, expectedRes)
}

// Test One NS with two IPs with only ipv4-lookup
func TestAllNsLookupTwoNs(t *testing.T) {
	gc, a, mc := InitTest(t)

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain1 := "example.com"
	ns_domain1 := "ns1.example.com"
	ns_domain2 := "ns2.example.com"
	ipv4_1 := "192.0.2.1"
	ipv4_2 := "192.0.2.2"

	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ns_domain1 + ".",
			},
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ns_domain2 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   ns_domain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   ns_domain2 + ".",
				Answer: ipv4_2,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domain_ns_2 := domain_ns{domain: domain1, ns: ns2}
	ipv4_3 := "192.0.2.3"
	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_3,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns3 := net.JoinHostPort(ipv4_2, "53")
	domain_ns_3 := domain_ns{domain: domain1, ns: ns3}
	ipv4_4 := "192.0.2.4"
	mockResults[domain_ns_3] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_4,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	expectedRes := []ExtendedResult{
		{
			Nameserver: ns_domain1,
			Status:     zdns.STATUS_NOERROR,
			Res:        mockResults[domain_ns_2],
		},
		{
			Nameserver: ns_domain2,
			Status:     zdns.STATUS_NOERROR,
			Res:        mockResults[domain_ns_3],
		},
	}

	res, _, _, _ := a.DoLookupAllNameservers(mc, "example.com", ns1)
	verifyCombinedResult(t, res.(CombinedResult).Results, expectedRes)
}

// Test error in A lookup via targeted lookup records
func TestAllNsLookupErrorInOne(t *testing.T) {
	gc, a, mc := InitTest(t)

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain1 := "example.com"
	ns_domain1 := "ns1.example.com"
	ipv4_1 := "192.0.2.1"
	ipv4_2 := "192.0.2.2"

	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
	mockResults[domain_ns_1] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ns_domain1 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   ns_domain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   ns_domain1 + ".",
				Answer: ipv4_2,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domain_ns_2 := domain_ns{domain: domain1, ns: ns2}
	ipv4_3 := "192.0.2.3"
	ipv6_1 := "2001:db8::1"
	mockResults[domain_ns_2] = Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_3,
			},
			Answer{
				Ttl:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv6_1,
			},
		},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns3 := net.JoinHostPort(ipv4_2, "53")
	domain_ns_3 := domain_ns{domain: domain1, ns: ns3}
	protocolStatus[domain_ns_3] = zdns.STATUS_SERVFAIL
	mockResults[domain_ns_3] = Result{}

	expectedRes := []ExtendedResult{
		{
			Nameserver: ns_domain1,
			Status:     zdns.STATUS_NOERROR,
			Res:        mockResults[domain_ns_2],
		},
		{
			Nameserver: ns_domain1,
			Status:     zdns.STATUS_SERVFAIL,
			Res:        mockResults[domain_ns_3],
		},
	}

	res, _, _, _ := a.DoLookupAllNameservers(mc, "example.com", ns1)
	verifyCombinedResult(t, res.(CombinedResult).Results, expectedRes)
}

func TestAllNsLookupNXDomain(t *testing.T) {
	gc, a, mc := InitTest(t)

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	res, _, status, _ := a.DoLookupAllNameservers(mc, "example.com", ns1)

	assert.Equal(t, status, zdns.STATUS_NXDOMAIN)
	assert.Equal(t, res, nil)
}

func TestAllNsLookupServFail(t *testing.T) {
	gc, a, mc := InitTest(t)

	ns1 := net.JoinHostPort(gc.NameServers[0], "53")
	domain1 := "example.com"
	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}

	protocolStatus[domain_ns_1] = zdns.STATUS_SERVFAIL
	mockResults[domain_ns_1] = Result{}

	res, _, status, _ := a.DoLookupAllNameservers(mc, "example.com", ns1)

	assert.Equal(t, status, zdns.STATUS_SERVFAIL)
	assert.Equal(t, res, nil)
}

func TestParseAnswer(t *testing.T) {
	var rr dns.RR

	// typical A record
	rr = &dns.A{
		Hdr: dns.RR_Header{
			Name:     "ipv4.example.com",
			Rrtype:   dns.TypeA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		A: net.ParseIP("192.0.2.1"),
	}

	res := ParseAnswer(rr)
	verifyAnswer(t, res, rr, "192.0.2.1")

	// typical AAAA record
	rr = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "ipv6.example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		AAAA: net.ParseIP("2001:db8::1"),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "2001:db8::1")

	// loopback AAAA record
	rr = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "ipv6.example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		AAAA: net.ParseIP("::1"),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "::1")

	// unspecified AAAA record
	rr = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "ipv6.example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		AAAA: net.ParseIP("::"),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "::")

	// IPv4-Mapped IPv6 address as AAAA record
	rr = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "ipv6.example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		AAAA: net.ParseIP("::ffff:192.0.2.1"),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "::ffff:192.0.2.1")

	// IPv4-compatible IPv6 address as AAAA record
	rr = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "ipv6.example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		AAAA: net.ParseIP("::192.0.2.1"),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "::192.0.2.1")

	// IPv4 in AAAA record gets prepended by ::ffff:
	rr = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "ipv6.example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		AAAA: net.ParseIP("192.0.2.1"),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "::ffff:192.0.2.1")

	// Incorrect cname record in expected A record
	rr = &dns.A{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeCNAME,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		A: net.ParseIP("cname.example.com."),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "<nil>")

	// Incorrect cname record in expected AAAA record
	rr = &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeCNAME,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		AAAA: net.ParseIP("cname.example.com."),
	}

	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "<nil>")

	// NAPTR record für aa e.164 phone number (+1-234-555-6789)
	rr = &dns.NAPTR{
		Hdr: dns.RR_Header{
			Name:     "9.8.7.6.5.5.5.4.3.2.1.e164.arpa",
			Rrtype:   dns.TypeNAPTR,
			Class:    dns.ClassINET,
			Ttl:      300,
			Rdlength: 0,
		},
		Order:       100,
		Preference:  10,
		Flags:       "u",
		Service:     "sip+E2U",
		Regexp:      "!^.*$!sip:number@example.com!",
		Replacement: ".",
	}

	res = ParseAnswer(rr)
	answer, ok := res.(NAPTRAnswer)
	if !ok {
		t.Error("Failed to parse record")
		return
	}
	verifyAnswer(t, answer.Answer, rr, "")
	if answer.Order != 100 {
		t.Errorf("Unxpected order. Expected %v, got %v", 100, answer.Order)
	}
	if answer.Preference != 10 {
		t.Errorf("Unxpected preference. Expected %v, got %v", 10, answer.Preference)
	}
	if answer.Flags != "u" {
		t.Errorf("Unxpected flags. Expected %v, got %v", "u", answer.Flags)
	}
	if answer.Service != "sip+E2U" {
		t.Errorf("Unxpected service. Expected %v, got %v", "sip+E2U", answer.Service)
	}
	if answer.Regexp != "!^.*$!sip:number@example.com!" {
		t.Errorf("Unxpected regexp. Expected %v, got %v", "!^.*$!sip:number@example.com!", answer.Regexp)
	}
	if answer.Replacement != "." {
		t.Errorf("Unxpected replacement. Expected %v, got %v", ".", answer.Replacement)
	}

	// MX record
	rr = &dns.MX{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeMX,
			Class:    dns.ClassINET,
			Ttl:      7200,
			Rdlength: 16,
		},
		Preference: 1,
		Mx:         "mail.example.com.",
	}
	res = ParseAnswer(rr)
	verifyAnswer(t, res.(PrefAnswer).Answer, rr, "mail.example.com.")

	// NS record
	rr = &dns.NS{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeMX,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		Ns: "ns1.example.com.",
	}
	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "ns1.example.com.")

	// SPF
	rr = &dns.SPF{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeSPF,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		Txt: []string{"v=spf1 mx include:_spf.google.com -all"},
	}
	res = ParseAnswer(rr)
	verifyAnswer(t, res, rr, "example.com\t3600\tIN\tSPF\t\"v=spf1 mx include:_spf.google.com -all\"")

	// NSEC record
	rr = &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeNSEC,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 0,
		},
		NextDomain: "www.example.com.",
		TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	res = ParseAnswer(rr)
	nsecAnswer, ok := res.(NSECAnswer)
	if !ok {
		t.Error("Failed to parse NSEC record")
		return
	}
	verifyAnswer(t, nsecAnswer.Answer, rr, "")
	if nsecAnswer.NextDomain != "www.example.com" {
		t.Errorf("Unexpected NSEC NextDomain. Expected %v, got %v", "www.example.com", nsecAnswer.NextDomain)
	}
	if nsecAnswer.TypeBitMap != "RRSIG NSEC DNSKEY" {
		t.Errorf("Unexpected NSEC TypeBitMap. Expected %v, got %v", "RRSIG NSEC DNSKEY", nsecAnswer.TypeBitMap)
	}

	// NSEC3 record
	rr = &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:     "onib9mgub9h0rml3cdf5bgrj59dkjhvk.example.com", // example.com
			Rrtype:   dns.TypeNSEC3,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 0,
		},
		Hash: 1,
		Flags: 0,
		Iterations: 0,
		Salt: "",
		NextDomain: "MIFDNDT3NFF3OD53O7TLA1HRFF95JKUK", // www.example.com
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}
	res = ParseAnswer(rr)
	nsec3Answer, ok := res.(NSEC3Answer)
	if !ok {
		t.Error("Failed to parse NSEC3 record")
	}
	verifyAnswer(t, nsec3Answer.Answer, rr, "")
	if nsec3Answer.HashAlgorithm != 1 {
		t.Errorf("Unexpected NSEC3 HashAlgorithm. Expected %v, got %v", 1, nsec3Answer.HashAlgorithm)
	}
	if nsec3Answer.Flags != 0 {
		t.Errorf("Unexpected NSEC3 Flags. Expected %v, got %v", 0, nsec3Answer.Flags)
	}
	if nsec3Answer.Iterations != 0 {
		t.Errorf("Unexpected NSEC3 Iterations. Expected %v, got %v", 0, nsec3Answer.Iterations)
	}
	if nsec3Answer.Salt != "" {
		t.Errorf("Unexpected NSEC3 Salt. Expected %v, got %v", "", nsec3Answer.Salt)
	}
	if nsec3Answer.NextDomain != "MIFDNDT3NFF3OD53O7TLA1HRFF95JKUK" {
		t.Errorf("Unexpected NSEC3 NextDomain. Expected %v, got %v", "MIFDNDT3NFF3OD53O7TLA1HRFF95JKUK", nsec3Answer.NextDomain)
	}
	if nsec3Answer.TypeBitMap != "A RRSIG" {
		t.Errorf("Unexpected NSEC3 TypeBitMap. Expected %v, got %v", "A RRSIG", nsec3Answer.TypeBitMap)
	}

	// OPT record
	rr = &dns.OPT{
		Hdr: dns.RR_Header{
			Name:     ".",
			Rrtype:   dns.TypeOPT,
			Class:    1232,
		},
	}
	res = ParseAnswer(rr)
	ednsAnswer, ok := res.(EDNSAnswer)
	if !ok {
		t.Error("Failed to parse OPT record")
		return
	}
	if ednsAnswer.Version != 0 {
		t.Errorf("Unexpected EDNS Version. Expected %v, got %v", 0, ednsAnswer.Version)
	}
	if ednsAnswer.UDPSize != 1232 {
		t.Errorf("Unexpected EDNS UDP Size. Expected %v, got %v", 0, ednsAnswer.UDPSize)
	}
	if ednsAnswer.Flags != "" {
		t.Errorf("Unexpected EDNS Flags. Expected %v, got %v", 0, ednsAnswer.Flags)
	}
}

func verifyAnswer(t *testing.T, answer interface{}, original dns.RR, expectedAnswer interface{}) {
	ans, ok := answer.(Answer)
	if !ok {
		t.Error("Failed to parse record")
		return
	}

	if ans.Name != original.Header().Name {
		t.Errorf("Unxpected name. Expected %v, got %v", original.Header().Name, ans.Name)
	}
	if ans.RrType != original.Header().Rrtype {
		t.Errorf("Unxpected RR type. Expected %v, got %v", original.Header().Rrtype, ans.RrType)
	}
	if ans.Type != dns.TypeToString[original.Header().Rrtype] {
		t.Errorf("Unxpected RR type (string). Expected %v, got %v", dns.TypeToString[original.Header().Rrtype], ans.Type)
	}
	if ans.RrClass != original.Header().Class {
		t.Errorf("Unxpected RR class. Expected %v, got %v", original.Header().Class, ans.RrClass)
	}
	if ans.Class != dns.ClassToString[original.Header().Class] {
		t.Errorf("Unxpected RR class (string). Expected %v, got %v", dns.TypeToString[original.Header().Class], ans.Class)
	}
	if ans.Answer != expectedAnswer {
		t.Errorf("Unxpected answer. Expected %v, got %v", expectedAnswer, ans.Answer)
	}
}

func TestLookup_DoTxtLookup_1(t *testing.T) {
	testRegexp := regexp.MustCompile(".*")
	var txtRecord = Lookup{Factory: &RoutineLookupFactory{PrefixRegexp: testRegexp}}
	input := Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "TXT",
			Class:  "IN",
			Name:   "example.com",
			Answer: "asdfasdfasdf",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	resultString, err := txtRecord.FindTxtRecord(input)
	assert.NilError(t, err)
	assert.Equal(t, "asdfasdfasdf", resultString)
}

func TestLookup_DoTxtLookup_2(t *testing.T) {
	testRegexp := regexp.MustCompile("^google-site-verification=.*")
	var txtRecord = Lookup{Factory: &RoutineLookupFactory{PrefixRegexp: testRegexp}}
	input := Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "TXT",
				Class:  "IN",
				Name:   "example.com",
				Answer: "testing TXT prefix: hello world!",
			}, Answer{
				Ttl:    3600,
				Type:   "TXT",
				Class:  "IN",
				Name:   "example.com",
				Answer: "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	resultString, err := txtRecord.FindTxtRecord(input)
	assert.NilError(t, err)
	assert.Equal(t, "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0", resultString)
}

func TestLookup_DoTxtLookup_3(t *testing.T) {
	testRegexp := regexp.MustCompile("(?i)^v=spf1.*")
	var txtRecord = Lookup{Factory: &RoutineLookupFactory{PrefixRegexp: testRegexp}}
	input := Result{
		Answers: []interface{}{
			Answer{
				Ttl:    3600,
				Type:   "TXT",
				Class:  "IN",
				Name:   "example.com",
				Answer: "testing TXT prefix: hello world!",
			}, Answer{
				Ttl:    3600,
				Type:   "TXT",
				Class:  "IN",
				Name:   "example.com",
				Answer: "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0s",
			}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	resultString, err := txtRecord.FindTxtRecord(input)
	assert.Error(t, err, "no such TXT record found")
	assert.Assert(t, resultString == "")
}

func TestLookup_DoTxtLookup_4(t *testing.T) {
	testRegexp := regexp.MustCompile("(?i)^v=spf1.*")
	var txtRecord = Lookup{Factory: &RoutineLookupFactory{PrefixRegexp: testRegexp}}
	input := Result{
		Answers: []interface{}{},
	}
	resultString, err := txtRecord.FindTxtRecord(input)
	assert.Error(t, err, "no such TXT record found")
	assert.Assert(t, resultString == "")
}

func TestLookup_DoTxtLookup_5(t *testing.T) {
	var txtRecord = Lookup{Factory: &RoutineLookupFactory{}}
	input := Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "TXT",
			Class:  "IN",
			Name:   "example.com",
			Answer: "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0s",
		}},
	}
	resultString, err := txtRecord.FindTxtRecord(input)
	assert.NilError(t, err)
	assert.Equal(t, "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0s", resultString)
}

func verifyResult(t *testing.T, res IpResult, ipv4 []string, ipv6 []string) {
	if !reflect.DeepEqual(ipv4, res.IPv4Addresses) {
		t.Errorf("Expected %v, Received %v IPv4 address(es)", ipv4, res.IPv4Addresses)
	}
	if !reflect.DeepEqual(ipv6, res.IPv6Addresses) {
		t.Errorf("Expected %v, Received %v IPv6 address(es)", ipv6, res.IPv6Addresses)
	}
}

func verifyNsResult(t *testing.T, servers []NSRecord, expectedServersMap map[string]IpResult) {
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

func verifyCombinedResult(t *testing.T, records []ExtendedResult, expectedRecords []ExtendedResult) {
	if !reflect.DeepEqual(records, expectedRecords) {
		t.Errorf("Combined result not matching, expected %v, found %v", expectedRecords, records)
	}
}
