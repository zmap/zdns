// /*
// * ZDNS Copyright 2022 Regents of the University of Michigan
// *
// * Licensed under the Apache License, Version 2.0 (the "License"); you may not
// * use this file except in compliance with the License. You may obtain a copy
// * of the License at http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// * implied. See the License for the specific language governing
// * permissions and limitations under the License.
// */
package alookup

//
//import (
//	"github.com/stretchr/testify/assert"
//	"github.com/zmap/zdns/pkg/zdns"
//	"net"
//	"strconv"
//	"testing"
//)
//
//
//type domain_ns struct {
//	domain string
//	ns     string
//}
//
//type minimalRecords struct {
//	zdns.Status        zdns.Status
//	IPv4Addresses []string
//	IPv6Addresses []string
//}
//
//var mockResults = make(map[domain_ns]SingleQueryResult)
//
//var protocolzdns.Status = make(map[domain_ns]zdns.Status)
//
//type MockLookupClient struct{}
//
//func (mc MockLookupClient) DoSingleDstServerLookup(r *zdns.Resolver, q Question, nameServer string, isIterative bool) (*SingleQueryResult, Trace, zdns.Status, error) {
//	cur_domain_ns := domain_ns{domain: q.Name, ns: nameServer}
//	if res, ok := mockResults[cur_domain_ns]; ok {
//		var status = zdns.STATUS_NOERROR
//		if protzdns.Status, ok := protocolzdns.Status[cur_domain_ns]; ok {
//			status = protzdns.Status
//		}
//		return &res, nil, status, nil
//	} else {
//		return &SingleQueryResult{}, nil, zdns.STATUS_NXDOMAIN, nil
//	}
//}
//
//func InitTest(t *testing.T) *zdns.ResolverConfig {
//	protocolzdns.Status = make(map[domain_ns]zdns.Status)
//	mockResults = make(map[domain_ns]SingleQueryResult)
//
//	mc := MockLookupClient{}
//	config := Newzdns.ResolverConfig()
//	config.ExternalNameServers = []string{"127.0.0.1"}
//	config.LookupClient = mc
//
//	return config
//}
//
//// Test specifying neither ipv4 not ipv6 flag looks up ipv4 by default
//func TestOneA(t *testing.T) {
//	config := InitTest(t)
//	resolver, err := Initzdns.Resolver(config)
//	assert.Nil(t, err)
//
//	domain1 := "example.com"
//	ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//	domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//	mockResults[domain_ns_1] = SingleQueryResult{
//		Answers: []interface{}{Answer{
//			Ttl:    3600,
//			Type:   "A",
//			Class:  "IN",
//			Name:   domain1 + ".",
//			Answer: "192.0.2.1",
//		}},
//		Additional:  nil,
//		Authorities: nil,
//		Protocol:    "",
//		Flags:       DNSFlags{},
//	}
//	res, _, _, _ := modules.DoTargetedLookup(resolver, "example.com", ns1, true, false)
//	verifyResult(t, res, []string{"192.0.2.1"}, nil)
//}
//
//// Test two ipv4 addresses
//
//	func TestTwoA(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "A",
//				Class:  "IN",
//				Name:   domain1 + ".",
//				Answer: "192.0.2.1",
//			},
//				Answer{
//					Ttl:    3600,
//					Type:   "A",
//					Class:  "IN",
//					Name:   "example.com",
//					Answer: "192.0.2.2",
//				}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//		res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, true, false)
//		verifyResult(t, res, []string{"192.0.2.1", "192.0.2.2"}, nil)
//	}
//
//// Test ipv6 results not returned when lookupIpv6 is false
//
//	func TestQuadAWithoutFlag(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "A",
//				Class:  "IN",
//				Name:   domain1 + ".",
//				Answer: "192.0.2.1",
//			},
//				Answer{
//					Ttl:    3600,
//					Type:   "AAAA",
//					Class:  "IN",
//					Name:   "example.com",
//					Answer: "2001:db8::1",
//				}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, true, false)
//		verifyResult(t, res, []string{"192.0.2.1"}, nil)
//	}
//
//// Test ipv6 results
//
//	func TestOnlyQuadA(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "AAAA",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "2001:db8::1",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, false, true)
//		verifyResult(t, res, nil, []string{"2001:db8::1"})
//	}
//
//// Test both ipv4 and ipv6 results are returned
//
//	func TestAandQuadA(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "A",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "192.0.2.1",
//			},
//				Answer{
//					Ttl:    3600,
//					Type:   "AAAA",
//					Class:  "IN",
//					Name:   "example.com",
//					Answer: "2001:db8::1",
//				}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//		res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, true, true)
//		verifyResult(t, res, []string{"192.0.2.1"}, []string{"2001:db8::1"})
//	}
//
//// Test two ipv6 addresses are returned
//
//	func TestTwoQuadA(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "AAAA",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "2001:db8::1",
//			},
//				Answer{
//					Ttl:    3600,
//					Type:   "AAAA",
//					Class:  "IN",
//					Name:   "example.com",
//					Answer: "2001:db8::2",
//				}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//		res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, false, true)
//		verifyResult(t, res, nil, []string{"2001:db8::1", "2001:db8::2"})
//	}
//
//// Test that when miekg lookup returns no IPv4 or IPv6 addresses (empty record),
//// we get empty result
//
//	func TestNoResults(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers:     nil,
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//		res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, true, true)
//		verifyResult(t, res, nil, nil)
//	}
//
//// Test CName lookup returns ipv4 address
//
//	func TestCname(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "cname.example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "CNAME",
//				Class:  "IN",
//				Name:   "cname.example.com",
//				Answer: "example.com.",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		dom2 := "example.com"
//
//		domain_ns_2 := domain_ns{domain: dom2, ns: ns1}
//
//		mockResults[domain_ns_2] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "A",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "192.0.2.1",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//		res, _, _, _ := resolver.DoTargetedLookup("cname.example.com", ns1, true, false)
//		verifyResult(t, res, []string{"192.0.2.1"}, nil)
//	}
//
//// Test CName with lookupIpv6 as true returns ipv6 addresses
//
//	func TestQuadAWithCname(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "cname.example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "AAAA",
//				Class:  "IN",
//				Name:   "cname.example.com",
//				Answer: "2001:db8::3",
//			},
//				Answer{
//					Ttl:    3600,
//					Type:   "CNAME",
//					Class:  "IN",
//					Name:   "cname.example.com",
//					Answer: "example.com.",
//				}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//		res, _, _, _ := resolver.DoTargetedLookup("cname.example.com", ns1, false, true)
//		verifyResult(t, res, nil, []string{"2001:db8::3"})
//	}
//
//// Test that MX record with no A or AAAA records gives error
//
//	func TestUnexpectedMxOnly(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "MX",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "mail.example.com.",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		res, _, status, _ := resolver.DoTargetedLookup("example.com", ns1, true, true)
//
//		if status != zdns.STATUS_ERROR {
//			t.Errorf("Expected ERROR status, got %v", status)
//		} else if res != nil {
//			t.Errorf("Expected no results, got %v", res)
//		}
//	}
//
//// Test A and AAAA records in additionals
//
//	func TestMxAndAdditionals(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "MX",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "mail.example.com.",
//			}},
//			Additional: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "A",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "192.0.2.3",
//			},
//				Answer{
//					Ttl:    3600,
//					Type:   "AAAA",
//					Class:  "IN",
//					Name:   "example.com",
//					Answer: "2001:db8::4",
//				}},
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, true, true)
//		verifyResult(t, res, []string{"192.0.2.3"}, []string{"2001:db8::4"})
//	}
//
//// Test A record with IPv6 address gives error
//
//	func TestMismatchIpType(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "A",
//				Class:  "IN",
//				Name:   "example.com",
//				Answer: "2001:db8::4",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		res, _, status, _ := resolver.DoTargetedLookup("example.com", ns1, true, true)
//
//		if status != zdns.STATUS_ERROR {
//			t.Errorf("Expected ERROR status, got %v", status)
//		} else if res != nil {
//			t.Errorf("Expected no results, got %v", res)
//		}
//	}
//
//// Test cname loops terminate with error
//
//	func TestCnameLoops(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "cname1.example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "CNAME",
//				Class:  "IN",
//				Name:   "cname1.example.com.",
//				Answer: "cname2.example.com.",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		dom2 := "cname2.example.com"
//
//		domain_ns_2 := domain_ns{domain: dom2, ns: ns1}
//
//		mockResults[domain_ns_2] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "CNAME",
//				Class:  "IN",
//				Name:   "cname2.example.com.",
//				Answer: "cname1.example.com.",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		res, _, status, _ := resolver.DoTargetedLookup("cname1.example.com", ns1, true, true)
//
//		if status != zdns.STATUS_ERROR {
//			t.Errorf("Expected ERROR status, got %v", status)
//		} else if res != nil {
//			t.Errorf("Expected no results, got %v", res)
//		}
//	}
//
//// Test recursion in cname lookup with length > 10 terminate with error
//
//	func TestExtendedRecursion(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		// Create a CNAME chain of length > 10
//		for i := 1; i < 12; i++ {
//			domain_ns := domain_ns{
//				domain: "cname" + strconv.Itoa(i) + ".example.com",
//				ns:     ns1,
//			}
//			mockResults[domain_ns] = SingleQueryResult{
//				Answers: []interface{}{Answer{
//					Ttl:    3600,
//					Type:   "CNAME",
//					Class:  "IN",
//					Name:   "cname" + strconv.Itoa(i) + ".example.com",
//					Answer: "cname" + strconv.Itoa(i+1) + ".example.com",
//				}},
//				Additional:  nil,
//				Authorities: nil,
//				Protocol:    "",
//				Flags:       DNSFlags{},
//			}
//		}
//
//		res, _, status, _ := resolver.DoTargetedLookup("cname1.example.com", ns1, true, true)
//
//		if status != zdns.STATUS_ERROR {
//			t.Errorf("Expected ERROR status, got %v", status)
//		} else if res != nil {
//			t.Errorf("Expected no results, got %v", res)
//		}
//	}
//
//// Test empty non-terminal returns no error
//
//	func TestEmptyNonTerminal(t *testing.T) {
//		config := InitTest(t)
//		resolver, err := Initzdns.Resolver(config)
//		assert.Nil(t, err)
//
//		domain1 := "leaf.intermediate.example.com"
//		ns1 := net.JoinHostPort(resolver.externalNameServers[0], "53")
//		domain_ns_1 := domain_ns{domain: domain1, ns: ns1}
//
//		mockResults[domain_ns_1] = SingleQueryResult{
//			Answers: []interface{}{Answer{
//				Ttl:    3600,
//				Type:   "A",
//				Class:  "IN",
//				Name:   "leaf.intermediate.example.com.",
//				Answer: "192.0.2.3",
//			}},
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//
//		dom2 := "intermediate.example.com"
//
//		domain_ns_2 := domain_ns{domain: dom2, ns: ns1}
//
//		mockResults[domain_ns_2] = SingleQueryResult{
//			Answers:     nil,
//			Additional:  nil,
//			Authorities: nil,
//			Protocol:    "",
//			Flags:       DNSFlags{},
//		}
//		// Verify leaf returns correctly
//		res, _, _, _ := resolver.DoTargetedLookup("leaf.intermediate.example.com", ns1, true, false)
//		verifyResult(t, res, []string{"192.0.2.3"}, nil)
//
//		// Verify empty non-terminal returns no answer
//		res, _, _, _ = resolver.DoTargetedLookup("intermediate.example.com", ns1, true, true)
//		verifyResult(t, res, nil, nil)
//	}
