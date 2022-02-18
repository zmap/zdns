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

var mockResults = make(map[string]Result)

var status = zdns.STATUS_NOERROR

type MockLookupClient struct{}

func (mc MockLookupClient) ProtocolLookup(s *Lookup, q Question, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if res, ok := mockResults[q.Name]; ok {
		return res, nil, status, nil
	} else {
		return nil, nil, zdns.STATUS_NXDOMAIN, nil
	}
}

func InitTest(t *testing.T) (*zdns.GlobalConf, Lookup, MockLookupClient) {
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
	mockResults["example.com"] = Result{
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
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, nil)
}

// Test two ipv4 addresses
func TestTwoA(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
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
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1", "192.0.2.2"}, nil)
}

// Test ipv6 results not returned when lookupIpv6 is false
func TestQuadAWithoutFlag(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
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

	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, nil)
}

// Test ipv6 results
func TestOnlyQuadA(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
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

	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], false, true)
	verifyResult(t, res.(IpResult), nil, []string{"2001:db8::1"})
}

// Test both ipv4 and ipv6 results are returned
func TestAandQuadA(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
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
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, true)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, []string{"2001:db8::1"})
}

// Test two ipv6 addresses are returned
func TestTwoQuadA(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
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
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], false, true)
	verifyResult(t, res.(IpResult), nil, []string{"2001:db8::1", "2001:db8::2"})
}

// Test that when miekg lookup returns no IPv4 or IPv6 addresses (empty record),
// we get empty result
func TestNoResults(t *testing.T) {
	gc, a, mc := InitTest(t)

	mockResults["example.com"] = Result{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, true)
	verifyResult(t, res.(IpResult), nil, nil)
}

// Test CName lookup returns ipv4 address
func TestCname(t *testing.T) {
	gc, a, mc := InitTest(t)

	mockResults["cname.example.com"] = Result{
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
	mockResults["example.com"] = Result{
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
	res, _, _, _ := a.DoTargetedLookup(mc, "cname.example.com", gc.NameServers[0], true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.1"}, nil)
}

// Test CName with lookupIpv6 as true returns ipv6 addresses
func TestQuadAWithCname(t *testing.T) {
	gc, a, mc := InitTest(t)

	mockResults["cname.example.com"] = Result{
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
	res, _, _, _ := a.DoTargetedLookup(mc, "cname.example.com", gc.NameServers[0], false, true)
	verifyResult(t, res.(IpResult), nil, []string{"2001:db8::3"})
}

// Test that MX record with no A or AAAA records gives error
func TestUnexpectedMxOnly(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
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

	res, _, status, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test A and AAAA records in additionals
func TestMxAndAdditionals(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
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

	res, _, _, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, true)
	verifyResult(t, res.(IpResult), []string{"192.0.2.3"}, []string{"2001:db8::4"})
}

// Test A record with IPv6 address gives error
func TestMismatchIpType(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{
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

	res, _, status, _ := a.DoTargetedLookup(mc, "example.com", gc.NameServers[0], true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test cname loops terminate with error
func TestCnameLoops(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["cname1.example.com"] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   "cname1.example.com",
			Answer: "cname2.example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	mockResults["cname2.example.com"] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   "cname2.example.com",
			Answer: "cname1.example.com.",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, status, _ := a.DoTargetedLookup(mc, "cname1.example.com", gc.NameServers[0], true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test recursion in cname lookup with length > 10 terminate with error
func TestExtendedRecursion(t *testing.T) {
	gc, a, mc := InitTest(t)
	// Create a CNAME chain of length > 10
	for i := 1; i < 12; i++ {
		mockResults["cname"+strconv.Itoa(i)+".example.com"] = Result{
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

	res, _, status, _ := a.DoTargetedLookup(mc, "cname1.example.com", gc.NameServers[0], true, true)

	if status != zdns.STATUS_ERROR {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test empty non-terminal returns no error
func TestEmptyNonTerminal(t *testing.T) {
	gc, a, mc := InitTest(t)
	mockResults["leaf.intermediate.example.com"] = Result{
		Answers: []interface{}{Answer{
			Ttl:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "leaf.intermediate.example.com",
			Answer: "192.0.2.3",
		}},
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	mockResults["intermediate.example.com"] = Result{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	// Verify leaf returns correctly
	res, _, _, _ := a.DoTargetedLookup(mc, "leaf.intermediate.example.com", gc.NameServers[0], true, false)
	verifyResult(t, res.(IpResult), []string{"192.0.2.3"}, nil)

	// Verify empty non-terminal returns no answer
	res, _, status, _ = a.DoTargetedLookup(mc, "intermediate.example.com", gc.NameServers[0], true, true)
	verifyResult(t, res.(IpResult), nil, nil)
}

// Test Non-existent domain in the zone returns NXDOMAIN
func TestNXDomain(t *testing.T) {
	gc, a, mc := InitTest(t)
	res, _, status, _ := a.DoTargetedLookup(mc, "nonexistent.example.com", gc.NameServers[0], true, true)
	if status != zdns.STATUS_NXDOMAIN {
		t.Errorf("Expected STATUS_NXDOMAIN status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test server failure returns SERVFAIL
func TestServFail(t *testing.T) {
	status = zdns.STATUS_SERVFAIL
	gc, a, mc := InitTest(t)
	mockResults["example.com"] = Result{}
	name := "example.com"
	res, _, final_status, _ := a.DoTargetedLookup(mc, name, gc.NameServers[0], true, true)

	if final_status != status {
		t.Errorf("Expected %v status, got %v", status, final_status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
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

	// TODO: test remaining RR types
}

func verifyAnswer(t *testing.T, answer interface{}, original dns.RR, expectedAnswer string) {
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
