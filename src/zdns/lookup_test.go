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
package zdns

import (
	"encoding/hex"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/zmap/dns"
)

type domainNS struct {
	domain string
	ns     string
}

var mockResults = make(map[domainNS]SingleQueryResult)

var protocolStatus = make(map[domainNS]Status)

type MockLookupClient struct{}

func (mc MockLookupClient) DoSingleDstServerLookup(r *Resolver, q Question, nameServer string, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	curDomainNs := domainNS{domain: q.Name, ns: nameServer}
	if res, ok := mockResults[curDomainNs]; ok {
		var status = StatusNoError
		if protStatus, ok := protocolStatus[curDomainNs]; ok {
			status = protStatus
		}
		return &res, nil, status, nil
	} else {
		return &SingleQueryResult{}, nil, StatusNXDomain, nil
	}
}

func InitTest(t *testing.T) *ResolverConfig {
	protocolStatus = make(map[domainNS]Status)
	mockResults = make(map[domainNS]SingleQueryResult)

	mc := MockLookupClient{}
	config := NewResolverConfig()
	config.ExternalNameServers = []string{"127.0.0.1"}
	config.LookupClient = mc

	return config
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
		Hash:       1,
		Flags:      0,
		Iterations: 0,
		Salt:       "",
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
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  1232,
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

func TestParseEdnsAnswerNsid1(t *testing.T) {
	rr := &dns.OPT{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
		Option: []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: hex.EncodeToString([]byte("test_nsid"))}},
	}
	res := ParseAnswer(rr)
	ednsAnswer, ok := res.(EDNSAnswer)
	assert.True(t, ok, "Failed to parse OPT record")
	assert.Equal(t, uint8(0), ednsAnswer.Version, "Unexpected EDNS Version. Expected %v, got %v", 0, ednsAnswer.Version)
	assert.Equal(t, uint16(1232), ednsAnswer.UDPSize, "Unexpected EDNS UDP Size. Expected %v, got %v", 0, ednsAnswer.UDPSize)
	assert.Empty(t, ednsAnswer.Flags, "Unexpected EDNS Flags. Expected %v, got %v", 0, ednsAnswer.Flags)
	assert.Equal(t, "test_nsid", ednsAnswer.NSID.Nsid, "Unexpected NSID string. Expected %v, got %v", "test_nsid", ednsAnswer.NSID.Nsid)
}

func TestParseEdnsAnswerNsid2(t *testing.T) {
	rr := &dns.OPT{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
		Option: []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "not_a_hex_string"}},
	}
	res := ParseAnswer(rr)
	ednsAnswer, ok := res.(EDNSAnswer)
	assert.True(t, ok, "Failed to parse OPT record")
	assert.Equal(t, uint8(0), ednsAnswer.Version, "Unexpected EDNS Version. Expected %v, got %v", 0, ednsAnswer.Version)
	assert.Equal(t, uint16(1232), ednsAnswer.UDPSize, "Unexpected EDNS UDP Size. Expected %v, got %v", 0, ednsAnswer.UDPSize)
	assert.Empty(t, ednsAnswer.Flags, "Unexpected EDNS Flags. Expected %v, got %v", 0, ednsAnswer.Flags)
	assert.Nil(t, ednsAnswer.NSID, "Unexpected NSID string. Expected %v, got %v", nil, ednsAnswer.NSID)
}

func TestParseEdnsAnswerNoEdns(t *testing.T) {
	rr := &dns.OPT{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
		Option: []dns.EDNS0{},
	}
	res := ParseAnswer(rr)
	ednsAnswer, ok := res.(EDNSAnswer)
	assert.True(t, ok, "Failed to parse OPT record")
	assert.Equal(t, uint8(0), ednsAnswer.Version, "Unexpected EDNS Version. Expected %v, got %v", 0, ednsAnswer.Version)
	assert.Equal(t, uint16(1232), ednsAnswer.UDPSize, "Unexpected EDNS UDP Size. Expected %v, got %v", 0, ednsAnswer.UDPSize)
	assert.Empty(t, ednsAnswer.Flags, "Unexpected EDNS Flags. Expected %v, got %v", 0, ednsAnswer.Flags)
	assert.Nil(t, ednsAnswer.NSID, "Unexpected NSID string. Expected %v, got %v", nil, ednsAnswer.NSID)
	assert.Empty(t, ednsAnswer.EDE, "Expected no EDE error code, got %v", ednsAnswer.EDE)
}

func TestParseEdnsAnswerEDE1(t *testing.T) {
	rr := &dns.OPT{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
		Option: []dns.EDNS0{&dns.EDNS0_EDE{InfoCode: 65535, ExtraText: "testing"}},
	}
	res := ParseAnswer(rr)
	ednsAnswer, ok := res.(EDNSAnswer)
	assert.True(t, ok, "Failed to parse OPT record")
	assert.Equal(t, uint8(0), ednsAnswer.Version, "Unexpected EDNS Version. Expected %v, got %v", 0, ednsAnswer.Version)
	assert.Equal(t, uint16(1232), ednsAnswer.UDPSize, "Unexpected EDNS UDP Size. Expected %v, got %v", 0, ednsAnswer.UDPSize)
	assert.Empty(t, ednsAnswer.Flags, "Unexpected EDNS Flags. Expected %v, got %v", 0, ednsAnswer.Flags)
	assert.Len(t, ednsAnswer.EDE, 1, "Expected only one EDE error code, got %v", len(ednsAnswer.EDE))
	assert.Equal(t, uint16(65535), ednsAnswer.EDE[0].InfoCode, "Unexpected EDE info code. Expected %v, got %v", 65535, ednsAnswer.EDE[0].InfoCode)
	assert.Equal(t, "testing", ednsAnswer.EDE[0].ExtraText, "Unexpected EDE extra text. Expected %v, got %v", "testing", ednsAnswer.EDE[0].ExtraText)
}

func TestParseEdnsAnswerEDE2(t *testing.T) {
	rr := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
		Option: []dns.EDNS0{
			&dns.EDNS0_EDE{InfoCode: 65535, ExtraText: "testing1"},
			&dns.EDNS0_EDE{InfoCode: 65534, ExtraText: "testing2"}},
	}
	res := ParseAnswer(rr)
	ednsAnswer, ok := res.(EDNSAnswer)
	assert.True(t, ok, "Failed to parse OPT record")
	assert.Equal(t, uint8(0), ednsAnswer.Version, "Unexpected EDNS Version. Expected %v, got %v", 0, ednsAnswer.Version)
	assert.Equal(t, uint16(1232), ednsAnswer.UDPSize, "Unexpected EDNS UDP Size. Expected %v, got %v", 0, ednsAnswer.UDPSize)
	assert.Empty(t, ednsAnswer.Flags, "Unexpected EDNS Flags. Expected %v, got %v", 0, ednsAnswer.Flags)
	assert.Len(t, ednsAnswer.EDE, 2, "Expected only one EDE error code, got %v", len(ednsAnswer.EDE))
	assert.Equal(t, uint16(65535), ednsAnswer.EDE[0].InfoCode, "Unexpected EDE info code. Expected %v, got %v", 65535, ednsAnswer.EDE[0].InfoCode)
	assert.Equal(t, "testing1", ednsAnswer.EDE[0].ExtraText, "Unexpected EDE extra text. Expected %v, got %v", "testing1", ednsAnswer.EDE[1].ExtraText)
	assert.Equal(t, uint16(65534), ednsAnswer.EDE[1].InfoCode, "Unexpected EDE info code. Expected %v, got %v", 655354, ednsAnswer.EDE[0].InfoCode)
	assert.Equal(t, "testing2", ednsAnswer.EDE[01].ExtraText, "Unexpected EDE extra text. Expected %v, got %v", "testing2", ednsAnswer.EDE[1].ExtraText)
}

func TestParseEdnsAnswerClientSubnet1(t *testing.T) {
	rr := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
		Option: []dns.EDNS0{
			&dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        uint16(1),
				SourceNetmask: uint8(24),
				SourceScope:   uint8(20),
				Address:       net.ParseIP("1.2.3.4"),
			},
		}}
	res := ParseAnswer(rr)
	ednsAnswer, ok := res.(EDNSAnswer)
	assert.True(t, ok, "Failed to parse OPT record")
	assert.Equal(t, uint8(0), ednsAnswer.Version, "Unexpected EDNS Version. Expected %v, got %v", 0, ednsAnswer.Version)
	assert.Equal(t, uint16(1232), ednsAnswer.UDPSize, "Unexpected EDNS UDP Size. Expected %v, got %v", 0, ednsAnswer.UDPSize)
	assert.Empty(t, ednsAnswer.Flags, "Unexpected EDNS Flags. Expected %v, got %v", 0, ednsAnswer.Flags)
	assert.Equal(t, uint8(20), ednsAnswer.ClientSubnet.SourceScope, "Unexpected source scope. Expected %v, got %v", 20, ednsAnswer.ClientSubnet.SourceScope)
	assert.Equal(t, uint8(24), ednsAnswer.ClientSubnet.SourceNetmask, "Unexpected source netmask. Expected %v, got %v", 24, ednsAnswer.ClientSubnet.SourceNetmask)
	assert.Equal(t, uint16(1), ednsAnswer.ClientSubnet.Family, "Unexpected family. Expected %v, got %v", 1, ednsAnswer.ClientSubnet.Family)
	assert.Equal(t, "1.2.3.4", ednsAnswer.ClientSubnet.Address, "Unexpected address. Expected %v, got %v", "1.2.3.4", ednsAnswer.ClientSubnet.Address)
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
	input := &SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	resultString, err := FindTxtRecord(input, testRegexp)
	require.NoError(t, err)
	assert.Equal(t, "asdfasdfasdf", resultString)
}

func TestLookup_DoTxtLookup_2(t *testing.T) {
	testRegexp := regexp.MustCompile("^google-site-verification=.*")
	input := &SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "TXT",
				Class:  "IN",
				Name:   "example.com",
				Answer: "testing TXT prefix: hello world!",
			}, Answer{
				TTL:    3600,
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

	resultString, err := FindTxtRecord(input, testRegexp)
	require.NoError(t, err)
	assert.Equal(t, "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0", resultString)
}

func TestLookup_DoTxtLookup_3(t *testing.T) {
	testRegexp := regexp.MustCompile("(?i)^v=spf1.*")
	input := &SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "TXT",
				Class:  "IN",
				Name:   "example.com",
				Answer: "testing TXT prefix: hello world!",
			}, Answer{
				TTL:    3600,
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
	resultString, err := FindTxtRecord(input, testRegexp)
	require.Error(t, err, "no such TXT record found")
	assert.Empty(t, resultString)
}

func TestLookup_DoTxtLookup_4(t *testing.T) {
	testRegexp := regexp.MustCompile("(?i)^v=spf1.*")
	input := &SingleQueryResult{
		Answers: []interface{}{},
	}
	resultString, err := FindTxtRecord(input, testRegexp)
	require.Error(t, err, "no such TXT record found")
	assert.Empty(t, resultString)
}

func TestLookup_DoTxtLookup_5(t *testing.T) {
	testRegexp := regexp.MustCompile("")
	input := &SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "TXT",
			Class:  "IN",
			Name:   "example.com",
			Answer: "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0s",
		}},
	}
	resultString, err := FindTxtRecord(input, testRegexp)
	require.NoError(t, err)
	assert.Equal(t, "google-site-verification=A2WZWCNQHrGV_TWwKh7KHY90UY0SHZo_rnyMJoDaG0s", resultString)
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// A Lookup Tests
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Test specifying neither ipv4 not ipv6 flag looks up ipv4 by default
func TestOneA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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
	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, IPv4Only, false)
	verifyResult(t, *res, []string{"192.0.2.1"}, nil)
}

// Test two ipv4 addresses

func TestTwoA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain1 + ".",
			Answer: "192.0.2.1",
		},
			Answer{
				TTL:    3600,
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
	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, IPv4Only, false)
	verifyResult(t, *res, []string{"192.0.2.1", "192.0.2.2"}, nil)
}

// Test ipv6 results not returned when lookupIpv6 is false

func TestQuadAWithoutFlag(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain1 + ".",
			Answer: "192.0.2.1",
		},
			Answer{
				TTL:    3600,
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

	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, IPv4Only, false)
	verifyResult(t, *res, []string{"192.0.2.1"}, nil)
}

// Test ipv6 results

func TestOnlyQuadA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, IPv6Only, false)
	assert.NotNil(t, res)
	verifyResult(t, *res, nil, []string{"2001:db8::1"})
}

// Test both ipv4 and ipv6 results are returned

func TestAandQuadA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.1",
		},
			Answer{
				TTL:    3600,
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
	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, IPv4OrIPv6, false)
	assert.NotNil(t, res)
	verifyResult(t, *res, []string{"192.0.2.1"}, []string{"2001:db8::1"})
}

// Test two ipv6 addresses are returned

func TestTwoQuadA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   "example.com",
			Answer: "2001:db8::1",
		},
			Answer{
				TTL:    3600,
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
	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, IPv6Only, false)
	assert.NotNil(t, res)
	verifyResult(t, *res, nil, []string{"2001:db8::1", "2001:db8::2"})
}

// Test that when miekg lookup returns no IPv4 or IPv6 addresses (empty record),
// we get empty result

func TestNoResults(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, IPv4Only, false)
	verifyResult(t, *res, nil, nil)
}

// Test CName lookup returns ipv4 address

func TestCname(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "cname.example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	domainNS2 := domainNS{domain: dom2, ns: ns1}

	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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
	res, _, _, _ := resolver.DoTargetedLookup("cname.example.com", ns1, IPv4Only, false)
	verifyResult(t, *res, []string{"192.0.2.1"}, nil)
}

// Test CName with lookupIpv6 as true returns ipv6 addresses

func TestQuadAWithCname(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "cname.example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "AAAA",
			Class:  "IN",
			Name:   "cname.example.com",
			Answer: "2001:db8::3",
		},
			Answer{
				TTL:    3600,
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
	res, _, _, _ := resolver.DoTargetedLookup("cname.example.com", ns1, IPv6Only, false)
	verifyResult(t, *res, nil, []string{"2001:db8::3"})
}

// Test that MX record with no A or AAAA records gives error

func TestUnexpectedMxOnly(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	res, _, status, _ := resolver.DoTargetedLookup("example.com", ns1, IPv4OrIPv6, false)

	if status != StatusError {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test A and AAAA records in additionals

func TestMxAndAdditionals(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "MX",
			Class:  "IN",
			Name:   "example.com",
			Answer: "mail.example.com.",
		}},
		Additional: []interface{}{Answer{
			TTL:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   "example.com",
			Answer: "192.0.2.3",
		},
			Answer{
				TTL:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "example.com",
				Answer: "2001:db8::4",
			}},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, IPv4OrIPv6, false)
	verifyResult(t, *res, []string{"192.0.2.3"}, []string{"2001:db8::4"})
}

// Test A record with IPv6 address gives error

func TestMismatchIpType(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	res, _, status, _ := resolver.DoTargetedLookup("example.com", ns1, IPv4OrIPv6, false)

	if status != StatusError {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test cname loops terminate with error

func TestCnameLoops(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "cname1.example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	domainNS2 := domainNS{domain: dom2, ns: ns1}

	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	res, _, status, _ := resolver.DoTargetedLookup("cname1.example.com", ns1, IPv4OrIPv6, false)

	if status != StatusError {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test recursion in cname lookup with length > 10 terminate with error

func TestExtendedRecursion(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	// Create a CNAME chain of length > 10
	for i := 1; i < 12; i++ {
		domainNSRecord := domainNS{
			domain: "cname" + strconv.Itoa(i) + ".example.com",
			ns:     ns1,
		}
		mockResults[domainNSRecord] = SingleQueryResult{
			Answers: []interface{}{Answer{
				TTL:    3600,
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

	res, _, status, _ := resolver.DoTargetedLookup("cname1.example.com", ns1, IPv4OrIPv6, false)

	if status != StatusError {
		t.Errorf("Expected ERROR status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test empty non-terminal returns no error

func TestEmptyNonTerminal(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "leaf.intermediate.example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
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

	domainNS2 := domainNS{domain: dom2, ns: ns1}

	mockResults[domainNS2] = SingleQueryResult{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	// Verify leaf returns correctly
	res, _, _, _ := resolver.DoTargetedLookup("leaf.intermediate.example.com", ns1, IPv4Only, false)
	verifyResult(t, *res, []string{"192.0.2.3"}, nil)

	// Verify empty non-terminal returns no answer
	res, _, _, _ = resolver.DoTargetedLookup("intermediate.example.com", ns1, IPv4OrIPv6, false)
	verifyResult(t, *res, nil, nil)
}

// Test Non-existent domain in the zone returns NXDOMAIN

func TestNXDomain(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	res, _, status, _ := resolver.DoTargetedLookup("nonexistent.example.com", ns1, IPv4OrIPv6, false)
	if status != StatusNXDomain {
		t.Errorf("Expected StatusNXDomain status, got %v", status)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

// Test both ipv4 and ipv6 results are deduplicated before returning
func TestAandQuadADedup(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "cname1.example.com"
	domain2 := "cname2.example.com"
	domain3 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}
	domainNS2 := domainNS{domain: domain2, ns: ns1}
	domainNS3 := domainNS{domain: domain3, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   domain1,
			Answer: domain2 + ".",
		}, Answer{
			TTL:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   domain2,
			Answer: domain3 + ".",
		}, Answer{
			TTL:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain3,
			Answer: "192.0.2.1",
		}, Answer{
			TTL:    3600,
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

	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "CNAME",
			Class:  "IN",
			Name:   domain2,
			Answer: domain3 + ".",
		}, Answer{
			TTL:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain3,
			Answer: "192.0.2.1",
		}, Answer{
			TTL:    3600,
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

	mockResults[domainNS3] = SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:    3600,
			Type:   "A",
			Class:  "IN",
			Name:   domain3,
			Answer: "192.0.2.1",
		}, Answer{
			TTL:    3600,
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

	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, IPv4OrIPv6, false)
	assert.NotNil(t, res)
	verifyResult(t, *res, []string{"192.0.2.1"}, []string{"2001:db8::3"})
}

// Test server failure returns SERVFAIL

func TestServFail(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{}
	name := "example.com"
	protocolStatus[domainNS1] = StatusServFail

	res, _, finalStatus, _ := resolver.DoTargetedLookup(name, ns1, IPv4OrIPv6, false)

	if finalStatus != protocolStatus[domainNS1] {
		t.Errorf("Expected %v status, got %v", protocolStatus, finalStatus)
	} else if res != nil {
		t.Errorf("Expected no results, got %v", res)
	}
}

func verifyResult(t *testing.T, res IPResult, ipv4 []string, ipv6 []string) {
	if !reflect.DeepEqual(ipv4, res.IPv4Addresses) {
		t.Errorf("Expected %v, Received %v IPv4 address(es)", ipv4, res.IPv4Addresses)
	}
	if !reflect.DeepEqual(ipv6, res.IPv6Addresses) {
		t.Errorf("Expected %v, Received %v IPv6 address(es)", ipv6, res.IPv6Addresses)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// NS Lookup Tests
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// /*NS lookup tests*/
func TestNsAInAdditional(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
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

	expectedServersMap := make(map[string]IPResult)
	expectedServersMap["ns1.example.com"] = IPResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestTwoNSInAdditional(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns2.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				TTL:    3600,
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

	expectedServersMap := make(map[string]IPResult)
	expectedServersMap["ns1.example.com"] = IPResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: nil,
	}
	expectedServersMap["ns2.example.com"] = IPResult{
		IPv4Addresses: []string{"192.0.2.4"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestAandQuadAInAdditional(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4OrIPv6
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				TTL:    3600,
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

	expectedServersMap := make(map[string]IPResult)
	expectedServersMap["ns1.example.com"] = IPResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: []string{"2001:db8::4"},
	}
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestNsMismatchIpType(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4OrIPv6
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: "ns1.example.com.",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				TTL:    3600,
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

	expectedServersMap := make(map[string]IPResult)
	expectedServersMap["ns1.example.com"] = IPResult{
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestAandQuadALookup(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4OrIPv6
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
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

	domainNS2 := domainNS{domain: dom2, ns: ns1}

	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "ns1.example.com.",
				Answer: "192.0.2.3",
			},
			Answer{
				TTL:    3600,
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

	expectedServersMap := make(map[string]IPResult)
	expectedServersMap["ns1.example.com"] = IPResult{
		IPv4Addresses: []string{"192.0.2.3"},
		IPv6Addresses: []string{"2001:db8::4"},
	}
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestNsNXDomain(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")

	_, _, status, _ := resolver.DoNSLookup("nonexistentexample.com", ns1, false)

	assert.Equal(t, StatusNXDomain, status)
}

func TestNsServFail(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{}
	protocolStatus[domainNS1] = StatusServFail

	res, _, status, _ := resolver.DoNSLookup("example.com", ns1, false)

	assert.Equal(t, status, protocolStatus[domainNS1])
	assert.Empty(t, res.Servers)
}

func TestErrorInTargetedLookup(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
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

	protocolStatus[domainNS1] = StatusError

	res, _, status, _ := resolver.DoNSLookup("example.com", ns1, false)
	assert.Empty(t, len(res.Servers), 0)
	assert.Equal(t, status, protocolStatus[domainNS1])
}

// Test One NS with one IP with only ipv4-lookup
func TestAllNsLookupOneNs(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4OrIPv6
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domain1 := "example.com"
	nsDomain1 := "ns1.example.com"
	ipv4_1 := "192.0.2.1"
	ipv6_1 := "2001:db8::3"

	domainNS1 := domainNS{domain: domain1, ns: ns1}
	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: nsDomain1 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   nsDomain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				TTL:    3600,
				Type:   "AAAA",
				Class:  "IN",
				Name:   nsDomain1 + ".",
				Answer: ipv6_1,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domainNS2 := domainNS{domain: domain1, ns: ns2}
	ipv4_2 := "192.0.2.1"
	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
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
	domainNS3 := domainNS{domain: domain1, ns: ns3}
	ipv4_3 := "192.0.2.2"
	mockResults[domainNS3] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
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
			Nameserver: nsDomain1,
			Status:     StatusNoError,
			Res:        mockResults[domainNS2],
		},
		{
			Nameserver: nsDomain1,
			Status:     StatusNoError,
			Res:        mockResults[domainNS3],
		},
	}
	q := Question{
		Type:  dns.TypeNS,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	results, _, _, err := resolver.LookupAllNameservers(&q, ns1)
	require.NoError(t, err)
	verifyCombinedResult(t, results.Results, expectedRes)
}

// Test One NS with two IPs with only ipv4-lookup

func TestAllNsLookupOneNsMultipleIps(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domain1 := "example.com"
	nsDomain1 := "ns1.example.com"
	ipv4_1 := "192.0.2.1"
	ipv4_2 := "192.0.2.2"

	domainNS1 := domainNS{domain: domain1, ns: ns1}
	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: nsDomain1 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   nsDomain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   nsDomain1 + ".",
				Answer: ipv4_2,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domainNS2 := domainNS{domain: domain1, ns: ns2}
	ipv4_3 := "192.0.2.3"
	ipv6_1 := "2001:db8::1"
	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_3,
			},
			Answer{
				TTL:    3600,
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
	domainNS3 := domainNS{domain: domain1, ns: ns3}
	ipv4_4 := "192.0.2.4"
	ipv6_2 := "2001:db8::2"
	mockResults[domainNS3] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_4,
			},
			Answer{
				TTL:    3600,
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
			Nameserver: nsDomain1,
			Status:     StatusNoError,
			Res:        mockResults[domainNS2],
		},
		{
			Nameserver: nsDomain1,
			Status:     StatusNoError,
			Res:        mockResults[domainNS3],
		},
	}

	q := Question{
		Type:  dns.TypeNS,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	results, _, _, err := resolver.LookupAllNameservers(&q, ns1)
	require.NoError(t, err)
	verifyCombinedResult(t, results.Results, expectedRes)
}

// Test One NS with two IPs with only ipv4-lookup
func TestAllNsLookupTwoNs(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domain1 := "example.com"
	nsDomain1 := "ns1.example.com"
	nsDomain2 := "ns2.example.com"
	ipv4_1 := "192.0.2.1"
	ipv4_2 := "192.0.2.2"

	domainNS1 := domainNS{domain: domain1, ns: ns1}
	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: nsDomain1 + ".",
			},
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com.",
				Answer: nsDomain2 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   nsDomain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   nsDomain2 + ".",
				Answer: ipv4_2,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domainNS2 := domainNS{domain: domain1, ns: ns2}
	ipv4_3 := "192.0.2.3"
	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
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
	domainNS3 := domainNS{domain: domain1, ns: ns3}
	ipv4_4 := "192.0.2.4"
	mockResults[domainNS3] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
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
			Nameserver: nsDomain1,
			Status:     StatusNoError,
			Res:        mockResults[domainNS2],
		},
		{
			Nameserver: nsDomain2,
			Status:     StatusNoError,
			Res:        mockResults[domainNS3],
		},
	}

	q := Question{
		Type:  dns.TypeNS,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	results, _, _, err := resolver.LookupAllNameservers(&q, ns1)
	require.NoError(t, err)
	verifyCombinedResult(t, results.Results, expectedRes)
}

// Test error in A lookup via targeted lookup records

func TestAllNsLookupErrorInOne(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domain1 := "example.com"
	nsDomain1 := "ns1.example.com"
	ipv4_1 := "192.0.2.1"
	ipv4_2 := "192.0.2.2"

	domainNS1 := domainNS{domain: domain1, ns: ns1}
	mockResults[domainNS1] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				Class:  "IN",
				Name:   "example.com",
				Answer: nsDomain1 + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   nsDomain1 + ".",
				Answer: ipv4_1,
			},
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   nsDomain1 + ".",
				Answer: ipv4_2,
			},
		},
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}

	ns2 := net.JoinHostPort(ipv4_1, "53")
	domainNS2 := domainNS{domain: domain1, ns: ns2}
	ipv4_3 := "192.0.2.3"
	ipv6_1 := "2001:db8::1"
	mockResults[domainNS2] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				Class:  "IN",
				Name:   "example.com.",
				Answer: ipv4_3,
			},
			Answer{
				TTL:    3600,
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
	domainNS3 := domainNS{domain: domain1, ns: ns3}
	protocolStatus[domainNS3] = StatusServFail
	mockResults[domainNS3] = SingleQueryResult{}

	expectedRes := []ExtendedResult{
		{
			Nameserver: nsDomain1,
			Status:     StatusNoError,
			Res:        mockResults[domainNS2],
		},
		{
			Nameserver: nsDomain1,
			Status:     StatusServFail,
			Res:        mockResults[domainNS3],
		},
	}

	q := Question{
		Type:  dns.TypeNS,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	results, _, _, err := resolver.LookupAllNameservers(&q, ns1)
	require.NoError(t, err)
	verifyCombinedResult(t, results.Results, expectedRes)
}

func TestAllNsLookupNXDomain(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	q := Question{
		Type:  dns.TypeNS,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	res, _, status, err := resolver.LookupAllNameservers(&q, ns1)

	assert.Equal(t, StatusNXDomain, status)
	assert.Nil(t, res)
	require.NoError(t, err)
}

func TestAllNsLookupServFail(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := net.JoinHostPort(config.ExternalNameServers[0], "53")
	domain1 := "example.com"
	domainNS1 := domainNS{domain: domain1, ns: ns1}

	protocolStatus[domainNS1] = StatusServFail
	mockResults[domainNS1] = SingleQueryResult{}

	q := Question{
		Type:  dns.TypeNS,
		Class: dns.ClassINET,
		Name:  "example.com",
	}
	res, _, status, err := resolver.LookupAllNameservers(&q, ns1)

	assert.Equal(t, StatusServFail, status)
	assert.Nil(t, res)
	require.NoError(t, err)
}

func TestInvalidInputsLookup(t *testing.T) {
	config := NewResolverConfig()
	config.LocalAddrs = []net.IP{net.ParseIP("127.0.0.1")}
	resolver, err := InitResolver(config)
	require.NoError(t, err)
	q := Question{
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	t.Run("no port attached to nameserver", func(t *testing.T) {
		result, trace, status, err := resolver.ExternalLookup(&q, "127.0.0.53")
		assert.Nil(t, result)
		assert.Nil(t, trace)
		assert.Equal(t, StatusIllegalInput, status)
		assert.NotNil(t, err)
	})
	t.Run("using a loopback local addr with non-loopback nameserver", func(t *testing.T) {
		result, trace, status, err := resolver.ExternalLookup(&q, "1.1.1.1:53")
		assert.Nil(t, result)
		assert.Nil(t, trace)
		assert.Equal(t, StatusIllegalInput, status)
		assert.NotNil(t, err)
	})
	t.Run("invalid nameserver address", func(t *testing.T) {
		result, trace, status, err := resolver.ExternalLookup(&q, "987.987.987.987:53")
		assert.Nil(t, result)
		assert.Nil(t, trace)
		assert.Equal(t, StatusIllegalInput, status)
		assert.NotNil(t, err)
	})
}

func verifyNsResult(t *testing.T, servers []NSRecord, expectedServersMap map[string]IPResult) {
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
