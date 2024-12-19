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
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/miekg/dns"

	"github.com/zmap/zdns/src/internal/util"
)

type nameAndIP struct {
	name string
	IP   string
}

var mockResults = make(map[nameAndIP]SingleQueryResult)

var protocolStatus = make(map[nameAndIP]Status)

type MockLookupClient struct{}

func (mc MockLookupClient) DoDstServersLookup(ctx context.Context, r *Resolver, q Question, nameServers []NameServer, isIterative bool) (*SingleQueryResult, Trace, Status, error) {
	ns := nameServers[rand.Intn(len(nameServers))]
	curDomainNs := nameAndIP{name: q.Name, IP: ns.String()}
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
	protocolStatus = make(map[nameAndIP]Status)
	mockResults = make(map[nameAndIP]SingleQueryResult)

	mc := MockLookupClient{}
	config := NewResolverConfig()
	config.ExternalNameServersV4 = []NameServer{{IP: net.ParseIP("127.0.0.1"), Port: 53}}
	config.RootNameServersV4 = []NameServer{{IP: net.ParseIP("127.0.0.1"), Port: 53}}
	config.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
	config.IPVersionMode = IPv4Only
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
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, false, true, false)
	verifyResult(t, *res, []string{"192.0.2.1"}, nil)
}

// Test two ipv4 addresses

func TestTwoA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, false, true, false)
	verifyResult(t, *res, []string{"192.0.2.1", "192.0.2.2"}, nil)
}

// Test ipv6 results not returned when lookupIpv6 is false

func TestQuadAWithoutFlag(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, false, true, false)
	verifyResult(t, *res, []string{"192.0.2.1"}, nil)
}

// Test ipv6 results

func TestOnlyQuadA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, false, false, true)
	assert.NotNil(t, res)
	verifyResult(t, *res, nil, []string{"2001:db8::1"})
}

// Test both ipv4 and ipv6 results are returned

func TestAandQuadA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, false, true, true)
	assert.NotNil(t, res)
	verifyResult(t, *res, []string{"192.0.2.1"}, []string{"2001:db8::1"})
}

// Test two ipv6 addresses are returned

func TestTwoQuadA(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, false, false, true)
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
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

	mockResults[domainNS1] = SingleQueryResult{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, false, true, false)
	verifyResult(t, *res, nil, nil)
}

// Test CName with lookupIpv6 as true returns ipv6 addresses

func TestQuadAWithCname(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "cname.example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoTargetedLookup("cname.example.com", ns1, false, false, true)
	verifyResult(t, *res, nil, []string{"2001:db8::3"})
}

// Test that MX record with no A or AAAA records gives error

func TestUnexpectedMxOnly(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	res, _, status, _ := resolver.DoTargetedLookup("example.com", ns1, false, true, true)

	if status != StatusNoError {
		t.Errorf("Expected no error, got %v", status)
	} else if res == nil {
		t.Error("Expected results, got none")
	} else if len(res.IPv4Addresses) > 0 || len(res.IPv6Addresses) > 0 {
		t.Errorf("Expected no IP addresses, got: %v", util.Concat(res.IPv4Addresses, res.IPv6Addresses))
	}
}

// Test A and AAAA records in additionals

func TestMxAndAdditionals(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	res, _, _, _ := resolver.DoTargetedLookup("example.com", ns1, false, true, true)
	verifyResult(t, *res, []string{"192.0.2.3"}, []string{"2001:db8::4"})
}

// Test A record with IPv6 address gives error
func TestMismatchIpType(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	res, _, status, _ := resolver.DoTargetedLookup("example.com", ns1, false, false, true)

	if status != StatusNoError {
		t.Errorf("Expected no error, got %v", status)
	} else if res == nil {
		t.Error("Expected results, got none")
	} else if len(res.IPv4Addresses) > 0 || len(res.IPv6Addresses) > 0 {
		t.Errorf("Expected no IP addresses, got: %v", util.Concat(res.IPv4Addresses, res.IPv6Addresses))
	}
}

// Test empty non-terminal returns no error

func TestEmptyNonTerminal(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "leaf.intermediate.example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	domainNS2 := nameAndIP{name: dom2, IP: ns1.String()}

	mockResults[domainNS2] = SingleQueryResult{
		Answers:     nil,
		Additional:  nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{},
	}
	// Verify leaf returns correctly
	res, _, _, _ := resolver.DoTargetedLookup("leaf.intermediate.example.com", ns1, false, true, false)
	verifyResult(t, *res, []string{"192.0.2.3"}, nil)

	// Verify empty non-terminal returns no answer
	res, _, _, _ = resolver.DoTargetedLookup("intermediate.example.com", ns1, false, true, true)
	verifyResult(t, *res, nil, nil)
}

// Test Non-existent name in the zone returns NXDOMAIN

func TestNXDomain(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)
	ns1 := &config.ExternalNameServersV4[0]
	res, _, status, _ := resolver.DoTargetedLookup("nonexistent.example.com", ns1, false, true, true)
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
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}
	domainNS2 := nameAndIP{name: domain2, IP: ns1.String()}
	domainNS3 := nameAndIP{name: domain3, IP: ns1.String()}

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

	res, _, _, _ := resolver.DoTargetedLookup(domain1, ns1, false, true, true)
	assert.NotNil(t, res)
	verifyResult(t, *res, []string{"192.0.2.1"}, []string{"2001:db8::3"})
}

// Test server failure returns SERVFAIL

func TestServFail(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

	mockResults[domainNS1] = SingleQueryResult{}
	name := "example.com"
	protocolStatus[domainNS1] = StatusServFail

	res, _, finalStatus, _ := resolver.DoTargetedLookup(name, ns1, false, true, true)

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
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false, true, false)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestTwoNSInAdditional(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false, true, false)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestAandQuadAInAdditional(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false, true, true)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestNsMismatchIpType(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false, true, true)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestAandQuadALookup(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	domainNS2 := nameAndIP{name: dom2, IP: ns1.String()}

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
	res, _, _, _ := resolver.DoNSLookup("example.com", ns1, false, true, true)
	verifyNsResult(t, res.Servers, expectedServersMap)
}

func TestNsNXDomain(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := &config.ExternalNameServersV4[0]

	_, _, status, _ := resolver.DoNSLookup("nonexistentexample.com", ns1, false, true, true)

	assert.Equal(t, StatusNXDomain, status)
}

func TestNsServFail(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

	mockResults[domainNS1] = SingleQueryResult{}
	protocolStatus[domainNS1] = StatusServFail

	res, _, status, _ := resolver.DoNSLookup("example.com", ns1, false, true, false)

	assert.Equal(t, status, protocolStatus[domainNS1])
	assert.Empty(t, res.Servers)
}

func TestErrorInTargetedLookup(t *testing.T) {
	config := InitTest(t)
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	domain1 := "example.com"
	ns1 := &config.ExternalNameServersV4[0]
	domainNS1 := nameAndIP{name: domain1, IP: ns1.String()}

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

	res, _, status, _ := resolver.DoNSLookup("example.com", ns1, false, true, false)
	assert.Empty(t, len(res.Servers), 0)
	assert.Equal(t, status, protocolStatus[domainNS1])
}

// Test One NS with one IP with only ipv4-lookup
func TestAllNsLookupOneNsThreeLevels(t *testing.T) {
	config := InitTest(t)
	config.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
	resolver, err := InitResolver(config)
	require.NoError(t, err)
	exampleName := "example.com"

	rootServer := "a.root-servers.net"
	rootServerIP := "1.1.1.1"
	comServer := "a.gtld-servers.net"
	comServerIP := "2.2.2.2"
	exampleNSServer := "ns1.example.com"
	exampleNSServerIP := "3.3.3.3"
	exampleNameAAnswer := "4.4.4.4"

	mockResults[nameAndIP{name: exampleName, IP: rootServerIP + ":53"}] = SingleQueryResult{
		Authorities: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				RrType: dns.TypeNS,
				Class:  "IN",
				Name:   "com.",
				Answer: comServer + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				RrType: dns.TypeA,
				Class:  "IN",
				Name:   comServer + ".",
				Answer: comServerIP,
			},
		},
	}
	mockResults[nameAndIP{name: exampleName, IP: comServerIP + ":53"}] = SingleQueryResult{
		Authorities: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				RrType: dns.TypeNS,
				Class:  "IN",
				Name:   "example.com.",
				Answer: exampleNSServer + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				RrType: dns.TypeA,
				Class:  "IN",
				Name:   exampleNSServer + ".",
				Answer: exampleNSServerIP,
			},
		},
	}
	mockResults[nameAndIP{name: exampleName, IP: exampleNSServerIP + ":53"}] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				RrType: dns.TypeA,
				Class:  "IN",
				Name:   "example.com.",
				Answer: exampleNameAAnswer,
			},
		},
	}

	expectedRes := map[string][]ExtendedResult{
		".": {
			{
				Status:     StatusNoError,
				Nameserver: rootServer,
				Type:       "NS",
				Res: SingleQueryResult{
					Authorities: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "NS",
							RrType: dns.TypeNS,
							Class:  "IN",
							Name:   "com.",
							Answer: "a.gtld-servers.net.",
						},
					},
					Additional: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "a.gtld-servers.net.",
							Answer: "2.2.2.2",
						},
					},
				},
			},
		},
		"com": {
			{
				Status:     StatusNoError,
				Type:       "NS",
				Nameserver: comServer,
				Res: SingleQueryResult{
					Authorities: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "NS",
							RrType: dns.TypeNS,
							Class:  "IN",
							Name:   "example.com.",
							Answer: "ns1.example.com.",
						},
					},
					Additional: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "ns1.example.com.",
							Answer: "3.3.3.3",
						},
					},
				},
			},
		},
		"example.com": {
			{
				Status:     StatusNoError,
				Type:       "NS",
				Nameserver: exampleNSServer,
				Res: SingleQueryResult{
					Answers: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "example.com.",
							Answer: "4.4.4.4",
						},
					},
				},
			},
			{
				Status:     StatusNoError,
				Type:       "A",
				Nameserver: exampleNSServer,
				Res: SingleQueryResult{
					Answers: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "example.com.",
							Answer: "4.4.4.4",
						},
					},
				},
			},
		},
	}
	q := Question{
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	results, _, _, err := resolver.LookupAllNameserversIterative(&q, []NameServer{{DomainName: rootServer, IP: net.ParseIP(rootServerIP)}})
	require.NoError(t, err)
	verifyCombinedResult(t, results.LayeredResponses, expectedRes)
}

// Test AllNameservers with a ".", ".com", and "example.com". We'll have two .com servers and one will error. Should still be able to resolve the query.
func TestAllNsLookupErrorInOne(t *testing.T) {
	config := InitTest(t)
	config.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
	config.Timeout = time.Hour
	config.IterativeTimeout = time.Hour
	resolver, err := InitResolver(config)
	require.NoError(t, err)
	exampleName := "example.com"

	rootServer := "a.root-servers.net"
	rootServerIP := "1.1.1.1"
	comServerA := "a.gtld-servers.net"
	comServerB := "b.gtld-servers.net"
	comServerAIP := "2.2.2.2"
	comServerBIP := "3.3.3.3"
	exampleNSServer := "ns1.example.com"
	exampleNSServerIP := "4.4.4.4"
	exampleNameAAnswer := "5.5.5.5"

	mockResults[nameAndIP{name: exampleName, IP: rootServerIP + ":53"}] = SingleQueryResult{
		Authorities: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				RrType: dns.TypeNS,
				Class:  "IN",
				Name:   "com.",
				Answer: comServerA + ".",
			},
			Answer{
				TTL:    3600,
				Type:   "NS",
				RrType: dns.TypeNS,
				Class:  "IN",
				Name:   "com.",
				Answer: comServerB + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				RrType: dns.TypeA,
				Class:  "IN",
				Name:   comServerA + ".",
				Answer: comServerAIP,
			},
			Answer{
				TTL:    3600,
				Type:   "A",
				RrType: dns.TypeA,
				Class:  "IN",
				Name:   comServerB + ".",
				Answer: comServerBIP,
			},
		},
	}
	// Error in comServerB
	mockResults[nameAndIP{name: exampleName, IP: comServerAIP + ":53"}] = SingleQueryResult{}
	protocolStatus[nameAndIP{name: exampleName, IP: comServerAIP + ":53"}] = StatusServFail
	// Success in comServerA
	mockResults[nameAndIP{name: exampleName, IP: comServerBIP + ":53"}] = SingleQueryResult{
		Authorities: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "NS",
				RrType: dns.TypeNS,
				Class:  "IN",
				Name:   "example.com.",
				Answer: exampleNSServer + ".",
			},
		},
		Additional: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				RrType: dns.TypeA,
				Class:  "IN",
				Name:   exampleNSServer + ".",
				Answer: exampleNSServerIP,
			},
		},
	}
	mockResults[nameAndIP{name: exampleName, IP: exampleNSServerIP + ":53"}] = SingleQueryResult{
		Answers: []interface{}{
			Answer{
				TTL:    3600,
				Type:   "A",
				RrType: dns.TypeA,
				Class:  "IN",
				Name:   "example.com.",
				Answer: exampleNameAAnswer,
			},
		},
	}

	expectedRes := map[string][]ExtendedResult{
		".": {
			{
				Status:     StatusNoError,
				Type:       "NS",
				Nameserver: rootServer,
				Res: SingleQueryResult{
					Authorities: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "NS",
							RrType: dns.TypeNS,
							Class:  "IN",
							Name:   "com.",
							Answer: "a.gtld-servers.net.",
						},
						Answer{
							TTL:    3600,
							Type:   "NS",
							RrType: dns.TypeNS,
							Class:  "IN",
							Name:   "com.",
							Answer: "b.gtld-servers.net.",
						},
					},
					Additional: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "a.gtld-servers.net.",
							Answer: comServerAIP,
						},
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "b.gtld-servers.net.",
							Answer: comServerBIP,
						},
					},
				},
			},
		},
		"com": {
			{
				Status:     StatusServFail,
				Type:       "NS",
				Nameserver: comServerA,
				Res:        SingleQueryResult{},
			},
			{
				Status:     StatusNoError,
				Type:       "NS",
				Nameserver: comServerB,
				Res: SingleQueryResult{
					Authorities: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "NS",
							RrType: dns.TypeNS,
							Class:  "IN",
							Name:   "example.com.",
							Answer: exampleNSServer + ".",
						},
					},
					Additional: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "ns1.example.com.",
							Answer: exampleNSServerIP,
						},
					},
				},
			},
		},
		"example.com": {
			{
				Status:     StatusNoError,
				Type:       "NS",
				Nameserver: exampleNSServer,
				Res: SingleQueryResult{
					Answers: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "example.com.",
							Answer: exampleNameAAnswer,
						},
					},
				},
			},
			{
				Status:     StatusNoError,
				Type:       "A",
				Nameserver: exampleNSServer,
				Res: SingleQueryResult{
					Answers: []interface{}{
						Answer{
							TTL:    3600,
							Type:   "A",
							RrType: dns.TypeA,
							Class:  "IN",
							Name:   "example.com.",
							Answer: exampleNameAAnswer,
						},
					},
				},
			},
		},
	}
	q := Question{
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	results, _, _, err := resolver.LookupAllNameserversIterative(&q, []NameServer{{DomainName: rootServer, IP: net.ParseIP(rootServerIP)}})
	require.NoError(t, err)
	verifyCombinedResult(t, results.LayeredResponses, expectedRes)
}

func TestAllNsLookupNXDomain(t *testing.T) {
	config := InitTest(t)
	config.IPVersionMode = IPv4Only
	resolver, err := InitResolver(config)
	require.NoError(t, err)

	ns1 := &config.ExternalNameServersV4[0]
	q := Question{
		Type:  dns.TypeNS,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	res, _, status, err := resolver.LookupAllNameserversIterative(&q, []NameServer{*ns1})

	expectedResponse := map[string][]ExtendedResult{
		".": {{Status: StatusNXDomain, Type: "NS"}},
	}
	if !reflect.DeepEqual(res.LayeredResponses, expectedResponse) {
		t.Errorf("Expected %v, Received %v", expectedResponse, res.LayeredResponses)
	}
	assert.Equal(t, StatusError, status)
	require.Error(t, err) // could not successfully complete lookup, so this should error
}

func TestInvalidInputsLookup(t *testing.T) {
	config := InitTest(t)
	config.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
	config.ExternalNameServersV4 = []NameServer{{IP: net.ParseIP("127.0.0.53"), Port: 53}}
	resolver, err := InitResolver(config)
	require.NoError(t, err)
	q := Question{
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	t.Run("no port attached to nameserver", func(t *testing.T) {
		_, _, _, err := resolver.ExternalLookup(context.Background(), &q, &NameServer{IP: net.ParseIP("127.0.0.53")})
		assert.Nil(t, err)
	})
	t.Run("invalid nameserver address", func(t *testing.T) {
		result, trace, status, err := resolver.ExternalLookup(context.Background(), &q, &NameServer{IP: net.ParseIP("987.987.987.987"), Port: 53})
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

func verifyCombinedResult(t *testing.T, records map[string][]ExtendedResult, expectedRecords map[string][]ExtendedResult) {
	for layer := range expectedRecords {
		assert.Contains(t, records, layer, fmt.Sprintf("Layer %s not found in combined result", layer))
	}
	for layer, expectedLayerResults := range expectedRecords {
		sort.Slice(records[layer], func(i, j int) bool {
			return records[layer][i].Nameserver < records[layer][j].Nameserver
		})
		sort.Slice(records[layer], func(i, j int) bool {
			return expectedLayerResults[i].Nameserver < expectedLayerResults[j].Nameserver
		})
		if !reflect.DeepEqual(records[layer], expectedLayerResults) {
			t.Errorf("Combined result not matching for layer %s, expected %v, found %v", layer, expectedLayerResults, records[layer])
		}
	}
	if !reflect.DeepEqual(records, expectedRecords) {
		t.Errorf("Combined result not matching, expected %v, found %v", expectedRecords, records)
	}
}
