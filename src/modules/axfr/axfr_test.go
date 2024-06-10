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

package axfr

import (
	"net"
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/zmap/dns"
	"gotest.tools/v3/assert"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

// Map from IPv4 address of server to DNS records
var axfrRecords = make(map[string][]dns.RR)
var transferError = ""
var envelopeError = ""

// trError is used to specify error in the transfer over channel
type trError struct{}

func (err trError) Error() string {
	return transferError
}

// enError is used to specify error in envelope
type enError struct{}

func (err enError) Error() string {
	return envelopeError
}

func (axfrMod *AxfrLookupModule) In(m *dns.Msg, server string) (chan *dns.Envelope, error) {
	var eError error = nil
	if envelopeError != "" {
		eError = enError{}
	}
	envelope := dns.Envelope{
		RR:    axfrRecords[server],
		Error: eError,
	}
	env := make(chan *dns.Envelope)
	if transferError == "" {
		go func() {
			env <- &envelope
			close(env)
		}()
		return env, nil
	} else {
		go func() {
			close(env)
		}()
		return env, trError{}
	}
}

var nsRecords = make(map[string]*zdns.NSResult)
var nsStatus = zdns.StatusNoError

// Mock the actual NS lookup.
func mockNSLookup(r *zdns.Resolver, lookupName, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if res, ok := nsRecords[lookupName]; ok {
		return res, nil, nsStatus, nil
	} else {
		return zdns.NSResult{}, nil, zdns.StatusNXDomain, nil
	}
}

func InitTest() (*AxfrLookupModule, *zdns.Resolver) {
	axfrRecords = make(map[string][]dns.RR)
	transferError = ""
	envelopeError = ""

	nsRecords = make(map[string]*zdns.NSResult)
	nsStatus = zdns.StatusNoError

	cc := new(cli.CLIConf)
	cc.NameServers = []string{"127.0.0.1"}

	rc := new(zdns.ResolverConfig)
	flagSet := new(pflag.FlagSet)
	flagSet.Bool("ipv4-lookup", false, "Use IPv4")
	flagSet.Bool("ipv6-lookup", false, "Use IPv6")
	flagSet.String("blacklist-file", "", "Blacklist")
	axfrMod := new(AxfrLookupModule)
	err := axfrMod.CLIInit(cc, rc, flagSet)
	if err != nil {
		panic("failed to initialize axfr test lookup with error: " + err.Error())
	}
	resolver, err := zdns.InitResolver(rc)
	if err != nil {
		panic("failed to initialize resolver: " + err.Error())
	}
	axfrMod.NSModule.WithTestingLookup(mockNSLookup)
	return axfrMod, resolver
}

// This test checks that different record types are correctly returned by AXFR
func TestLookupSingleNS(t *testing.T) {
	axfrMod, resolver := InitTest()

	ns1 := "ns1.example.com"
	ip1 := "192.0.2.3"
	hostPort1 := net.JoinHostPort(ip1, "53")

	nsRecords["example.com"] = &zdns.NSResult{
		Servers: []zdns.NSRecord{
			{
				Name:          ns1 + ".",
				Type:          "NS",
				IPv4Addresses: []string{ip1},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}
	// A record
	ipv4 := &dns.A{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		A: net.ParseIP("192.0.2.1"),
	}
	// AAAA record
	ipv6 := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		AAAA: net.ParseIP("2001:db8::1"),
	}
	// MX record
	mx := &dns.MX{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeMX,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		Preference: 1,
		Mx:         "mail.example.com.",
	}
	// NS record
	ns := &dns.NS{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeMX,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		Ns: "ns1.example.com.",
	}
	// SPF
	spf := &dns.SPF{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeSPF,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		Txt: []string{"some TXT record"},
	}
	// NAPTR record
	naptr := &dns.NAPTR{
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

	axfrRecords[hostPort1] = []dns.RR{
		ipv4,
		ipv6,
		mx,
		ns,
		spf,
		naptr,
	}

	expectedServersMap := make(map[string][]interface{})
	expectedServersMap[ip1] = make([]interface{}, len(axfrRecords[hostPort1]))
	for i, rec := range axfrRecords[hostPort1] {
		expectedServersMap[ip1][i] = zdns.ParseAnswer(rec)
	}

	res, _, status, _ := axfrMod.Lookup(resolver, "example.com", "")
	assert.Equal(t, status, zdns.StatusNoError)
	verifyResult(t, res.(AXFRResult).Servers, expectedServersMap)
}

// For some reason if two name servers have different records,
// they will return what is available with them
func TestLookupTwoNS(t *testing.T) {
	axfrMod, resolver := InitTest()

	ns1 := "ns1.example.com"
	ip1 := "192.0.2.3"
	hostPort1 := net.JoinHostPort(ip1, "53")
	ns2 := "ns2.example.com"
	ip2 := "192.0.2.4"
	hostPort2 := net.JoinHostPort(ip2, "53")

	nsRecords["example.com"] = &zdns.NSResult{
		Servers: []zdns.NSRecord{
			{
				Name:          ns1 + ".",
				Type:          "NS",
				IPv4Addresses: []string{ip1},
				IPv6Addresses: nil,
				TTL:           3600,
			},
			{
				Name:          ns2 + ".",
				Type:          "NS",
				IPv4Addresses: []string{ip2},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}

	// A record
	ipv4 := &dns.A{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		A: net.ParseIP("192.0.2.1"),
	}
	// AAAA record
	ipv6 := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:     "example.com",
			Rrtype:   dns.TypeAAAA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		AAAA: net.ParseIP("2001:db8::1"),
	}

	axfrRecords[hostPort1] = []dns.RR{
		ipv4,
	}
	axfrRecords[hostPort2] = []dns.RR{
		ipv6,
	}

	expectedServersMap := make(map[string][]interface{})
	expectedServersMap[ip1] = make([]interface{}, len(axfrRecords[hostPort1]))
	for i, rec := range axfrRecords[hostPort1] {
		expectedServersMap[ip1][i] = zdns.ParseAnswer(rec)
	}
	expectedServersMap[ip2] = make([]interface{}, len(axfrRecords[hostPort2]))
	for i, rec := range axfrRecords[hostPort2] {
		expectedServersMap[ip2][i] = zdns.ParseAnswer(rec)
	}

	res, _, status, _ := axfrMod.Lookup(resolver, "example.com", "")
	assert.Equal(t, status, zdns.StatusNoError)
	verifyResult(t, res.(AXFRResult).Servers, expectedServersMap)
}

// Failure in transfer via the channel should return status ERROR
func TestFailureInTransfer(t *testing.T) {
	axfrMod, resolver := InitTest()

	ns1 := "ns1.example.com"
	ip1 := "192.0.2.3"

	nsRecords["example.com"] = &zdns.NSResult{
		Servers: []zdns.NSRecord{
			{
				Name:          ns1 + ".",
				Type:          "NS",
				IPv4Addresses: []string{ip1},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}

	transferError = "Error in transfer."

	expectedServersMap := make(map[string][]interface{})
	expectedServersMap[ip1] = make([]interface{}, 0)

	res, _, status, _ := axfrMod.Lookup(resolver, "example.com", "")
	// The overall status should be no error
	assert.Equal(t, status, zdns.StatusNoError)
	// The status for the axfr records for ns1 should be error
	assert.Equal(t, res.(AXFRResult).Servers[0].Status, zdns.StatusError)
	// No records should be present for ns1
	assert.Equal(t, len(res.(AXFRResult).Servers[0].Records), 0)
}

// Error in the envelope which is received via the channel should return status ERROR
func TestErrorInEnvelope(t *testing.T) {
	axfrMod, resolver := InitTest()

	ns1 := "ns1.example.com"
	ip1 := "192.0.2.3"

	nsRecords["example.com"] = &zdns.NSResult{
		Servers: []zdns.NSRecord{
			{
				Name:          ns1 + ".",
				Type:          "NS",
				IPv4Addresses: []string{ip1},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}

	envelopeError = "Error in envelope."

	expectedServersMap := make(map[string][]interface{})
	expectedServersMap[ip1] = make([]interface{}, 0)

	res, _, status, _ := axfrMod.Lookup(resolver, "example.com", "")
	// The overall status should be no error
	assert.Equal(t, status, zdns.StatusNoError)
	// The status for the axfr records for ns1 should be error
	assert.Equal(t, res.(AXFRResult).Servers[0].Status, zdns.StatusError)
	// No records should be present for ns1
	assert.Equal(t, len(res.(AXFRResult).Servers[0].Records), 0)
}

// Test if no IPv4 addresses exist for NS, we do not return any records
func TestNoIpv4InNsLookup(t *testing.T) {
	axfrMod, resolver := InitTest()

	ns1 := "ns1.example.com"

	nsRecords["example.com"] = &zdns.NSResult{
		Servers: []zdns.NSRecord{
			{
				Name:          ns1 + ".",
				Type:          "NS",
				IPv4Addresses: nil,
				IPv6Addresses: []string{"2001:db8::4"},
				TTL:           3600,
			},
		},
	}

	res, _, status, _ := axfrMod.Lookup(resolver, "example.com", "")
	assert.Equal(t, status, zdns.StatusNoError)
	assert.Equal(t, len(res.(AXFRResult).Servers), 0)
}

// Querying non-existent domains should return NXDOMAIN status
func TestNXDomain(t *testing.T) {
	axfrMod, resolver := InitTest()
	res, _, status, _ := axfrMod.Lookup(resolver, "example.com", "")
	assert.Equal(t, status, zdns.StatusNXDomain)
	assert.Equal(t, res, nil)
}

// Error in NS lookup should return the same status for overall lookup
func TestErrorInNsLookup(t *testing.T) {
	axfrMod, resolver := InitTest()

	nsStatus = zdns.StatusServFail
	nsRecords["example.com"] = &zdns.NSResult{
		Servers: nil,
	}

	res, _, status, _ := axfrMod.Lookup(resolver, "example.com", "")
	assert.Equal(t, status, nsStatus)
	assert.Equal(t, res, nil)
}

func verifyResult(t *testing.T, servers []AXFRServerResult, expectedServersMap map[string][]interface{}) {
	serversLength := len(servers)
	expectedServersLength := len(expectedServersMap)

	if serversLength != expectedServersLength {
		t.Errorf("Expected %v servers, found %v", expectedServersLength, serversLength)
	}

	for _, server := range servers {
		name := server.Server
		expectedRecords, ok := expectedServersMap[name]
		if !ok {
			t.Errorf("Did not find server %v in expected servers.", name)
		}
		if !reflect.DeepEqual(server.Records, expectedRecords) {
			t.Errorf("For server %v, found records: %v, expected records: %v", name, server.Records, expectedRecords)
		}
	}
}
