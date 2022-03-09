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
package nsalookup

import (
	"net"
	"reflect"
	"testing"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/miekg"
	"github.com/zmap/zdns/pkg/nslookup"
	"github.com/zmap/zdns/pkg/zdns"
	"gotest.tools/v3/assert"
)

// Global variables used for the nslookup mock
var nsRecords = make(map[string]nslookup.Result)
var nsStatus = zdns.STATUS_NOERROR

// Mock the NS lookup.
func (s *Lookup) DoNSLookup(name string, lookupIpv4 bool, lookupIpv6 bool, nameServer string) (nslookup.Result, zdns.Trace, zdns.Status, error) {
	if res, ok := nsRecords[name]; ok {
		return res, nil, nsStatus, nil
	} else {
		return nslookup.Result{}, nil, zdns.STATUS_NXDOMAIN, nil
	}
}

type domain_ns struct {
	domain string
	ns     string
}

// Global variables used for the targeted lookup
var mockResults = make(map[domain_ns]miekg.IpResult)
var protocolStatus = make(map[domain_ns]zdns.Status)

func (s *Lookup) DoTargetedLookup(l LookupClient, name, nameServer string, lookupIpv4 bool, lookupIpv6 bool) (interface{}, []interface{}, zdns.Status, error) {
	retv := miekg.IpResult{}
	cur_domain_ns := domain_ns{domain: name, ns: nameServer}
	default_status := zdns.STATUS_NOERROR

	if res, ok := mockResults[cur_domain_ns]; ok {
		if lookupIpv4 {
			retv.IPv4Addresses = res.IPv4Addresses
		}
		if lookupIpv6 {
			retv.IPv6Addresses = res.IPv6Addresses
		}

		if status, ok := protocolStatus[cur_domain_ns]; ok {
			return retv, nil, status, nil
		} else {
			return retv, nil, default_status, nil
		}
	} else {
		return nil, nil, zdns.STATUS_ERROR, nil
	}
}

type minimalRecords struct {
	Status        zdns.Status
	IPv4Addresses []string
	IPv6Addresses []string
}

func InitTest(t *testing.T) (*GlobalLookupFactory, zdns.Lookup) {
	nsRecords = make(map[string]nslookup.Result)
	mockResults = make(map[domain_ns]miekg.IpResult)
	nsStatus = zdns.STATUS_NOERROR
	protocolStatus = make(map[domain_ns]zdns.Status)

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
	return glf, l
}

// Test One NS with one IP with only ipv4-lookup
func TestOneNsIpv4(t *testing.T) {
	_, l := InitTest(t)

	ns1 := "ns1.example.com"
	ipv4_1 := "192.0.2.3"
	ipv6_1 := "2001:db8::3"

	nsRecords["example.com"] = nslookup.Result{
		Servers: []nslookup.NSRecord{
			{
				Name:          ns1,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_1},
				IPv6Addresses: []string{ipv6_1},
				TTL:           3600,
			},
		},
	}

	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_1, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}

	expectedrecordsMap := make(map[string]minimalRecords)
	expectedrecordsMap[ipv4_1] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}
	expectedrecordsMap[ipv6_1] = minimalRecords{
		Status:        zdns.STATUS_ERROR,
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).ARecords, expectedrecordsMap)
}

// Test One NS with two IPs with only ipv4-lookup
func TestOneNsMultipleIps(t *testing.T) {
	_, l := InitTest(t)

	ns1 := "ns1.example.com"
	ipv4_1 := "192.0.2.3"
	ipv4_2 := "192.0.2.4"

	nsRecords["example.com"] = nslookup.Result{
		Servers: []nslookup.NSRecord{
			{
				Name:          ns1,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_1, ipv4_2},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}

	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_1, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_2, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}

	expectedrecordsMap := make(map[string]minimalRecords)
	expectedrecordsMap[ipv4_1] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}
	expectedrecordsMap[ipv4_2] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).ARecords, expectedrecordsMap)
}

// Test One NS with one IP with ipv4-lookup and ipv6-lookup
func TestOneNsIpv4AndIpv6(t *testing.T) {
	glf, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true

	ns1 := "ns1.example.com"
	ipv4_1 := "192.0.2.3"
	ipv6_1 := "2001:db8::3"

	nsRecords["example.com"] = nslookup.Result{
		Servers: []nslookup.NSRecord{
			{
				Name:          ns1,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_1},
				IPv6Addresses: []string{ipv6_1},
				TTL:           3600,
			},
		},
	}

	// This test assumes only IPv4 address returns records for the domain.
	// IPv6 doesn't return anything
	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_1, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}

	expectedrecordsMap := make(map[string]minimalRecords)
	expectedrecordsMap[ipv4_1] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	expectedrecordsMap[ipv6_1] = minimalRecords{
		Status:        zdns.STATUS_ERROR,
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).ARecords, expectedrecordsMap)
}

// Test One NS with IPv4, IPv6 addresses and with ipv4-lookup and ipv6-lookup
func TestOneNsAllIpsWork(t *testing.T) {
	glf, l := InitTest(t)
	glf.IPv4Lookup = true
	glf.IPv6Lookup = true

	ns1 := "ns1.example.com"
	ipv4_1 := "192.0.2.3"
	ipv6_1 := "2001:db8::3"

	nsRecords["example.com"] = nslookup.Result{
		Servers: []nslookup.NSRecord{
			{
				Name:          ns1,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_1},
				IPv6Addresses: []string{ipv6_1},
				TTL:           3600,
			},
		},
	}

	// This test assumes only both IPv4 and IPv6 NS addresses work
	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_1, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv6_1, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}

	expectedrecordsMap := make(map[string]minimalRecords)
	expectedrecordsMap[ipv4_1] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	expectedrecordsMap[ipv6_1] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).ARecords, expectedrecordsMap)
}

// Test two NS with one IP each with only ipv4-lookup
func TestTwoNsIpv4(t *testing.T) {
	_, l := InitTest(t)

	ns1 := "ns1.example.com"
	ipv4_1 := "192.0.2.3"
	ns2 := "ns1.example.com"
	ipv4_2 := "192.0.2.4"

	nsRecords["example.com"] = nslookup.Result{
		Servers: []nslookup.NSRecord{
			{
				Name:          ns1,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_1},
				IPv6Addresses: nil,
				TTL:           3600,
			},
			{
				Name:          ns2,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_2},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}

	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_1, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_2, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}

	expectedrecordsMap := make(map[string]minimalRecords)
	expectedrecordsMap[ipv4_1] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}
	expectedrecordsMap[ipv4_2] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).ARecords, expectedrecordsMap)
}

// Test two NS with one IP each with ipv4-lookup but giving different IPs for the A lookup
func TestTwoNsMismatchIpv4(t *testing.T) {
	_, l := InitTest(t)

	ns1 := "ns1.example.com"
	ipv4_1 := "192.0.2.3"
	ns2 := "ns1.example.com"
	ipv4_2 := "192.0.2.4"

	nsRecords["example.com"] = nslookup.Result{
		Servers: []nslookup.NSRecord{
			{
				Name:          ns1,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_1},
				IPv6Addresses: nil,
				TTL:           3600,
			},
			{
				Name:          ns2,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_2},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}

	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_1, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: []string{"2001:db8::1"},
	}
	mockResults[domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_2, "53")}] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.2"},
		IPv6Addresses: []string{"2001:db8::2"},
	}

	expectedrecordsMap := make(map[string]minimalRecords)
	expectedrecordsMap[ipv4_1] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}
	expectedrecordsMap[ipv4_2] = minimalRecords{
		Status:        zdns.STATUS_NOERROR,
		IPv4Addresses: []string{"192.0.2.2"},
		IPv6Addresses: nil,
	}
	res, _, _, _ := l.DoLookup("example.com", "")
	verifyResult(t, res.(Result).ARecords, expectedrecordsMap)
}

// Test error in A lookup via targeted lookup records
func TestErrorInOneTargetedLookup(t *testing.T) {
	_, l := InitTest(t)

	ns1 := "ns1.example.com"
	ipv4_1 := "192.0.2.3"
	ipv4_2 := "192.0.2.4"

	nsRecords["example.com"] = nslookup.Result{
		Servers: []nslookup.NSRecord{
			{
				Name:          ns1,
				Type:          "NS",
				IPv4Addresses: []string{ipv4_1, ipv4_2},
				IPv6Addresses: nil,
				TTL:           3600,
			},
		},
	}

	domain_ns_1 := domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_1, "53")}
	protocolStatus[domain_ns_1] = zdns.STATUS_SERVFAIL
	mockResults[domain_ns_1] = miekg.IpResult{
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	// The default protocol status is NOERROR, but we explicitly set it
	// in this test for sake of clarity
	domain_ns_2 := domain_ns{domain: "example.com", ns: net.JoinHostPort(ipv4_2, "53")}
	protocolStatus[domain_ns_2] = zdns.STATUS_NOERROR
	mockResults[domain_ns_2] = miekg.IpResult{
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}

	expectedrecordsMap := make(map[string]minimalRecords)
	expectedrecordsMap[ipv4_1] = minimalRecords{
		Status:        protocolStatus[domain_ns_1],
		IPv4Addresses: nil,
		IPv6Addresses: nil,
	}
	expectedrecordsMap[ipv4_2] = minimalRecords{
		Status:        protocolStatus[domain_ns_2],
		IPv4Addresses: []string{"192.0.2.1"},
		IPv6Addresses: nil,
	}
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, status, zdns.STATUS_NOERROR)
	verifyResult(t, res.(Result).ARecords, expectedrecordsMap)
}

func TestNXDomain(t *testing.T) {
	_, l := InitTest(t)

	res, _, status, _ := l.DoLookup("nonexistent.example.com", "")

	assert.Equal(t, status, zdns.STATUS_NXDOMAIN)
	assert.Equal(t, res, nil)
}

func TestServFail(t *testing.T) {
	_, l := InitTest(t)
	nsStatus = zdns.STATUS_SERVFAIL
	nsRecords["example.com"] = nslookup.Result{}
	res, _, status, _ := l.DoLookup("example.com", "")

	assert.Equal(t, status, nsStatus)
	assert.Equal(t, res, nil)
}

func verifyResult(t *testing.T, records []ARecord, expectedrecordsMap map[string]minimalRecords) {
	recordsLength := len(records)
	expectedrecordsLength := len(expectedrecordsMap)

	if recordsLength != expectedrecordsLength {
		t.Errorf("Expected %v records, found %v", expectedrecordsLength, recordsLength)
	}

	for _, record := range records {
		ip := record.NameServer.IP
		name := record.NameServer.Name
		expectedRecords, ok := expectedrecordsMap[ip]
		if !ok {
			t.Errorf("Did not find NS server %v in expected records.", ip)
		}
		assert.Equal(t, record.Status, expectedRecords.Status)
		if !reflect.DeepEqual(record.IPv4Addresses, expectedRecords.IPv4Addresses) {
			t.Errorf("IPv4 addresses not matching for NS %v with IP %v, expected %v, found %v", name, ip, expectedRecords.IPv4Addresses, record.IPv4Addresses)
		}
		if !reflect.DeepEqual(record.IPv6Addresses, expectedRecords.IPv6Addresses) {
			t.Errorf("IPv6 addresses not matching for NS %v with IP %v, expected %v, found %v", name, ip, expectedRecords.IPv6Addresses, record.IPv6Addresses)
		}
	}
}
