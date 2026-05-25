/*
 * ZDNS Copyright 2026 Regents of the University of Michigan
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
	"fmt"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/zmap/dns"
)

type testCase struct {
	transportMode         TransportMode
	ipVersion             IPVersionMode
	iterationIPPreference IterationIPPreference
	lookupAllNameservers  bool
	useHTTPS              bool
	useTLS                bool
	recycleSockets        bool
	isExternalLookup      bool
}

func (t *testCase) String() string {
	return fmt.Sprintf("transport=%s/ip=%s/iterationpref=%s/lookupAllNS=%v/https=%v/tls=%v/recycleSocks=%v/externalLookup=%v",
		t.transportMode, t.ipVersion, t.iterationIPPreference, t.lookupAllNameservers, t.useHTTPS, t.useTLS, t.recycleSockets, t.isExternalLookup)
}

func TestNetworkConditions(t *testing.T) {
	const timeout = 2 * time.Second
	q := Question{
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	expectedResult, err := net.LookupHost(q.Name)
	if err != nil {
		t.Fatal("failed to lookup sample domain for test validation: ", err)
	}
	expectedResult = slices.DeleteFunc(expectedResult, func(s string) bool {
		// Delete non-IPv4 addresses since we're doing an A lookup
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return false
		}
		return true
	})
	slices.Sort(expectedResult)

	hostSupportsIPv4 := canReachIPv4()
	hostSupportsIPv6 := canReachIPv6()

	// skipReason returns a non-empty string if this case should be skipped.
	skipReason := func(tc testCase) string {
		if (tc.ipVersion == IPv4Only || tc.ipVersion == IPv4OrIPv6) && !hostSupportsIPv4 {
			return "host does not support IPv4"
		}
		if (tc.ipVersion == IPv6Only || tc.ipVersion == IPv4OrIPv6) && !hostSupportsIPv6 {
			return "host does not support IPv6"
		}
		// HTTPS and TLS are mutually exclusive
		if tc.useHTTPS && tc.useTLS {
			return "HTTPS and TLS cannot both be enabled"
		}
		// IterationIPPreference only meaningful for dual-stack
		if tc.ipVersion != IPv4OrIPv6 && tc.iterationIPPreference != NoPreference {
			return "IterationIPPreference only relevant in IPv4OrIPv6 mode"
		}
		if (tc.useHTTPS || tc.useTLS) && !tc.isExternalLookup {
			return "HTTPS and TLS only supported for external lookups, root nameservers don't support HTTPS/TLS"
		}
		if tc.transportMode == UDPOnly && (tc.useHTTPS || tc.useTLS) {
			return "UDP transport cannot be used with HTTPS or TLS"
		}
		return ""
	}

	var tests []testCase
	for _, ipv := range []IPVersionMode{IPv4Only, IPv6Only, IPv4OrIPv6} {
		for _, tm := range []TransportMode{UDPOnly, TCPOnly, UDPOrTCP} {
			for _, pref := range []IterationIPPreference{PreferIPv4, PreferIPv6, NoPreference} {
				for _, lan := range []bool{false, true} {
					for _, https := range []bool{false, true} {
						for _, tls := range []bool{false, true} {
							for _, recycle := range []bool{false, true} {
								for _, isExternalLookup := range []bool{false, true} {
									tests = append(tests,
										testCase{
											tm,
											ipv,
											pref,
											lan,
											https,
											tls,
											recycle,
											isExternalLookup})
								}
							}
						}
					}
				}
			}
		}
	}
	numTestsRan := 0
	for _, tc := range tests {
		tc := tc
		t.Run(tc.String(), func(t *testing.T) {
			t.Parallel()
			if reason := skipReason(tc); reason != "" {
				t.Skip(reason)
			}
			numTestsRan++

			// Create a fresh ResolverConfig per test (no shared cache)
			cfg := NewResolverConfig()
			if tc.useHTTPS {
				cfg.ExternalNameServersV4 = append(cfg.ExternalNameServersV4, []NameServer{{DomainName: GoogleDoHDomainName, IP: net.ParseIP("8.8.8.8"), Port: 443}, {DomainName: GoogleDoHDomainName, IP: net.ParseIP("8.8.4.4"), Port: 443}}...)
				cfg.ExternalNameServersV6 = append(cfg.ExternalNameServersV6, []NameServer{{DomainName: GoogleDoHDomainName, IP: net.ParseIP("2001:4860:4860::8844"), Port: 443}, {DomainName: GoogleDoHDomainName, IP: net.ParseIP("2001:4860:4860::8888"), Port: 443}}...)
			}
			if tc.useTLS {
				cfg.ExternalNameServersV4 = DefaultExternalDoTResolversV4
				cfg.ExternalNameServersV6 = DefaultExternalDoTResolversV6
			}
			cfg.Timeout = timeout
			cfg.NetworkTimeout = timeout
			cfg.IterativeTimeout = timeout
			cfg.Retries = 3
			cfg.IPVersionMode = tc.ipVersion
			cfg.TransportMode = tc.transportMode
			cfg.IterationIPPreference = tc.iterationIPPreference
			cfg.LookupAllNameServers = tc.lookupAllNameservers
			cfg.DNSOverHTTPS = tc.useHTTPS
			cfg.DNSOverTLS = tc.useTLS
			cfg.ShouldRecycleSockets = tc.recycleSockets
			var err error
			if err = cfg.Validate(); err != nil {
				t.Fatalf("could not validate config: %v", err)
			}
			var resolver *Resolver
			resolver, err = InitResolver(cfg)
			if err != nil {
				t.Fatalf("could not initialize resolver: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			var result *SingleQueryResult
			var status Status
			if tc.isExternalLookup {
				result, _, status, err = resolver.ExternalLookup(ctx, &q, nil)
			} else {
				result, _, status, err = resolver.IterativeLookup(ctx, &q)
			}
			if err != nil {
				t.Fatalf("could not perform lookup: %v", err)
			}
			if status != StatusNoError {
				t.Fatalf("lookup returned status %v; want %v", status, StatusNoError)
			}
			actualResult := make([]string, 0, len(result.Answers))
			for _, answer := range result.Answers {
				if ans, ok := answer.(Answer); !ok {
					t.Fatalf("answer was incorrect type")
				} else {
					actualResult = append(actualResult, ans.Answer)
				}
			}
			slices.Sort(actualResult)
			if !reflect.DeepEqual(actualResult, expectedResult) {
				t.Errorf("got %v; want %v", actualResult, expectedResult)
			}
		})
	}
}

func canReachIPv4() bool {
	conn, err := net.DialTimeout("tcp4", "8.8.8.8:53", 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func canReachIPv6() bool {
	conn, err := net.DialTimeout("tcp6", "[2001:4860:4860::8888]:53", 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
