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

package cli

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zmap/zdns/v2/src/zdns"
)

func TestConvertNameServerStringToNameServer(t *testing.T) {
	tests := []struct {
		nameServerString   string
		expectedNameServer string
	}{
		{
			"1.1.1.1",
			"1.1.1.1:53",
		}, {
			"1.1.1.1:35",
			"1.1.1.1:35",
		}, {
			"2606:4700:4700::1111",
			"[2606:4700:4700::1111]:53",
		}, {
			"[2606:4700:4700::1111]:35",
			"[2606:4700:4700::1111]:35",
		},
	}
	for _, test := range tests {
		nses, err := convertNameServerStringToNameServer(test.nameServerString, zdns.IPv4OrIPv6, false, false)
		require.Nil(t, err)
		require.Len(t, nses, 1)
		if nses[0].String() != test.expectedNameServer {
			t.Errorf("Expected %s, got %s", test.expectedNameServer, nses[0].String())
		}
	}
	// need to convert these to use the .String method to test
	t.Run("Domain Name as Name Server, both IPv4 and v6", func(t *testing.T) {
		nses, err := convertNameServerStringToNameServer("one.one.one.one", zdns.IPv4OrIPv6, false, false)
		require.Nil(t, err)
		expectedNSes := []string{"1.1.1.1:53", "1.0.0.1:53", "[2606:4700:4700::1111]:53", "[2606:4700:4700::1001]:53"}
		containsExpectedNameServerStrings(t, nses, expectedNSes)
	})
	t.Run("Domain Name as Name Server, just IPv4", func(t *testing.T) {
		nses, err := convertNameServerStringToNameServer("one.one.one.one", zdns.IPv4Only, false, false)
		require.Nil(t, err)
		expectedNSes := []string{"1.1.1.1:53", "1.0.0.1:53"}
		containsExpectedNameServerStrings(t, nses, expectedNSes)
	})
	t.Run("Domain Name as Name Server, just IPv6", func(t *testing.T) {
		nses, err := convertNameServerStringToNameServer("one.one.one.one", zdns.IPv6Only, false, false)
		require.Nil(t, err)
		expectedNSes := []string{"[2606:4700:4700::1111]:53", "[2606:4700:4700::1001]:53"}
		containsExpectedNameServerStrings(t, nses, expectedNSes)
	})
	t.Run("Domain Name as Name Server, port provided", func(t *testing.T) {
		nses, err := convertNameServerStringToNameServer("one.one.one.one:2345", zdns.IPv4OrIPv6, false, false)
		require.Nil(t, err)
		expectedNSes := []string{"1.1.1.1:2345", "1.0.0.1:2345", "[2606:4700:4700::1111]:2345", "[2606:4700:4700::1001]:2345"}
		containsExpectedNameServerStrings(t, nses, expectedNSes)
	})
	t.Run("Bad domain name", func(t *testing.T) {
		_, err := convertNameServerStringToNameServer("bad.domain.name.random.j83bs", zdns.IPv4OrIPv6, false, false)
		require.Error(t, err)
	})
	t.Run("Bad IP address", func(t *testing.T) {
		_, err := convertNameServerStringToNameServer("1.1.1.556", zdns.IPv4OrIPv6, false, false)
		require.Error(t, err)
	})
}

func containsExpectedNameServerStrings(t *testing.T, actualNSes []zdns.NameServer, expectedNameServers []string) {
	require.Len(t, actualNSes, len(expectedNameServers))
	currentNS := ""
	var foundNS bool
	for _, ns := range expectedNameServers {
		currentNS = ns
		foundNS = false
		for _, actualNS := range actualNSes {
			if actualNS.String() == ns {
				foundNS = true
				break
			}
		}
		if !foundNS {
			require.Fail(t, fmt.Sprintf("Expected nameserver %s not present in actual list", currentNS))
		}
	}
}

func TestRemoveDomainsFromNameServersString(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		// Test with no name servers (empty list)
		{
			input:    "",
			expected: []string{},
		},
		// Test with single IP only
		{
			input:    "1.1.1.1",
			expected: []string{"1.1.1.1"},
		},
		// Test with single domain only
		{
			input:    "example.com",
			expected: []string{},
		},
		// Test with single IP+Port
		{
			input:    "1.1.1.1:53",
			expected: []string{"1.1.1.1:53"},
		},
		// Test with two IPs
		{
			input:    "1.1.1.1,8.8.8.8",
			expected: []string{"1.1.1.1", "8.8.8.8"},
		},
		// Test with IP and domain
		{
			input:    "1.1.1.1,example.com",
			expected: []string{"1.1.1.1"},
		},
		// Test with IP, IP+Port, and domain
		{
			input:    "1.1.1.1,example.com,8.8.8.8:53",
			expected: []string{"1.1.1.1", "8.8.8.8:53"},
		},
		// Test with IPv6, domain, and IPv4
		{
			input:    "2001:4860:4860::8888,example.com,8.8.8.8",
			expected: []string{"2001:4860:4860::8888", "8.8.8.8"},
		},
		// Test with IPv6+Port and domain
		{
			input:    "[2001:4860:4860::8888]:53,example.com",
			expected: []string{"[2001:4860:4860::8888]:53"},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := removeDomainsFromNameServersString(test.input)
			require.Equal(t, result, test.expected)
		})
	}
}

func TestParseNormalInputLine(t *testing.T) {
	tests := []struct {
		input            string
		expectedDomain   string
		expectedNS       string
		expectedTriggers []string
	}{
		{
			input:            "example.com",
			expectedDomain:   "example.com",
			expectedNS:       "",
			expectedTriggers: []string{},
		},
		{
			input:            "example.com,1.1.1.1",
			expectedDomain:   "example.com",
			expectedNS:       "1.1.1.1",
			expectedTriggers: []string{},
		},
		{
			// spaces after commas
			input:            "example.com, 1.1.1.1",
			expectedDomain:   "example.com",
			expectedNS:       "1.1.1.1",
			expectedTriggers: []string{},
		},
		{
			input:            "example.com, 1.1.1.1, trigger1",
			expectedDomain:   "example.com",
			expectedNS:       "1.1.1.1",
			expectedTriggers: []string{"trigger1"},
		},
		{
			input:            "example.com,, trigger1",
			expectedDomain:   "example.com",
			expectedNS:       "",
			expectedTriggers: []string{"trigger1"},
		},
		{
			input:            "example.com,,,",
			expectedDomain:   "example.com",
			expectedNS:       "",
			expectedTriggers: []string{"", ""},
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			domain, ns, triggers := parseNormalInputLine(test.input)
			require.Equal(t, test.expectedDomain, domain)
			require.Equal(t, test.expectedNS, ns)
			require.Equal(t, test.expectedTriggers, triggers)
		})
	}
}

// writeTempResolvConf writes a resolv.conf-style file with the given nameservers and
// returns its path. The file is cleaned up when the test ends.
func writeTempResolvConf(t *testing.T, nameservers ...string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "resolv.conf")
	require.NoError(t, err)
	for _, ns := range nameservers {
		_, err = fmt.Fprintf(f, "nameserver %s\n", ns)
		require.NoError(t, err)
	}
	require.NoError(t, f.Close())
	return f.Name()
}

// baseConf returns a CLIConf with sensible non-zero defaults so populateResolverConfig
// does not hit log.Fatal on missing required fields. Individual tests override specific
// fields to exercise the behavior under test.
func baseConf(t *testing.T) CLIConf {
	t.Helper()
	return CLIConf{
		GeneralOptions: GeneralOptions{
			Timeout:          20,
			NetworkTimeout:   2,
			IterationTimeout: 8,
			Retries:          3,
			MaxDepth:         10,
			CacheSize:        100,
		},
		InputOutputOptions: InputOutputOptions{
			// Provide a resolv.conf with a known IPv4 address so tests that do not
			// supply name servers or local addresses get a deterministic IP mode.
			DNSConfigFilePath: writeTempResolvConf(t, "1.1.1.1"),
			Verbosity:         3,
		},
	}
}

// mustParseIP panics if the string is not a valid IP. Only used in test setup.
func mustParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid IP in test: " + s)
	}
	return ip
}

func TestPopulateResolverConfig(t *testing.T) {
	const (
		ipv4NS  = "1.1.1.1"
		ipv4NS2 = "8.8.8.8"
		ipv6NS  = "2606:4700:4700::1111"
		ipv6NS2 = "2001:4860:4860::8888"

		localIPv4  = "192.168.1.5"
		localIPv6  = "fd00::1"
		localIPv42 = "10.0.0.1"
	)

	t.Run("IPVersionMode from --4/--6 flags", func(t *testing.T) {
		tests := []struct {
			name              string
			ipv4Only          bool
			ipv6Only          bool
			nameServers       []string
			nameServersString string
			wantIPVersionMode zdns.IPVersionMode
			wantIterPref      zdns.IterationIPPreference
			wantV4NSes        []string // IPs expected in External/RootNameServersV4; nil means don't check
			wantV6NSes        []string // IPs expected in External/RootNameServersV6; nil means don't check
			wantV4Empty       bool
			wantV6Empty       bool
		}{
			{
				name:              "--4 forces IPv4Only regardless of nameserver family",
				ipv4Only:          true,
				nameServers:       []string{ipv4NS},
				nameServersString: ipv4NS,
				wantIPVersionMode: zdns.IPv4Only,
				wantIterPref:      zdns.PreferIPv4,
				wantV4NSes:        []string{ipv4NS},
				wantV6Empty:       true,
			},
			{
				name:              "--6 forces IPv6Only regardless of nameserver family",
				ipv6Only:          true,
				nameServers:       []string{ipv6NS},
				nameServersString: ipv6NS,
				wantIPVersionMode: zdns.IPv6Only,
				wantIterPref:      zdns.PreferIPv6,
				wantV6NSes:        []string{ipv6NS},
				wantV4Empty:       true,
			},
			{
				name:              "--4 with mixed nameservers drops IPv6 nameservers",
				ipv4Only:          true,
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantIPVersionMode: zdns.IPv4Only,
				wantIterPref:      zdns.PreferIPv4,
				wantV4NSes:        []string{ipv4NS},
				wantV6Empty:       true,
			},
			{
				name:              "--6 with mixed nameservers drops IPv4 nameservers",
				ipv6Only:          true,
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantIPVersionMode: zdns.IPv6Only,
				wantIterPref:      zdns.PreferIPv6,
				wantV6NSes:        []string{ipv6NS},
				wantV4Empty:       true,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gc := baseConf(t)
				gc.IPv4TransportOnly = tt.ipv4Only
				gc.IPv6TransportOnly = tt.ipv6Only
				gc.NameServers = tt.nameServers
				gc.NameServersString = tt.nameServersString
				config := populateResolverConfig(&gc)
				assert.Equal(t, tt.wantIPVersionMode, config.IPVersionMode)
				assert.Equal(t, tt.wantIterPref, config.IterationIPPreference)
				if tt.wantV4Empty {
					assert.Empty(t, config.ExternalNameServersV4, "ExternalNameServersV4 should be empty")
					assert.Empty(t, config.RootNameServersV4, "RootNameServersV4 should be empty")
				} else if tt.wantV4NSes != nil {
					requireNSIPs(t, config.ExternalNameServersV4, tt.wantV4NSes, "ExternalNameServersV4")
					requireNSIPs(t, config.RootNameServersV4, tt.wantV4NSes, "RootNameServersV4")
				}
				if tt.wantV6Empty {
					assert.Empty(t, config.ExternalNameServersV6, "ExternalNameServersV6 should be empty")
					assert.Empty(t, config.RootNameServersV6, "RootNameServersV6 should be empty")
				} else if tt.wantV6NSes != nil {
					requireNSIPs(t, config.ExternalNameServersV6, tt.wantV6NSes, "ExternalNameServersV6")
					requireNSIPs(t, config.RootNameServersV6, tt.wantV6NSes, "RootNameServersV6")
				}
			})
		}
	})

	t.Run("IPVersionMode inferred from nameserver addresses", func(t *testing.T) {
		tests := []struct {
			name              string
			nameServers       []string
			nameServersString string
			wantIPVersionMode zdns.IPVersionMode
			wantIterPref      zdns.IterationIPPreference
		}{
			{
				name:              "IPv4-only nameservers infer IPv4Only",
				nameServers:       []string{ipv4NS, ipv4NS2},
				nameServersString: ipv4NS + "," + ipv4NS2,
				wantIPVersionMode: zdns.IPv4Only,
				wantIterPref:      zdns.PreferIPv4,
			},
			{
				name:              "IPv6-only nameservers infer IPv6Only",
				nameServers:       []string{ipv6NS, ipv6NS2},
				nameServersString: ipv6NS + "," + ipv6NS2,
				wantIPVersionMode: zdns.IPv6Only,
				wantIterPref:      zdns.PreferIPv6,
			},
			{
				name:              "mixed IPv4 and IPv6 nameservers infer IPv4OrIPv6",
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantIPVersionMode: zdns.IPv4OrIPv6,
				wantIterPref:      zdns.NoPreference,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gc := baseConf(t)
				gc.NameServers = tt.nameServers
				gc.NameServersString = tt.nameServersString
				config := populateResolverConfig(&gc)
				assert.Equal(t, tt.wantIPVersionMode, config.IPVersionMode)
				assert.Equal(t, tt.wantIterPref, config.IterationIPPreference)
			})
		}
	})

	t.Run("IPVersionMode inferred from local addresses when no nameservers provided", func(t *testing.T) {
		tests := []struct {
			name              string
			localAddrs        []net.IP
			wantIPVersionMode zdns.IPVersionMode
			wantIterPref      zdns.IterationIPPreference
			wantLocalAddrsV4  []net.IP
			wantLocalAddrsV6  []net.IP
		}{
			{
				name:              "IPv4 local addr infers IPv4Only and populates LocalAddrsV4",
				localAddrs:        []net.IP{mustParseIP(localIPv4)},
				wantIPVersionMode: zdns.IPv4Only,
				wantIterPref:      zdns.PreferIPv4,
				wantLocalAddrsV4:  []net.IP{mustParseIP(localIPv4)},
				wantLocalAddrsV6:  []net.IP{},
			},
			{
				name:              "IPv6 local addr infers IPv6Only and populates LocalAddrsV6",
				localAddrs:        []net.IP{mustParseIP(localIPv6)},
				wantIPVersionMode: zdns.IPv6Only,
				wantIterPref:      zdns.PreferIPv6,
				wantLocalAddrsV4:  []net.IP{},
				wantLocalAddrsV6:  []net.IP{mustParseIP(localIPv6)},
			},
			{
				name:              "mixed local addrs infer IPv4OrIPv6 and populate both lists",
				localAddrs:        []net.IP{mustParseIP(localIPv4), mustParseIP(localIPv6)},
				wantIPVersionMode: zdns.IPv4OrIPv6,
				wantIterPref:      zdns.NoPreference,
				wantLocalAddrsV4:  []net.IP{mustParseIP(localIPv4)},
				wantLocalAddrsV6:  []net.IP{mustParseIP(localIPv6)},
			},
			{
				name:              "multiple IPv4 local addrs all stored in LocalAddrsV4",
				localAddrs:        []net.IP{mustParseIP(localIPv4), mustParseIP(localIPv42)},
				wantIPVersionMode: zdns.IPv4Only,
				wantIterPref:      zdns.PreferIPv4,
				wantLocalAddrsV4:  []net.IP{mustParseIP(localIPv4), mustParseIP(localIPv42)},
				wantLocalAddrsV6:  []net.IP{},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gc := baseConf(t)
				gc.LocalAddrs = tt.localAddrs
				config := populateResolverConfig(&gc)
				assert.Equal(t, tt.wantIPVersionMode, config.IPVersionMode)
				assert.Equal(t, tt.wantIterPref, config.IterationIPPreference)
				assert.Equal(t, tt.wantLocalAddrsV4, config.LocalAddrsV4)
				assert.Equal(t, tt.wantLocalAddrsV6, config.LocalAddrsV6)
			})
		}
	})

	t.Run("local addresses populated when nameservers also provided", func(t *testing.T) {
		tests := []struct {
			name              string
			nameServers       []string
			nameServersString string
			localAddrs        []net.IP
			wantLocalAddrsV4  []net.IP
			wantLocalAddrsV6  []net.IP
		}{
			{
				name:              "IPv4 local addr is propagated when IPv4 nameservers are also set",
				nameServers:       []string{ipv4NS},
				nameServersString: ipv4NS,
				localAddrs:        []net.IP{mustParseIP(localIPv4)},
				wantLocalAddrsV4:  []net.IP{mustParseIP(localIPv4)},
				wantLocalAddrsV6:  []net.IP{},
			},
			{
				name:              "IPv6 local addr is propagated when IPv6 nameservers are also set",
				nameServers:       []string{ipv6NS},
				nameServersString: ipv6NS,
				localAddrs:        []net.IP{mustParseIP(localIPv6)},
				wantLocalAddrsV4:  []net.IP{},
				wantLocalAddrsV6:  []net.IP{mustParseIP(localIPv6)},
			},
			{
				name:              "mixed local addrs are propagated when mixed nameservers are also set",
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				localAddrs:        []net.IP{mustParseIP(localIPv4), mustParseIP(localIPv6)},
				wantLocalAddrsV4:  []net.IP{mustParseIP(localIPv4)},
				wantLocalAddrsV6:  []net.IP{mustParseIP(localIPv6)},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gc := baseConf(t)
				gc.NameServers = tt.nameServers
				gc.NameServersString = tt.nameServersString
				gc.LocalAddrs = tt.localAddrs
				config := populateResolverConfig(&gc)
				// These assertions currently fail due to the regression in
				// populateIPTransportMode: when nameservers are provided the function
				// returns early, skipping the populateLocalAddresses call.
				assert.Equal(t, tt.wantLocalAddrsV4, config.LocalAddrsV4, "LocalAddrsV4")
				assert.Equal(t, tt.wantLocalAddrsV6, config.LocalAddrsV6, "LocalAddrsV6")
			})
		}
	})

	t.Run("IterationIPPreference with prefer flags", func(t *testing.T) {
		tests := []struct {
			name             string
			preferIPv4       bool
			preferIPv6       bool
			nameServers      []string
			nameServersString string
			wantIterPref     zdns.IterationIPPreference
		}{
			{
				name:              "--prefer-ipv4-iteration with mixed nameservers sets PreferIPv4",
				preferIPv4:        true,
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantIterPref:      zdns.PreferIPv4,
			},
			{
				name:              "--prefer-ipv6-iteration with mixed nameservers sets PreferIPv6",
				preferIPv6:        true,
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantIterPref:      zdns.PreferIPv6,
			},
			{
				name:              "no preference flag with mixed nameservers sets NoPreference",
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantIterPref:      zdns.NoPreference,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gc := baseConf(t)
				gc.PreferIPv4Iteration = tt.preferIPv4
				gc.PreferIPv6Iteration = tt.preferIPv6
				gc.NameServers = tt.nameServers
				gc.NameServersString = tt.nameServersString
				config := populateResolverConfig(&gc)
				assert.Equal(t, tt.wantIterPref, config.IterationIPPreference)
			})
		}
	})

	t.Run("nameserver lists populated correctly from user-provided nameservers", func(t *testing.T) {
		tests := []struct {
			name              string
			ipv4Only          bool
			ipv6Only          bool
			nameServers       []string
			nameServersString string
			wantV4NSes        []string // expected ExternalNameServersV4 IPs
			wantV6NSes        []string // expected ExternalNameServersV6 IPs
			wantV4Empty       bool     // ExternalNameServersV4 should be empty
			wantV6Empty       bool     // ExternalNameServersV6 should be empty
		}{
			{
				name:              "IPv4 nameserver populates ExternalNameServersV4 and RootNameServersV4",
				nameServers:       []string{ipv4NS},
				nameServersString: ipv4NS,
				wantV4NSes:        []string{ipv4NS},
				wantV6Empty:       true,
			},
			{
				name:              "IPv6 nameserver populates ExternalNameServersV6 and RootNameServersV6",
				nameServers:       []string{ipv6NS},
				nameServersString: ipv6NS,
				wantV6NSes:        []string{ipv6NS},
				wantV4Empty:       true,
			},
			{
				name:              "mixed nameservers populate both V4 and V6 lists",
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantV4NSes:        []string{ipv4NS},
				wantV6NSes:        []string{ipv6NS},
			},
			{
				name:              "--4 drops IPv6 nameservers from ExternalNameServersV6",
				ipv4Only:          true,
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantV4NSes:        []string{ipv4NS},
				wantV6Empty:       true,
			},
			{
				name:              "--6 drops IPv4 nameservers from ExternalNameServersV4",
				ipv6Only:          true,
				nameServers:       []string{ipv4NS, ipv6NS},
				nameServersString: ipv4NS + "," + ipv6NS,
				wantV6NSes:        []string{ipv6NS},
				wantV4Empty:       true,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gc := baseConf(t)
				gc.IPv4TransportOnly = tt.ipv4Only
				gc.IPv6TransportOnly = tt.ipv6Only
				gc.NameServers = tt.nameServers
				gc.NameServersString = tt.nameServersString
				config := populateResolverConfig(&gc)

				if tt.wantV4Empty {
					assert.Empty(t, config.ExternalNameServersV4, "ExternalNameServersV4 should be empty")
					assert.Empty(t, config.RootNameServersV4, "RootNameServersV4 should be empty")
				} else if tt.wantV4NSes != nil {
					requireNSIPs(t, config.ExternalNameServersV4, tt.wantV4NSes, "ExternalNameServersV4")
					requireNSIPs(t, config.RootNameServersV4, tt.wantV4NSes, "RootNameServersV4")
				}

				if tt.wantV6Empty {
					assert.Empty(t, config.ExternalNameServersV6, "ExternalNameServersV6 should be empty")
					assert.Empty(t, config.RootNameServersV6, "RootNameServersV6 should be empty")
				} else if tt.wantV6NSes != nil {
					requireNSIPs(t, config.ExternalNameServersV6, tt.wantV6NSes, "ExternalNameServersV6")
					requireNSIPs(t, config.RootNameServersV6, tt.wantV6NSes, "RootNameServersV6")
				}
			})
		}
	})

	t.Run("iterative resolution uses root servers when no nameservers provided", func(t *testing.T) {
		gc := baseConf(t)
		gc.IPv4TransportOnly = true // avoid resolv.conf dependency for IP mode detection
		gc.IterativeResolution = true
		config := populateResolverConfig(&gc)
		assert.Equal(t, zdns.RootServersV4[:], config.ExternalNameServersV4)
		assert.Equal(t, zdns.RootServersV4[:], config.RootNameServersV4)
	})

	t.Run("non-iterative resolution reads nameservers from resolv.conf when none provided", func(t *testing.T) {
		confFile := writeTempResolvConf(t, ipv4NS)
		gc := baseConf(t)
		gc.DNSConfigFilePath = confFile
		config := populateResolverConfig(&gc)
		assert.Equal(t, zdns.IPv4Only, config.IPVersionMode)
		requireNSIPs(t, config.ExternalNameServersV4, []string{ipv4NS}, "ExternalNameServersV4")
		requireNSIPs(t, config.RootNameServersV4, []string{ipv4NS}, "RootNameServersV4")
	})
}

// requireNSIPs asserts that the given nameserver list contains exactly the given IPs (order-independent).
func requireNSIPs(t *testing.T, actual []zdns.NameServer, wantIPs []string, label string) {
	t.Helper()
	require.Len(t, actual, len(wantIPs), "%s: expected %d nameserver(s), got %d", label, len(wantIPs), len(actual))
	actualIPs := make(map[string]struct{}, len(actual))
	for _, ns := range actual {
		actualIPs[ns.IP.String()] = struct{}{}
	}
	for _, ip := range wantIPs {
		_, ok := actualIPs[ip]
		assert.True(t, ok, "%s: expected IP %s not found in actual list", label, ip)
	}
}
