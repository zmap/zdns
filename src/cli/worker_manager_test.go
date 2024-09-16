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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zmap/zdns/src/zdns"
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
		_, err := convertNameServerStringToNameServer("bad.domain.name", zdns.IPv4OrIPv6, false, false)
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
