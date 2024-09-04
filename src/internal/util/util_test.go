/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
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

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsStringValidDomainName(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		// Valid domain names
		{"example.com", true},
		{"sub-domain.example.com", true},
		{"example.co.uk", true},
		{"a.com", true},
		{"0-0.com", true},
		{"example-domain.com", true},
		{"EXAMPLE.COM", true},
		{"subdomain.example.com", true},
		{"subdomain1.subdomain0.zdns-testing.com", true},
		{"subdomain4.subdomain3.subdomain2.subdomain1.zdns-testing.com", true},

		// Invalid domain names
		{"example", false},      // No TLD
		{"ex@mple.com", false},  // Invalid character
		{".example.com", false}, // Starts with dot
		{"-example.com", false}, // Starts with hyphen
		{"example-.com", false}, // Ends with hyphen
		{"example..com", false}, // Consecutive dots
		{"example.com-", false}, // Ends with hyphen
		{"example..", false},    // Ends with dot
		{"", false},             // Empty string
		{"exa mple.com", false}, // Contains space
		{"example.123", false},  // TLD with digits only
		{"example.com/", false}, // Contains slash
		{"example-.com", false}, // Hyphen at end of label
		{"-example.com", false}, // Hyphen at start of label
		{"example..com", false}, // Double dot
		{"example.c", false},    // Single letter TLD
		{"example.helloThisTLDIsOverThe63CharacterLimithelloThisTLDIsOverThe63Char", false}, // TLD too long, max 63 chars
		{"exa$mple.com", false}, // Invalid character
		{"a-very-long-domain-name-that-exceeds-the-maximum-length-of-253-characters-because-it-is-designed-to-" +
			"test-the-upper-boundary-conditions-of-domain-name-validation-functionality-in-golang." +
			"example.com", false}, // Domain too long, max domain name length is 253 characters
	}

	for _, test := range tests {
		t.Run(test.domain, func(t *testing.T) {
			result := IsStringValidDomainName(test.domain)
			if test.expected {
				require.True(t, result, "For domain %s, expected domain to be valid but got invalid", test.domain)
			} else {
				require.False(t, result, "For domain %s, expected domain to be invalid but got valid", test.domain)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []int
		entity   int
		expected bool
	}{
		{
			name:     "Entity in slice",
			slice:    []int{1, 2, 3, 4, 5},
			entity:   3,
			expected: true,
		},
		{
			name:     "Entity not in slice",
			slice:    []int{1, 2, 3, 4, 5},
			entity:   6,
			expected: false,
		},
		{
			name:     "Empty slice",
			slice:    []int{},
			entity:   1,
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Contains(test.slice, test.entity)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestConcat(t *testing.T) {
	inputSlice1 := make([]int, 0, 10)
	for i := 0; i < 3; i++ {
		inputSlice1 = append(inputSlice1, i)
	}
	// Test naive append
	newSlice1 := append(inputSlice1, 4)
	newSlice2 := append(inputSlice1, 5)
	newSlice3 := append(inputSlice1, 6)
	// Shows test is working, you'd think that this would be Equal but it isn't. append() is modifying the inputSlice1
	require.NotEqual(t, []int{0, 1, 2, 4}, newSlice1)
	require.NotEqual(t, []int{0, 1, 2, 5}, newSlice2)
	require.Equal(t, []int{0, 1, 2, 6}, newSlice3)
	// Now try with new Concat
	newSlice1 = Concat(inputSlice1, []int{4})
	newSlice2 = Concat(inputSlice1, []int{5})
	newSlice3 = Concat(inputSlice1, []int{6})
	require.Len(t, inputSlice1, 3)
	require.Equal(t, 10, cap(inputSlice1))
	require.Equal(t, []int{0, 1, 2}, inputSlice1)
	require.Equal(t, []int{0, 1, 2, 4}, newSlice1)
	require.Equal(t, []int{0, 1, 2, 5}, newSlice2)
	require.Equal(t, []int{0, 1, 2, 6}, newSlice3)
}
