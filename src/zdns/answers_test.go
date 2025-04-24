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
package zdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatLOCCoordinates(t *testing.T) {
	tests := []struct {
		name     string
		lat      uint32
		long     uint32
		alt      uint32
		size     uint8
		horizPre uint8
		vertPre  uint8
		expected string
	}{
		// Test cases for different locations
		{
			name:     "San Francisco",
			lat:      2147483648 + 134726000, // 37° 25′ 26″ N
			long:     2147483648 - 439796000, // 122° 9′ 56″ W
			alt:      10003000,               // 30.00 m
			size:     1,
			horizPre: 1,
			vertPre:  1,
			expected: "37 25 26.000 N 122 9 56.000 W 30.00m 1m 1m 1m",
		},
		{
			name:     "Greenwich",
			lat:      2147483648, // 0° 0′ 0″ N
			long:     2147483648, // 0° 0′ 0″ E
			alt:      10000000,   // 0.00 m
			size:     18,         // 100 m
			horizPre: 1,
			vertPre:  1,
			expected: "0 0 0.000 N 0 0 0.000 E 0.00m 18m 1m 1m",
		},
		{
			name:     "Mount Everest",
			lat:      2147483648 + 100757000, // 27° 59′ 17″ N
			long:     2147483648 + 312928000, // 86° 55′ 28″ E
			alt:      10884800,               // 8848.00 m
			size:     1,
			horizPre: 1,
			vertPre:  1,
			expected: "27 59 17.000 N 86 55 28.000 E 8848.00m 1m 1m 1m",
		},
		{
			name:     "Dead Sea (below sea level)",
			lat:      2147483648 + 116660000, // 32° 24′ 20″ N
			long:     2147483648 + 126440000, // 35° 7′ 20″ E
			alt:      9995790,                // -42.1 m
			size:     1,
			horizPre: 1,
			vertPre:  1,
			expected: "32 24 20.000 N 35 7 20.000 E -42.10m 1m 1m 1m",
		},
		// Test cases for different hemispheres
		{
			name:     "South Latitude",
			lat:      2147483648 - 14209648,  // 3 56 49.648 S
			long:     2147483648 - 411686648, // 114 21 26.648 W
			alt:      10003000,               // 30.00m
			size:     1,                      // 1m
			horizPre: 1,                      // 1m
			vertPre:  1,                      // 1m
			expected: "3 56 49.648 S 114 21 26.648 W 30.00m 1m 1m 1m",
		},
		{
			name:     "North Latitude",
			lat:      2147483648 + 152514000, // 42 21 54 N
			long:     2147483648 - 255960000, // 71 06 00 W
			alt:      10000000,               // 0m
			size:     1,                      // 1m
			horizPre: 1,                      // 1m
			vertPre:  1,                      // 1m
			expected: "42 21 54.000 N 71 6 0.000 W 0.00m 1m 1m 1m",
		},
		// Test cases for different altitudes
		{
			name:     "High Altitude",
			lat:      2147483648 + 152514000, // 42 21 54 N
			long:     2147483648 - 255960000, // 71 06 00 W
			alt:      20000000,               // 100000.00m
			size:     1,                      // 1m
			horizPre: 1,                      // 1m
			vertPre:  1,                      // 1m
			expected: "42 21 54.000 N 71 6 0.000 W 100000.00m 1m 1m 1m",
		},
		{
			name:     "Negative Altitude",
			lat:      2147483648 + 152514000, // 42 21 54 N
			long:     2147483648 - 255960000, // 71 06 00 W
			alt:      9990000,                // -100.00m
			size:     1,                      // 1m
			horizPre: 1,                      // 1m
			vertPre:  1,                      // 1m
			expected: "42 21 54.000 N 71 6 0.000 W -100.00m 1m 1m 1m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatLOCCoordinates(tt.lat, tt.long, tt.alt, tt.size, tt.horizPre, tt.vertPre)
			assert.Equal(t, tt.expected, got, "formatLOCCoordinates() returned unexpected result")
		})
	}
}
