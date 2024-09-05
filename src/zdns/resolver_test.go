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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolverConfig_Validate(t *testing.T) {
	t.Run("Valid config with external/root name servers and local addr", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []NameServer{{IP: net.ParseIP("127.0.0.53"), Port: 53}},
			RootNameServersV4:     []NameServer{{IP: net.ParseIP("127.0.0.53"), Port: 53}},
			LocalAddrsV4:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.Nil(t, err, "Expected no error but got %v", err)
	})
	t.Run("Using external nameserver with no port", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []NameServer{{IP: net.ParseIP("127.0.0.53")}},
			RootNameServersV4:     []NameServer{{IP: net.ParseIP("127.0.0.53"), Port: 53}},
			LocalAddrsV4:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Using root nameserver with no port", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []NameServer{{IP: net.ParseIP("127.0.0.53"), Port: 53}},
			RootNameServersV4:     []NameServer{{IP: net.ParseIP("127.0.0.53")}},
			LocalAddrsV4:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Missing external nameserver", func(t *testing.T) {
		rc := &ResolverConfig{
			RootNameServersV4: []NameServer{{IP: net.ParseIP("127.0.0.53")}},
			LocalAddrsV4:      []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Missing root nameserver", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []NameServer{{IP: net.ParseIP("127.0.0.53"), Port: 53}},
			LocalAddrsV4:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
}
