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
			ExternalNameServers: []string{"127.0.0.53:53"},
			RootNameServers:     []string{"127.0.0.53:53"},
			LocalAddrs:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.Nil(t, err, "Expected no error but got %v", err)
	})
	t.Run("Using external nameserver with no port", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"127.0.0.53"},
			RootNameServers:     []string{"127.0.0.53:53"},
			LocalAddrs:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Using root nameserver with no port", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"127.0.0.53:53"},
			RootNameServers:     []string{"127.0.0.53"},
			LocalAddrs:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Missing external nameserver", func(t *testing.T) {
		rc := &ResolverConfig{
			RootNameServers: []string{"127.0.0.53:53"},
			LocalAddrs:      []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Missing root nameserver", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"127.0.0.53:53"},
			LocalAddrs:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Missing local addr", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"127.0.0.53:53"},
			RootNameServers:     []string{"127.0.0.53:53"},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})

	t.Run("Cannot mix loopback addresses in nameservers", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"127.0.0.53:53, 1.1.1.1:53"},
			RootNameServers:     []string{"127.0.0.53:53"},
			LocalAddrs:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Cannot mix loopback addresses among nameservers", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"1.1.1.1:53"},
			RootNameServers:     []string{"127.0.0.53:53"},
			LocalAddrs:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Cannot reach loopback NSes from non-loopback local address", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"127.0.0.53:53"},
			RootNameServers:     []string{"127.0.0.53:53"},
			LocalAddrs:          []net.IP{net.ParseIP("192.168.1.2")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
	t.Run("Cannot reach non-loopback NSes from loopback local address", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServers: []string{"1.1.1.1:53"},
			RootNameServers:     []string{"1.1.1.1:53"},
			LocalAddrs:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.Validate()
		require.NotNil(t, err)
	})
}
