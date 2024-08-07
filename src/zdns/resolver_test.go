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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolverConfig_PopulateAndValidate(t *testing.T) {
	t.Run("Using loopback nameserver and no specified local address", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"127.0.0.53:53"},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err, "Expected no error but got %v", err)
		require.Equal(t, LoopbackAddrString, rc.LocalAddrsV4[0].String())
	})

	t.Run("Using nameserver with no port", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"1.1.1.1"},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err)
		require.Equal(t, "1.1.1.1:53", rc.ExternalNameServersV4[0], "Expected port 53 to be appended to nameserver")
	})
	t.Run("Using nameserver with port", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"1.1.1.1:64"},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err)
		require.Equal(t, "1.1.1.1:64", rc.ExternalNameServersV4[0], "Expected nameserver to remain unchanged")
	})
	t.Run("Using local address with no port", func(t *testing.T) {
		rc := &ResolverConfig{
			LocalAddrsV4: []net.IP{net.ParseIP("192.168.1.1")},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err)
		require.Equal(t, "192.168.1.1", rc.LocalAddrsV4[0].String(), "Expected local address to be unchanged")
	})

	t.Run("Mixing loopback and non-loopback nameservers results in error", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"127.0.0.1:53", "8.8.8.8:53"},
		}
		err := rc.PopulateAndValidate()
		require.NotNil(t, err, "Mixing loopback and non-loopback nameservers should result in an error")
	})

	t.Run("Using non-loopback nameservers with loopback local address results in nameserver being overwritten", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"8.8.8.8:53"},
			LocalAddrsV4:          []net.IP{net.ParseIP("127.0.0.1")},
		}
		err := rc.PopulateAndValidate()
		require.NotNil(t, err, "Using non-loopback nameservers with loopback local address should result in an error")
	})

	t.Run("Using loopback nameservers with non-loopback local address results in local address being overwritten", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"127.0.0.1:53"},
			LocalAddrsV4:          []net.IP{net.ParseIP("192.168.0.1")},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err)
		require.Equal(t, LoopbackAddrString, rc.LocalAddrsV4[0].String(), "Expected local address to be overwritten with loopback address")
	})

	t.Run("Valid non-loopback nameservers and local addresses", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"8.8.8.8:53", "8.8.4.4:53"},
			LocalAddrsV4:          []net.IP{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2")},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err, "Valid non-loopback nameservers and local addresses should not result in an error")
		require.Equal(t, "8.8.8.8:53", rc.ExternalNameServersV4[0], "Expected nameserver to remain unchanged")
		require.Equal(t, "192.168.0.1", rc.LocalAddrsV4[0].String(), "Expected local address to remain unchanged")
	})

	t.Run("Valid loopback nameservers and local addresses", func(t *testing.T) {
		rc := &ResolverConfig{
			ExternalNameServersV4: []string{"127.0.0.1:53", "127.0.0.2:53"},
			LocalAddrsV4:          []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err, "Valid loopback nameservers and local addresses should not result in an error")
		require.Equal(t, LoopbackAddrString, rc.LocalAddrsV4[0].String(), "Expected local address to be overwritten with loopback address")
		require.Equal(t, "127.0.0.1:53", rc.ExternalNameServersV4[0], "Expected nameserver to remain unchanged")
	})

	t.Run("Invalid Root NS", func(t *testing.T) {
		rc := &ResolverConfig{
			RootNameServersV4: []string{"1.2.3"},
		}
		err := rc.PopulateAndValidate()
		require.NotNil(t, err, "Expected error for invalid root nameserver")
	})

	t.Run("Validate Port-appended Root NS", func(t *testing.T) {
		rc := &ResolverConfig{
			RootNameServersV4: []string{"1.2.3.4:49"},
		}
		err := rc.PopulateAndValidate()
		require.Nil(t, err, "Expected no error for valid root nameserver")
		require.Equal(t, "49", strings.Split(rc.RootNameServersV4[0], ":")[1], "Expected port to be unchanged")
		rc = &ResolverConfig{
			RootNameServersV4: []string{"1.2.3.4"},
		}
		err = rc.PopulateAndValidate()
		require.Nil(t, err, "Expected no error for valid root nameserver")
		require.Equal(t, "53", strings.Split(rc.RootNameServersV4[0], ":")[1], "Expected port to be populated")
	})
}
