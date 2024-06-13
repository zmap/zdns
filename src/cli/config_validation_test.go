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
package cli

import (
	"net"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/require"
)

func TestValidateNetworkingConfig(t *testing.T) {
	t.Run("LocalAddr and LocalInterface both specified", func(t *testing.T) {
		gc := &CLIConf{
			LocalAddrString:  "1.1.1.1",
			LocalIfaceString: "eth0",
		}
		err := validateNetworkingConfig(gc)
		require.NotNil(t, err, "Expected an error but got nil")
	})
	t.Run("Using invalid interface", func(t *testing.T) {
		gc := &CLIConf{
			LocalIfaceString: "invalid_interface",
		}
		err := validateNetworkingConfig(gc)
		require.NotNil(t, err, "Expected an error but got nil")
	})

	t.Run("Using loopback nameserver and no specified local address", func(t *testing.T) {
		gc := &CLIConf{
			NameServersString: "127.0.0.53",
		}
		err := validateNetworkingConfig(gc)
		require.Nil(t, err, "Expected no error but got %v", err)
		require.Equal(t, loopbackAddrString, gc.LocalAddrs[0].String())
		require.True(t, gc.UsingLoopbackNameServer, "Expected UsingLoopbackNameServer to be true")
	})
	t.Run("Using nameserver with no port", func(t *testing.T) {
		gc := &CLIConf{
			NameServersString: "1.1.1.1",
		}
		err := validateNetworkingConfig(gc)
		require.Nil(t, err, "Expected no error but got %v", err)
		require.Equal(t, "1.1.1.1:53", gc.NameServers[0], "Expected port 53 to be appended to nameserver")
		require.False(t, gc.UsingLoopbackNameServer, "Expected UsingLoopbackNameServer to be false")
	})
	t.Run("Using nameserver with port", func(t *testing.T) {
		gc := &CLIConf{
			NameServersString: "127.0.0.1:5353",
		}
		err := validateNetworkingConfig(gc)
		require.Nil(t, err, "Expected no error but got %v", err)
		require.Equal(t, "127.0.0.1:5353", gc.NameServers[0], "Expected user supplied port to not be changed")
	})
	t.Run("Using a loopback and non-loopback nameserver", func(t *testing.T) {
		gc := &CLIConf{
			NameServersString: "127.0.0.53,1.1.1.1",
		}
		err := validateNetworkingConfig(gc)
		require.NotNil(t, err, "Expected an error but got nil")
	})
	t.Run("Loopback interface and nameserver mismatch", func(t *testing.T) {
		// get both a loopback and non-loopback interface
		ifaces, err := net.Interfaces()
		require.Nil(t, err, "Expected no error but got %v", err)
		var nonLoopbackIface string
		var loopbackIface string
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback == 0 {
				nonLoopbackIface = iface.Name
			} else {
				loopbackIface = iface.Name
			}
		}
		log.Infof("using non-loopback interface: %s", nonLoopbackIface)
		log.Infof("using loopback interface: %s", loopbackIface)
		t.Run("loopback interface with non-loopback nameserver", func(t *testing.T) {
			gc := &CLIConf{
				NameServersString: "1.1.1.1",
				LocalIfaceString:  loopbackIface,
			}
			err = validateNetworkingConfig(gc)
			require.NotNil(t, err, "Expected an error but got nil")
		})
		t.Run("non-loopback interface with loopback nameserver", func(t *testing.T) {
			gc := &CLIConf{
				NameServersString: "127.0.0.1",
				LocalIfaceString:  nonLoopbackIface,
			}
			err = validateNetworkingConfig(gc)
			require.NotNil(t, err, "Expected an error but got nil")
		})
		t.Run("loopback interface with loopback nameserver", func(t *testing.T) {
			gc := &CLIConf{
				NameServersString: "127.0.0.53",
				LocalIfaceString:  loopbackIface,
			}
			err = validateNetworkingConfig(gc)
			require.Nil(t, err, "Expected no error but got %v", err)
		})
		t.Run("non-loopback interface with non-loopback nameserver", func(t *testing.T) {
			gc := &CLIConf{
				NameServersString: "1.1.1.1",
				LocalIfaceString:  nonLoopbackIface,
			}
			err = validateNetworkingConfig(gc)
			require.Nil(t, err, "Expected no error but got %v", err)
		})
	})
}
