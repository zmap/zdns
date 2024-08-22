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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateNetworkingConfig(t *testing.T) {
	t.Run("LocalAddr and LocalInterface both specified", func(t *testing.T) {
		gc := &CLIConf{
			NetworkOptions: NetworkOptions{
				LocalAddrString:   "1.1.1.1",
				LocalIfaceString:  "eth0",
				IPv4TransportOnly: true,
			},
		}
		err := populateNetworkingConfig(gc)
		require.NotNil(t, err, "Expected an error but got nil")
	})
	t.Run("Using invalid interface", func(t *testing.T) {
		gc := &CLIConf{
			NetworkOptions: NetworkOptions{
				LocalIfaceString:  "invalid_interface",
				IPv4TransportOnly: true,
			},
		}
		err := populateNetworkingConfig(gc)
		require.NotNil(t, err, "Expected an error but got nil")
	})
	t.Run("Using nameserver with port", func(t *testing.T) {
		gc := &CLIConf{
			NetworkOptions: NetworkOptions{
				IPv4TransportOnly: true,
			},
			GeneralOptions: GeneralOptions{
				NameServersString: "127.0.0.1:53",
			},
		}
		err := populateNetworkingConfig(gc)
		require.Nil(t, err, "Expected no error but got %v", err)
		require.Equal(t, "127.0.0.1:53", gc.NameServers[0], "Expected user supplied port to not be changed")
	})
}
