package cli

import (
	"github.com/stretchr/testify/require"
	"testing"
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
}
