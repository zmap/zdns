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
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zmap/dns"
)

func TestSetClientSubnetDoesNotMutateSharedOptions(t *testing.T) {
	original := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IP{198, 51, 100, 0}}
	options := []dns.EDNS0{original, &dns.EDNS0_NSID{Code: dns.EDNS0NSID}}
	first := &Resolver{ednsOptions: options}
	second := &Resolver{ednsOptions: options}
	replacement := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IP{192, 0, 2, 0}}
	first.SetClientSubnet(replacement)
	replacement.Address[0] = 10
	require.Equal(t, options, second.ednsOptions)
	require.Equal(t, "198.51.100.0", original.Address.String())
	subnet, ok := first.ednsOptions[1].(*dns.EDNS0_SUBNET)
	require.True(t, ok)
	require.Equal(t, "192.0.2.0", subnet.Address.String())
	first.SetClientSubnet(nil)
	require.False(t, first.hasClientSubnet())
	require.True(t, second.hasClientSubnet())
	require.Len(t, first.ednsOptions, 1)
	require.Equal(t, uint16(dns.EDNS0NSID), first.ednsOptions[0].Option())
}

func TestClientSubnetBypassesAuthorityCache(t *testing.T) {
	ns, ednsQueries, plainQueries := startEDNSFallbackTestServer(t, "udp", false, 0, 0)
	config := NewResolverConfig()
	config.IPVersionMode = IPv4Only
	config.TransportMode = UDPOnly
	config.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
	config.ExternalNameServersV4, config.RootNameServersV4 = []NameServer{ns}, []NameServer{ns}
	config.NetworkTimeout = time.Second
	referral := &SingleQueryResult{
		Authorities: []any{Answer{Name: "com", Type: "NS", Class: "IN", RrType: dns.TypeNS, RrClass: dns.ClassINET, TTL: 60, Answer: "ns.com"}},
		Additionals: []any{Answer{Name: "ns.com", Type: "A", Class: "IN", RrType: dns.TypeA, RrClass: dns.ClassINET, TTL: 60, Answer: "192.0.2.1"}},
	}
	config.Cache.SafeAddCachedAuthority(referral, nil, 0, ".")
	_, found := config.Cache.GetCachedAuthority("com", nil, 0)
	require.True(t, found)
	resolver, err := InitResolver(config)
	require.NoError(t, err)
	t.Cleanup(resolver.Close)
	q := Question{Name: "example.com", Type: dns.TypeA, Class: dns.ClassINET}
	_, cached, status, _, err := resolver.cachedLookup(context.Background(), q, &ns, ".", 0, false, false, false, nil)
	require.NoError(t, err)
	require.Equal(t, StatusNoError, status)
	require.True(t, bool(cached))

	resolver.SetClientSubnet(&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IP{192, 0, 2, 0}})
	_, cached, status, _, err = resolver.cachedLookup(context.Background(), q, &ns, ".", 0, false, false, false, nil)
	require.NoError(t, err)
	require.False(t, bool(cached))
	require.Equal(t, StatusFormErr, status, "must query the server instead of reusing the plain referral")
	require.Equal(t, int32(1), ednsQueries.Load())
	require.Zero(t, plainQueries.Load(), "must not silently retry an ECS query without EDNS")
}
