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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/v2/src/zdns"
)

func TestParseClientSubnet(t *testing.T) {
	for _, tc := range []struct {
		input, address string
		family         uint16
		prefix         uint8
	}{
		{"192.0.2.129/24", "192.0.2.0", 1, 24},
		{"192.0.2.1/0", "0.0.0.0", 1, 0},
		{"192.0.2.1/32", "192.0.2.1", 1, 32},
		{"2001:db8:1234:abcd::1/48", "2001:db8:1234::", 2, 48},
		{"2001:db8::1/0", "::", 2, 0},
		{"2001:db8::1/128", "2001:db8::1", 2, 128},
		{"::ffff:192.0.2.129/120", "192.0.2.0", 2, 120},
	} {
		t.Run(tc.input, func(t *testing.T) {
			gc := &CLIConf{QueryOptions: QueryOptions{ClientSubnetString: tc.input}}
			require.NoError(t, validateClientSubnetString(gc))
			subnet := gc.ClientSubnet
			require.NotNil(t, subnet)
			assert.Equal(t, tc.family, subnet.Family)
			assert.Equal(t, tc.prefix, subnet.SourceNetmask)
			assert.Equal(t, tc.address, subnet.Address.String())
			assert.Equal(t, uint8(0), subnet.SourceScope)
			assert.Equal(t, uint16(dns.EDNS0SUBNET), subnet.Code)
			roundTrip, err := parseClientSubnet(clientSubnetCIDR(subnet))
			require.NoError(t, err)
			assert.Equal(t, subnet, roundTrip)
		})
	}
	for _, input := range []string{"192.0.2.1", "192.0.2.1/33", "2001:db8::/129", "192.0.2.1/-1", "example.com/24", "192.0.2.1/abc"} {
		_, err := parseClientSubnet(input)
		require.Error(t, err, input)
	}
	subnet, err := parseClientSubnet("")
	require.NoError(t, err)
	require.Nil(t, subnet)
}

func TestParseClientSubnetInputLine(t *testing.T) {
	_, _, _, _, err := parseClientSubnetInputLine(` "example.com" , 2001:db8::1/48 , 127.0.0.1:5300 , a , b `)
	// CSV quotes must start at the beginning of a field.
	require.Error(t, err)
	name, subnet, ns, triggers, err := parseClientSubnetInputLine(`"example.com", 2001:db8::1/48 , 127.0.0.1:5300 , a , b `)
	require.NoError(t, err)
	assert.Equal(t, "example.com", name)
	assert.Equal(t, "2001:db8::", subnet.Address.String())
	assert.Equal(t, "127.0.0.1:5300", ns)
	assert.Equal(t, []string{"a", "b"}, triggers)

	name, subnet, _, _, err = parseClientSubnetInputLine("example.com,")
	require.NoError(t, err)
	assert.Equal(t, "example.com", name)
	assert.Nil(t, subnet)

	for _, line := range []string{"", "example.com", `"example.com,192.0.2.0/24`, "example.com,invalid"} {
		_, _, _, _, err = parseClientSubnetInputLine(line)
		require.Error(t, err, line)
	}
	// The new mode must not reinterpret normal CSV's nameserver and trigger columns.
	name, ns, triggers = parseNormalInputLine("example.com,127.0.0.1,a")
	assert.Equal(t, "example.com", name)
	assert.Equal(t, "127.0.0.1", ns)
	assert.Equal(t, []string{"a"}, triggers)
}

func TestClientSubnetInputConflicts(t *testing.T) {
	for _, tc := range []struct {
		name           string
		options        InputOutputOptions
		nameServerMode bool
	}{
		{"alexa", InputOutputOptions{AlexaFormat: true}, false},
		{"metadata", InputOutputOptions{MetadataFormat: true}, false},
		{"zone file", InputOutputOptions{ZoneFileFormat: true}, false},
		{"nameserver mode", InputOutputOptions{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gc := &CLIConf{InputOutputOptions: tc.options}
			gc.NameServerMode = tc.nameServerMode
			gc.ClientSubnetInput = true
			require.ErrorContains(t, populateNetworkingConfig(gc), "--client-subnet-input")
		})
	}
}

// This exercises actual DNS packets, worker reuse, shared-cache isolation and JSON
// output against a local server. Its answers deliberately depend on the ECS option.
func TestPerInputClientSubnet(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			var queries atomic.Int32
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
				queries.Add(1)
				answer := "203.0.113.1"
				var subnetCount, nsidCount int
				if opt := req.IsEdns0(); opt != nil {
					for _, option := range opt.Option {
						switch option := option.(type) {
						case *dns.EDNS0_SUBNET:
							subnetCount++
							assert.Zero(t, option.SourceScope)
							switch option.Address.String() {
							case "192.0.2.0":
								assert.Equal(t, uint8(24), option.SourceNetmask)
								answer = "203.0.113.2"
							case "2001:db8::":
								assert.Equal(t, uint8(48), option.SourceNetmask)
								answer = "203.0.113.3"
							case "198.51.100.0":
								answer = "203.0.113.4"
							default:
								t.Errorf("unexpected wire subnet: %s", option.Address)
							}
						case *dns.EDNS0_NSID:
							nsidCount++
						}
					}
				}
				assert.LessOrEqual(t, subnetCount, 1)
				assert.Equal(t, 1, nsidCount, "updating ECS must preserve NSID")
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Authoritative = true
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(answer),
				}}
				assert.NoError(t, w.WriteMsg(resp))
			})
			server := &dns.Server{Net: network, Handler: handler}
			var addr net.Addr
			if network == "udp" {
				conn, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				server.PacketConn, addr = conn, conn.LocalAddr()
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				server.Listener, addr = listener, listener.Addr()
			}
			ready := make(chan struct{})
			server.NotifyStartedFunc = func() { close(ready) }
			go func() { assert.NoError(t, server.ActivateAndServe()) }()
			<-ready
			t.Cleanup(func() { require.NoError(t, server.Shutdown()) })
			nses, err := convertNameServerStringToNameServer(addr.String(), zdns.IPv4Only, false, false)
			require.NoError(t, err)

			rc := zdns.NewResolverConfig()
			rc.IPVersionMode = zdns.IPv4Only
			rc.NetworkTimeout = time.Second
			rc.Timeout = 2 * time.Second
			rc.Retries = 0
			rc.LocalAddrsV4 = []net.IP{net.ParseIP("127.0.0.1")}
			rc.RootNameServersV4, rc.ExternalNameServersV4 = nses, nses
			rc.EdnsOptions = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}}
			if network == "tcp" {
				rc.TransportMode = zdns.TCPOnly
			} else {
				rc.TransportMode = zdns.UDPOnly
			}
			resolver, err := zdns.InitResolver(rc)
			require.NoError(t, err)
			t.Cleanup(resolver.Close)
			gc := &CLIConf{
				InputOutputOptions: InputOutputOptions{ClientSubnetInput: true, QuietStatusUpdates: true},
				OutputGroups:       []string{"normal"},
				TimeFormat:         time.RFC3339,
				Class:              dns.ClassINET,
				ActiveModules:      map[string]LookupModule{"A": &BasicLookupModule{DNSType: dns.TypeA, DNSClass: dns.ClassINET, Trigger: "a"}},
			}
			metadata := &routineMetadata{Status: make(map[zdns.Status]int)}
			output := make(chan string, 1)
			check := func(line, expectedSubnet, expectedAnswer, expectedStatus string) {
				t.Helper()
				handleWorkerInput(context.Background(), gc, rc, line, resolver, metadata, output, nil)
				var result struct {
					ClientSubnet string `json:"client_subnet"`
					Results      map[string]struct {
						Status string `json:"status"`
						Data   struct {
							Answers []struct {
								Answer string `json:"answer"`
							} `json:"answers"`
						} `json:"data"`
					} `json:"results"`
				}
				require.NoError(t, json.Unmarshal([]byte(<-output), &result))
				require.Equal(t, expectedStatus, result.Results["A"].Status, line)
				assert.Equal(t, expectedSubnet, result.ClientSubnet, line)
				if expectedAnswer != "" {
					require.Len(t, result.Results["A"].Data.Answers, 1)
					assert.Equal(t, expectedAnswer, result.Results["A"].Data.Answers[0].Answer, line)
				}
			}
			check("example.com,", "", "203.0.113.1", "NOERROR") // seed the plain cache
			check("example.com,192.0.2.129/24", "192.0.2.0/24", "203.0.113.2", "NOERROR")
			check("example.com,invalid", "", "", "ILLEGAL_INPUT")
			check(fmt.Sprintf("example.com,2001:db8::1/48,%s,a", addr), "2001:db8::/48", "203.0.113.3", "NOERROR")
			check("example.com,", "", "203.0.113.1", "NOERROR") // must reuse only the plain result
			assert.Equal(t, int32(3), queries.Load())

			check("other.example,192.0.2.1/24", "192.0.2.0/24", "203.0.113.2", "NOERROR")
			check("other.example,", "", "203.0.113.1", "NOERROR") // ECS must not populate the plain cache
			assert.Equal(t, int32(5), queries.Load())
			gc.ClientSubnet, err = parseClientSubnet("198.51.100.1/24")
			require.NoError(t, err)
			check("example.com,", "198.51.100.0/24", "203.0.113.4", "NOERROR")
			check("example.com,192.0.2.1/24", "192.0.2.0/24", "203.0.113.2", "NOERROR")
			check("example.com,", "198.51.100.0/24", "203.0.113.4", "NOERROR") // restore global default
			gc.NameOverride = "example.com"
			check(",2001:db8::/48", "2001:db8::/48", "203.0.113.3", "NOERROR")
			assert.Equal(t, int32(9), queries.Load())
		})
	}
}
