package zdns

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zmap/dns"
)

type testCase struct {
	transportMode         TransportMode
	ipVersion             IPVersionMode
	iterationIPPreference IterationIPPreference
	lookupAllNameservers  bool
	useHTTPS              bool
	useTLS                bool
	recycleSockets        bool
	isExternalLookup      bool
}

func (t *testCase) String() string {
	return fmt.Sprintf("transport=%s/ip=%s/iterationpref=%s/lookupAllNS=%v/https=%v/tls=%v/recycleSocks=%v/externalLookup=%v",
		t.transportMode,t.ipVersion,t.iterationIPPreference,t.lookupAllNameservers,t.useHTTPS,t.useTLS,t.recycleSockets,t.isExternalLookup)
}

// TODO
// Wrapping up for the night, but preliminary testing shows 2 issues
// 1. We're not obeying the timeout in all cases. Yep, definitely some issue wiht the context not preempting
// 2. Almost all errors seem to be when preference is "NoPref"

func TestNetworkConditions(t *testing.T) {
	const timeout = 2 * time.Second
	q := Question{
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		Name:  "example.com",
	}

	// TODO Phillip You have to figure this part out
	hostSupportsIPv4 := hostHasIPv4()
	hostSupportsIPv6 := hostHasIPv6()

	// skipReason returns a non-empty string if this case should be skipped.
	skipReason := func(tc testCase) string {
		if tc.ipVersion == IPv4Only && !hostSupportsIPv4 {
			return "host does not support IPv4"
		}
		if tc.ipVersion == IPv6Only && !hostSupportsIPv6 {
			return "host does not support IPv6"
		}
		// HTTPS and TLS are mutually exclusive
		if tc.useHTTPS && tc.useTLS {
			return "HTTPS and TLS cannot both be enabled"
		}
		// IterationIPPreference only meaningful for dual-stack
		if tc.ipVersion != IPv4OrIPv6 && tc.iterationIPPreference != NoPreference {
			return "IterationIPPreference only relevant in IPv4OrIPv6 mode"
		}
		if tc.transportMode == UDPOnly && (tc.useHTTPS || tc.useTLS) {
			return "UDP transport cannot be used with HTTPS or TLS"
		}
		return ""
	}

	var tests []testCase
	for _, ipv := range []IPVersionMode{IPv4Only, IPv6Only, IPv4OrIPv6} {
		for _, tm := range []TransportMode{UDPOnly, TCPOnly, UDPOrTCP} {
			for _, pref := range []IterationIPPreference{PreferIPv4, PreferIPv6, NoPreference} {
				for _, lan := range []bool{false, true} {
					for _, https := range []bool{false, true} {
						for _, tls := range []bool{false, true} {
							for _, recycle := range []bool{false, true} {
								for _, isExternalLookup := range []bool{false, true} {
									tests = append(tests,
										testCase{
											tm,
											ipv,
											pref,
											lan,
											https,
											tls,
											recycle,
											isExternalLookup})
								}
							}
						}
					}
				}
			}
		}
	}
	numTestsRan := 0
	for _, tc := range tests {
		tc := tc
		t.Run(tc.String(), func(t *testing.T) {
			//t.Parallel()
			if reason := skipReason(tc); reason != "" {
				t.Skip(reason)
			}
			numTestsRan++

			// Create a fresh ResolverConfig per test (no shared cache)
			cfg := NewResolverConfig()
			cfg.IPVersionMode = tc.ipVersion
			cfg.TransportMode = tc.transportMode
			cfg.IterationIPPreference = tc.iterationIPPreference
			cfg.LookupAllNameServers = tc.lookupAllNameservers
			cfg.DNSOverHTTPS = tc.useHTTPS
			cfg.DNSOverTLS = tc.useTLS
			cfg.ShouldRecycleSockets = tc.recycleSockets
			var err error
			if err = cfg.Validate(); err != nil {
				t.Fatalf("could not validate config: %v", err)
			}
			var resolver *Resolver
			resolver, err = InitResolver(cfg)
			if err != nil {
				t.Fatalf("could not initialize resolver: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			var result *SingleQueryResult
			var status Status
			if tc.isExternalLookup {
				result, _, status, err = resolver.ExternalLookup(ctx, &q, nil)
			} else {
				result, _, status, err = resolver.IterativeLookup(ctx, &q)
			}
			if err != nil {
				t.Fatalf("could not perform lookup: %v", err)
			}
			if status != StatusNoError {
				t.Fatalf("lookup returned status %v; want %v", status, StatusNoError)
			}
			if result == nil {
				t.Fatal("result is nil")
			}
			// TODO actually validate the answer, if possible
		})
	}
}

func hostHasIPv4() bool {
	listener, err := net.Listen("tcp4", ":0")
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

func hostHasIPv6() bool {
	listener, err := net.Listen("tcp6", ":0")
	if err != nil {
		return false
	}
	listener.Close()
	return true
}
