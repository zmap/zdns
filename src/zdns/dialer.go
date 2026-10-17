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
	"strings"
	"time"

	"github.com/zmap/dns"
)

// Dialer opens the network connections a Resolver uses to talk to name servers. It exists so tests can substitute a
// fake network and assert on connection behavior, e.g. that a TCP session is re-used instead of re-handshaking.
// Set ResolverConfig.Dialer to override; the default dials over the real network.
//
// network is the net.Dial network ("udp" or "tcp"), localAddr is the local IP to bind to, and address is the
// name server's "ip:port".
type Dialer interface {
	DialContext(ctx context.Context, network string, localAddr net.IP, address string) (net.Conn, error)
}

// netDialer is the default Dialer, it dials over the real network, binding to localAddr.
type netDialer struct {
	timeout time.Duration
}

func (d netDialer) DialContext(ctx context.Context, network string, localAddr net.IP, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout}
	if strings.HasPrefix(network, "udp") {
		dialer.LocalAddr = &net.UDPAddr{IP: localAddr}
	} else {
		dialer.LocalAddr = &net.TCPAddr{IP: localAddr}
	}
	return dialer.DialContext(ctx, network, address)
}

// exchangeWithNewConn dials a fresh connection to the name server through the connInfo's Dialer, performs a single
// exchange over it and closes it. Equivalent to dns.Client.ExchangeContext, but dialing via the injectable Dialer.
func exchangeWithNewConn(ctx context.Context, connInfo *ConnectionInfo, client *dns.Client, network string, m *dns.Msg, nameServer *NameServer) (*dns.Msg, error) {
	netConn, err := connInfo.dialer.DialContext(ctx, network, connInfo.localAddr, nameServer.String())
	if err != nil {
		// don't wrap, callers type-assert the error to net.Error to detect timeouts
		return nil, err
	}
	conn := &dns.Conn{Conn: netConn, UDPSize: client.UDPSize}
	defer conn.Close()
	r, _, err := client.ExchangeWithConnContext(ctx, m, conn)
	return r, err
}
