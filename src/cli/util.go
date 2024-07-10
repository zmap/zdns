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
	"fmt"
	"github.com/pkg/errors"
	"net/netip"
)

const (
	// TODO - we'll need to update this when we add IPv6 support
	loopbackAddrSubnet = "127.0.0.0/8"
)

// is_address_loopback checks if an address is a loopback address
func is_address_loopback(addr string) (bool, error) {
	network, err := netip.ParsePrefix(loopbackAddrSubnet)
	if err != nil {
		return false, errors.New("could not parse loopback subnet")
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false, fmt.Errorf("could not parse address: %s", addr)
	}
	addrInLoopback := network.Contains(ip)
	return addrInLoopback, nil
}
