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
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/zmap/dns"
)

// parseClientSubnet accepts IPv4 and IPv6 CIDRs, including /0, and clears host bits.
func parseClientSubnet(value string) (*dns.EDNS0_SUBNET, error) {
	if value == "" {
		return nil, nil
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("invalid client subnet %q: %w", value, err)
	}
	prefix, bits := network.Mask.Size()
	family := uint16(1)
	if bits == 128 {
		family = 2
	}
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(prefix),
		Address:       network.IP,
	}, nil
}

func clientSubnetCIDR(subnet *dns.EDNS0_SUBNET) string {
	address, _ := netip.AddrFromSlice(subnet.Address)
	if subnet.Family == 1 {
		address = address.Unmap()
	}
	return netip.PrefixFrom(address, int(subnet.SourceNetmask)).String()
}

// parseClientSubnetInputLine is opt-in so existing CSV fields keep their meaning.
func parseClientSubnetInputLine(line string) (name string, subnet *dns.EDNS0_SUBNET, nameserver string, triggers []string, err error) {
	fields, err := csv.NewReader(strings.NewReader(line)).Read()
	if err != nil {
		return line, nil, "", nil, fmt.Errorf("invalid client subnet input: %w", err)
	}
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) < 2 {
		return fields[0], nil, "", nil, errors.New("client subnet input must be name,subnet[,nameserver[,trigger...]]")
	}
	subnet, err = parseClientSubnet(fields[1])
	if err != nil {
		return fields[0], nil, "", nil, err
	}
	if len(fields) > 2 {
		nameserver = fields[2]
	}
	if len(fields) > 3 {
		triggers = fields[3:]
	}
	return fields[0], subnet, nameserver, triggers, nil
}
