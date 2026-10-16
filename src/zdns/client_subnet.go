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
	"slices"

	"github.com/zmap/dns"
)

// SetClientSubnet replaces the EDNS Client Subnet option for subsequent lookups.
// A nil subnet removes ECS. Other EDNS options and reusable connections are preserved.
// Like lookups, this method must not be called concurrently on the same Resolver.
// ECS queries bypass the cache, whose keys do not distinguish client subnets.
func (r *Resolver) SetClientSubnet(subnet *dns.EDNS0_SUBNET) {
	options := make([]dns.EDNS0, 0, len(r.ednsOptions)+1)
	for _, option := range r.ednsOptions {
		if option.Option() != dns.EDNS0SUBNET {
			options = append(options, option)
		}
	}
	if subnet != nil {
		// Resolver configs (including their option slices) can be shared by workers.
		// Keep both the replacement option and its address private to this resolver.
		cloned := *subnet
		cloned.Address = slices.Clone(subnet.Address)
		options = append(options, &cloned)
	}
	r.ednsOptions = options
}

func (r *Resolver) hasClientSubnet() bool {
	for _, option := range r.ednsOptions {
		if option.Option() == dns.EDNS0SUBNET {
			return true
		}
	}
	return false
}
