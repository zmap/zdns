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

import "fmt"

type transportMode int

const (
	UDPOrTCP transportMode = iota
	UDPOnly
	TCPOnly
)

func GetTransportMode(useUDP, useTCP bool) transportMode {
	if useUDP && useTCP {
		return UDPOrTCP
	} else if useUDP {
		return UDPOnly
	} else if useTCP {
		return TCPOnly
	}
	return UDPOrTCP
}

func (tm transportMode) isValid() (bool, string) {
	isValid := tm >= 0 && tm <= 2
	if !isValid {
		return false, fmt.Sprintf("invalid transport mode: %d", tm)
	}
	return true, ""
}

type IPVersionMode int

const (
	IPv4Only IPVersionMode = iota
	IPv6Only
	IPv4OrIPv6
)

func GetIPVersionMode(ipv4, ipv6 bool) IPVersionMode {
	if ipv4 && ipv6 {
		return IPv4OrIPv6
	} else if ipv4 {
		return IPv4Only
	} else if ipv6 {
		return IPv6Only
	}
	return IPv4Only
}

func (ivm IPVersionMode) IsValid() (bool, string) {
	isValid := ivm >= 0 && ivm <= 2
	if !isValid {
		return false, fmt.Sprintf("invalid ip version mode: %d", ivm)
	}
	return true, ""
}
