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
	"fmt"
	"net"

	"github.com/zmap/zdns/src/internal/util"
)

const (
	DoHProtocol = "DoH"
	DoTProtocol = "DoT"
	UDPProtocol = "udp"
	TCPProtocol = "tcp"
)

type transportMode int

const (
	UDPOrTCP transportMode = iota
	UDPOnly
	TCPOnly
)

const (
	DefaultDNSPort = 53
	DefaultDoHPort = 443
	DefaultDoTPort = 853
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

type IterationIPPreference int

const (
	PreferIPv4 IterationIPPreference = iota
	PreferIPv6
)

func GetIterationIPPreference(preferIPv4, preferIPv6 bool) IterationIPPreference {
	if preferIPv4 {
		return PreferIPv4
	} else if preferIPv6 {
		return PreferIPv6
	}
	return PreferIPv4
}

func (iip IterationIPPreference) IsValid() (bool, string) {
	isValid := iip >= 0 && iip <= 1
	if !isValid {
		return false, fmt.Sprintf("invalid iteration ip preference: %d", iip)
	}
	return true, ""
}

type NameServer struct {
	IP         net.IP // ip address, required
	Port       uint16 // udp/tcp port
	DomainName string // used for SNI with TLS, required if you want to validate server certs
}

func (ns *NameServer) String() string {
	if ns == nil || ns.IP == nil {
		return ""
	}
	if ns.IP.To4() != nil {
		return fmt.Sprintf("%s:%d", ns.IP.String(), ns.Port)
	} else if util.IsIPv6(&ns.IP) {
		return fmt.Sprintf("[%s]:%d", ns.IP.String(), ns.Port)
	}
	return ""
}

func (ns *NameServer) PopulateDefaultPort(usingDoT, usingDoH bool) {
	if ns.Port != 0 {
		return
	} else if usingDoT {
		ns.Port = DefaultDoTPort
	} else if usingDoH {
		ns.Port = DefaultDoHPort
	} else {
		ns.Port = DefaultDNSPort
	}
}

func (ns *NameServer) IsValid() (bool, string) {
	if ns.IP == nil {
		return false, "missing IP address"
	}
	if ns.IP != nil && ns.IP.To4() == nil && ns.IP.To16() == nil {
		return false, "invalid IP address"
	}
	if ns.Port == 0 {
		return false, "missing port"
	}
	return true, ""
}

func (ns *NameServer) DeepCopy() *NameServer {
	if ns == nil {
		return nil
	}
	ip := make(net.IP, len(ns.IP))
	copy(ip, ns.IP)
	return &NameServer{
		IP:         ip,
		Port:       ns.Port,
		DomainName: ns.DomainName,
	}
}
