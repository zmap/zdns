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
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func populateNetworkingConfig(gc *CLIConf) error {
	// mutually exclusive CLI options
	if gc.LocalIfaceString != "" && gc.LocalAddrString != "" {
		return errors.New("--local-addr and --local-interface cannot both be specified")
	}

	if gc.DNSOverHTTPS && gc.IterativeResolution {
		return errors.New("--https and --iterative cannot both be specified")
	}

	if gc.DNSOverTLS && gc.IterativeResolution {
		return errors.New("--tls and --iterative cannot both be specified")
	}

	if gc.UDPOnly && gc.DNSOverHTTPS {
		return errors.New("--udp-only and --https cannot both be specified")
	}

	if gc.UDPOnly && gc.DNSOverTLS {
		return errors.New("--udp-only and --tls cannot both be specified")
	}

	if gc.DNSOverHTTPS && gc.DNSOverTLS {
		return errors.New("--https and --tls cannot both be specified")
	}

	if err := parseNameServers(gc); err != nil {
		return errors.Wrap(err, "name servers could not be parsed")
	}

	if err := validateClientSubnetString(gc); err != nil {
		return errors.Wrap(err, "client subnet did not pass validation")
	}

	// local address - the user can enter both IPv4 and IPv6 addresses. We'll differentiate them later
	if GC.LocalAddrString != "" {
		for _, la := range strings.Split(GC.LocalAddrString, ",") {
			ip := net.ParseIP(la)
			if ip != nil {
				gc.LocalAddrs = append(gc.LocalAddrs, ip)
			} else {
				return fmt.Errorf("invalid argument for --local-addr (%v). Must be a comma-separated list of valid IP addresses", la)
			}
		}
		gc.LocalAddrSpecified = true
	}

	// local interface - same as local addresses, an interface could have both IPv4 and IPv6 addresses, we'll differentiate them later
	if gc.LocalIfaceString != "" {
		li, err := net.InterfaceByName(gc.LocalIfaceString)
		if err != nil {
			return fmt.Errorf("invalid local interface specified: %v", err)
		}
		addrs, err := li.Addrs()
		if err != nil {
			return fmt.Errorf("unable to detect addresses of local interface: %v", err)
		}
		for _, la := range addrs {
			// strip off the network mask
			ip, _, err := net.ParseCIDR(la.String())
			if err != nil {
				return fmt.Errorf("unable to parse IP address from interface %s: %v", gc.LocalIfaceString, err)
			}
			gc.LocalAddrs = append(gc.LocalAddrs, ip)
			gc.LocalAddrSpecified = true
		}
		log.Info("using local interface: ", gc.LocalIfaceString)
	}

	return nil
}

func validateClientSubnetString(gc *CLIConf) error {
	if gc.ClientSubnetString != "" {
		parts := strings.Split(gc.ClientSubnetString, "/")
		if len(parts) != 2 {
			return fmt.Errorf("client subnet should be in CIDR format: %s", gc.ClientSubnetString)
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			return fmt.Errorf("client subnet invalid: %s", gc.ClientSubnetString)
		}
		netmask, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("client subnet netmask invalid: %s", gc.ClientSubnetString)
		}
		if netmask > 24 || netmask < 8 {
			return fmt.Errorf("client subnet netmask must be in 8..24: %s", gc.ClientSubnetString)
		}
		gc.ClientSubnet = new(dns.EDNS0_SUBNET)
		gc.ClientSubnet.Code = dns.EDNS0SUBNET
		if ip.To4() == nil {
			gc.ClientSubnet.Family = 2
		} else {
			gc.ClientSubnet.Family = 1
		}
		gc.ClientSubnet.SourceNetmask = uint8(netmask)
		gc.ClientSubnet.Address = ip
	}
	return nil
}

func parseNameServers(gc *CLIConf) error {
	if gc.NameServersString != "" {
		if gc.NameServerMode {
			log.Fatal("name servers cannot be specified on command line in --name-server-mode")
		}
		var nses []string
		if (gc.NameServersString)[0] == '@' {
			filepath := (gc.NameServersString)[1:]
			f, err := os.ReadFile(filepath)
			if err != nil {
				log.Fatalf("Unable to read file (%s): %s", filepath, err.Error())
			}
			if len(f) == 0 {
				log.Fatalf("Empty file (%s)", filepath)
			}
			nses = strings.Split(strings.Trim(string(f), "\n"), "\n")
		} else {
			nses = strings.Split(gc.NameServersString, ",")
			trimmedNSes := make([]string, 0, len(nses))
			for _, ns := range nses {
				trimmedNSes = append(trimmedNSes, strings.TrimSpace(ns))
			}
			nses = trimmedNSes
		}
		gc.NameServers = nses
	}
	return nil
}
