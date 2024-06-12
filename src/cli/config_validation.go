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
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"net"
	"strconv"
	"strings"
)

const (
	loopbackAddrString = "127.0.0.1"
)

func validateNetworkingConfig(gc *CLIConf) error {
	if err := validateClientSubnetString(gc); err != nil {
		return errors.Wrap(err, "could not validate client subnet")
	}

	if GC.LocalAddrString != "" {
		for _, la := range strings.Split(GC.LocalAddrString, ",") {
			ip := net.ParseIP(la)
			if ip != nil {
				gc.LocalAddrs = append(gc.LocalAddrs, ip)
			} else {
				return fmt.Errorf("invalid argument for --local-addr (%v). Must be a comma-separated list of valid IP addresses", la)
			}
		}
		log.Info("using local address: ", GC.LocalAddrString)
		gc.LocalAddrSpecified = true
	}

	if gc.LocalIfaceString != "" {
		if gc.LocalAddrSpecified {
			return errors.New("both --local-addr and --local-interface specified.")
		} else {
			li, err := net.InterfaceByName(gc.LocalIfaceString)
			if err != nil {
				return fmt.Errorf("invalid local interface specified: %v", err)
			}
			addrs, err := li.Addrs()
			if err != nil {
				return fmt.Errorf("unable to detect addresses of local interface: %v", err)
			}
			for _, la := range addrs {
				gc.LocalAddrs = append(gc.LocalAddrs, la.(*net.IPNet).IP)
				gc.LocalAddrSpecified = true
			}
			log.Info("using local interface: ", gc.LocalIfaceString)
		}
	}

	if !gc.LocalAddrSpecified {
		// Find local address for use in unbound UDP sockets
		if conn, err := net.Dial("udp", "8.8.8.8:53"); err != nil {
			return fmt.Errorf("unable to find default IP address: %v", err)
		} else {
			gc.LocalAddrs = append(gc.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
			err := conn.Close()
			if err != nil {
				log.Warn("unable to close test connection to Google Public DNS: ", err)
			}
		}
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

/*
	// Check for using a localhost resolver, since we must use a localhost IP when sending on the loopback interface
	usingLoopbackNameServer := util.Contains[string](gc.NameServers, loopbackAddrString)

	localAddrIsLoopback := util.Contains[string](gc.l)

	if gc.LocalAddrSpecified && usingLoopbackNameServer && !localAddrIsLoopback {
		return fmt.Errorf("must use")
	}
	if !gc.LocalAddrSpecified && usingLoopbackNameServer {
		loopbackAddr := net.ParseIP(loopbackAddrString)
		gc.LocalAddrs = []net.IP{loopbackAddr}
		gc.LocalAddrSpecified = true
		if nonLoopbackNameServers > 0 {
			log.Warn("using the loopback address to resolve along with a non-loopback address is not recommended")
		}
	}

*/
