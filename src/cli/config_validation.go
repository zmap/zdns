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
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/internal/util"
	"github.com/zmap/zdns/src/zdns"
)

const (
	// TODO - we'll need to update this when we add IPv6 support
	loopbackAddrString = "127.0.0.1"
)

func validateNetworkingConfig(gc *CLIConf) error {
	// mutually exclusive CLI options
	if gc.LocalIfaceString != "" && gc.LocalAddrString != "" {
		return errors.New("--local-addr and --local-interface cannot both be specified")
	}

	// Note: we rely on the value of gc.UsingLoopbackNameServer set here, so this must be called first before other validation
	if err := validateNameServers(gc); err != nil {
		return errors.Wrap(err, "name servers did not pass validation")
	}

	if err := validateClientSubnetString(gc); err != nil {
		return errors.Wrap(err, "client subnet did not pass validation")
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
		li, err := net.InterfaceByName(gc.LocalIfaceString)
		if err != nil {
			return fmt.Errorf("invalid local interface specified: %v", err)
		}
		// net.FlagLoopback is a bitmask, so we need to check if the loopback flag is set
		ifaceLoopbackFlag := li.Flags & net.FlagLoopback
		isIfaceLoopback := ifaceLoopbackFlag != 0
		// if we're using the loopback nameserver, make sure we're using the loopback interface
		// Vice-versa for a non-loopback nameserver
		if isIfaceLoopback != gc.UsingLoopbackNameServer {
			return fmt.Errorf("cannot mix loopback/non-loopback nameservers (%v) and interface (%s)", gc.NameServers, gc.LocalIfaceString)
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
			if ip.To4() == nil {
				// skip IPv6 addresses
				// TODO - we'll need to update this when we add IPv6 support
				log.Infof("interface %s has IPv6 address %s, skipping since unsupported", gc.LocalIfaceString, ip.String())
				continue
			}
			gc.LocalAddrs = append(gc.LocalAddrs, ip)
			gc.LocalAddrSpecified = true
		}
		log.Info("using local interface: ", gc.LocalIfaceString)
	}

	if gc.UsingLoopbackNameServer && !gc.LocalAddrSpecified {
		// set local addr as loopback if we're using the loopback name server
		gc.LocalAddrs = []net.IP{net.ParseIP(loopbackAddrString)}
		gc.LocalAddrSpecified = true
	}

	if !gc.LocalAddrSpecified {
		// Find non-loopback local address for use in any socket connections
		conn, err := net.Dial("udp", "8.8.8.8:53")
		if err != nil {
			return fmt.Errorf("unable to find default IP address: %v", err)
		}
		gc.LocalAddrs = append(gc.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
		err = conn.Close()
		if err != nil {
			log.Warn("unable to close test connection to Google Public DNS: ", err)
		}
	}
	log.Infof("using local address(es): %v", gc.LocalAddrs)
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

func validateNameServers(gc *CLIConf) error {
	if gc.LookupAllNameServers && gc.NameServersString != "" {
		log.Fatal("name servers cannot be specified in --all-nameservers mode.")
	}

	if gc.NameServersString == "" {
		// if we're doing recursive resolution, figure out default OS name servers
		// otherwise, use the set of 13 root name servers
		if gc.IterativeResolution {
			gc.NameServers = zdns.RootServers[:]
		} else {
			ns, err := zdns.GetDNSServers(gc.ConfigFilePath)
			if err != nil {
				ns = util.GetDefaultResolvers()
				log.Warn("Unable to parse resolvers file. Using ZDNS defaults: ", strings.Join(ns, ", "))
			}
			gc.NameServers = ns
		}
		log.Info("No name servers specified. will use: ", strings.Join(gc.NameServers, ", "))
	} else {
		if gc.NameServerMode {
			log.Fatal("name servers cannot be specified on command line in --name-server-mode")
		}
		var ns []string
		if (gc.NameServersString)[0] == '@' {
			filepath := (gc.NameServersString)[1:]
			f, err := os.ReadFile(filepath)
			if err != nil {
				log.Fatalf("Unable to read file (%s): %s", filepath, err.Error())
			}
			if len(f) == 0 {
				log.Fatalf("Empty file (%s)", filepath)
			}
			ns = strings.Split(strings.Trim(string(f), "\n"), "\n")
		} else {
			ns = strings.Split(gc.NameServersString, ",")
		}
		for i, s := range ns {
			nsWithPort, err := util.AddDefaultPortToDNSServerName(s)
			if err != nil {
				log.Fatalf("unable to parse name server: %s", s)
			}
			ns[i] = nsWithPort
		}
		if len(ns) == 0 {
			return fmt.Errorf("no valid name servers specified: %v", ns)
		}
		gc.NameServers = ns
	}

	// Potentially, a name-server could be listed multiple times by either the user or in the OS's respective /etc/resolv.conf
	// De-dupe
	gc.NameServers = util.RemoveDuplicates(gc.NameServers)

	// Check if any of the name servers are in the loopback subnet
	gc.UsingLoopbackNameServer = false
	numberOfLoopbackNameServers := 0
	for _, ns := range gc.NameServers {
		ip, err := netip.ParseAddr(strings.Split(ns, ":")[0])
		if err != nil {
			return errors.Wrapf(err, "could not parse nameserver: %s", ns)
		}
		if ip.IsLoopback() {
			gc.UsingLoopbackNameServer = true
			numberOfLoopbackNameServers++
		}
	}

	if gc.UsingLoopbackNameServer && len(gc.NameServers) > numberOfLoopbackNameServers {
		return fmt.Errorf("cannot use a loopback nameserver with non-loopback nameservers (%v). Please specify with --name-servers one or the other", gc.NameServers)
	}
	return nil
}
