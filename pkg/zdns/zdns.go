/*
 * ZDNS Copyright 2016 Regents of the University of Michigan
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
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/internal/util"
	"github.com/zmap/zdns/iohandlers"
)

func Run(gc GlobalConf, flags *pflag.FlagSet,
	timeout *int, iterationTimeout *int,
	class_string *string, servers_string *string,
	config_file *string, localaddr_string *string,
	localif_string *string, nanoSeconds *bool, clientsubnet_string *string) {

	factory := GetLookup(gc.Module)

	if factory == nil {
		log.Fatal("Invalid lookup module specified. Valid modules: ", ValidlookupsString())
	}

	factory.SetFlags(flags)

	if gc.LogFilePath != "" {
		f, err := os.OpenFile(gc.LogFilePath, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Fatalf("Unable to open log file (%s): %s", gc.LogFilePath, err.Error())
		}
		log.SetOutput(f)
	}

	// Translate the assigned verbosity level to a logrus log level.
	switch gc.Verbosity {
	case 1: // Fatal
		log.SetLevel(log.FatalLevel)
	case 2: // Error
		log.SetLevel(log.ErrorLevel)
	case 3: // Warnings  (default)
		log.SetLevel(log.WarnLevel)
	case 4: // Information
		log.SetLevel(log.InfoLevel)
	case 5: // Debugging
		log.SetLevel(log.DebugLevel)
	default:
		log.Fatal("Unknown verbosity level specified. Must be between 1 (lowest)--5 (highest)")
	}

	// complete post facto global initialization based on command line arguments
	gc.Timeout = time.Duration(time.Second * time.Duration(*timeout))
	gc.IterationTimeout = time.Duration(time.Second * time.Duration(*iterationTimeout))

	// class initialization
	switch strings.ToUpper(*class_string) {
	case "INET", "IN":
		gc.Class = dns.ClassINET
	case "CSNET", "CS":
		gc.Class = dns.ClassCSNET
	case "CHAOS", "CH":
		gc.Class = dns.ClassCHAOS
	case "HESIOD", "HS":
		gc.Class = dns.ClassHESIOD
	case "NONE":
		gc.Class = dns.ClassNONE
	case "ANY":
		gc.Class = dns.ClassANY
	default:
		log.Fatal("Unknown record class specified. Valid valued are INET (default), CSNET, CHAOS, HESIOD, NONE, ANY")

	}

	if gc.LookupAllNameServers {
		if *servers_string != "" {
			log.Fatal("Name servers cannot be specified in --all-nameservers mode.")
		}
	}

	if *servers_string == "" {
		// if we're doing recursive resolution, figure out default OS name servers
		// otherwise, use the set of 13 root name servers
		if gc.IterativeResolution {
			gc.NameServers = RootServers[:]
		} else {
			ns, err := GetDNSServers(*config_file)
			if err != nil {
				ns = util.GetDefaultResolvers()
				log.Warn("Unable to parse resolvers file. Using ZDNS defaults: ", strings.Join(ns, ", "))
			}
			gc.NameServers = ns
		}
		gc.NameServersSpecified = false
		log.Info("No name servers specified. will use: ", strings.Join(gc.NameServers, ", "))
	} else {
		if gc.NameServerMode {
			log.Fatal("name servers cannot be specified on command line in --name-server-mode")
		}
		var ns []string
		if (*servers_string)[0] == '@' {
			filepath := (*servers_string)[1:]
			f, err := ioutil.ReadFile(filepath)
			if err != nil {
				log.Fatalf("Unable to read file (%s): %s", filepath, err.Error())
			}
			if len(f) == 0 {
				log.Fatalf("Empty file (%s)", filepath)
			}
			ns = strings.Split(strings.Trim(string(f), "\n"), "\n")
		} else {
			ns = strings.Split(*servers_string, ",")
		}
		for i, s := range ns {
			ns[i] = util.AddDefaultPortToDNSServerName(s)
		}
		gc.NameServers = ns
		gc.NameServersSpecified = true
	}

	if *clientsubnet_string != "" {
		parts := strings.Split(*clientsubnet_string, "/")
		if len(parts) != 2 {
			log.Fatalf("Client subnet should be in CIDR format: %s", *clientsubnet_string)
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			log.Fatalf("Client subnet invalid: %s", *clientsubnet_string)
		}
		netmask, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("Client subnet netmask invalid: %s", *clientsubnet_string)
		}
		if netmask > 24 || netmask < 8 {
			log.Fatalf("Client subnet netmask must be in 8..24: %s", *clientsubnet_string)
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

	if *localaddr_string != "" {
		for _, la := range strings.Split(*localaddr_string, ",") {
			ip := net.ParseIP(la)
			if ip != nil {
				gc.LocalAddrs = append(gc.LocalAddrs, ip)
			} else {
				log.Fatal("Invalid argument for --local-addr (", la, "). Must be a comma-separated list of valid IP addresses.")
			}
		}
		log.Info("using local address: ", localaddr_string)
		gc.LocalAddrSpecified = true
	}

	if *localif_string != "" {
		if gc.LocalAddrSpecified {
			log.Fatal("Both --local-addr and --local-interface specified.")
		} else {
			li, err := net.InterfaceByName(*localif_string)
			if err != nil {
				log.Fatal("Invalid local interface specified: ", err)
			}
			addrs, err := li.Addrs()
			if err != nil {
				log.Fatal("Unable to detect addresses of local interface: ", err)
			}
			for _, la := range addrs {
				gc.LocalAddrs = append(gc.LocalAddrs, la.(*net.IPNet).IP)
				gc.LocalAddrSpecified = true
			}
			log.Info("using local interface: ", localif_string)
		}
	}
	if !gc.LocalAddrSpecified {
		// Find local address for use in unbound UDP sockets
		if conn, err := net.Dial("udp", "8.8.8.8:53"); err != nil {
			log.Fatal("Unable to find default IP address: ", err)
		} else {
			gc.LocalAddrs = append(gc.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
			err := conn.Close()
			if err != nil {
				log.Warn("Unable to close test connection to Google Public DNS: ", err)
			}
		}
	}
	if *nanoSeconds {
		gc.TimeFormat = time.RFC3339Nano
	} else {
		gc.TimeFormat = time.RFC3339
	}
	if gc.GoMaxProcs < 0 {
		log.Fatal("Invalid argument for --go-processes. Must be >1.")
	}

	if gc.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(gc.GoMaxProcs)
	}

	// the margin for limit of open files covers different build platforms (linux/darwin), metadata files, or
	// input and output files etc.
	// check ulimit if value is high enough and if not, try to fix it
	ulimitCheck(uint64(gc.Threads + 100))

	if gc.UDPOnly && gc.TCPOnly {
		log.Fatal("TCP Only and UDP Only are conflicting")
	}
	if gc.NameServerMode && gc.AlexaFormat {
		log.Fatal("Alexa mode is incompatible with name server mode")
	}
	if gc.NameServerMode && gc.MetadataFormat {
		log.Fatal("Metadata mode is incompatible with name server mode")
	}
	if gc.NameServerMode && gc.NameOverride == "" && gc.Module != "BINDVERSION" {
		log.Fatal("Static Name must be defined with --override-name in --name-server-mode unless DNS module does not expect names (e.g., BINDVERSION).")
	}
	// Output Groups are defined by a base + any additional fields that the user wants
	groups := strings.Split(gc.IncludeInOutput, ",")
	if gc.ResultVerbosity != "short" && gc.ResultVerbosity != "normal" && gc.ResultVerbosity != "long" && gc.ResultVerbosity != "trace" {
		log.Fatal("Invalid result verbosity. Options: short, normal, long, trace")
	}

	gc.OutputGroups = append(gc.OutputGroups, gc.ResultVerbosity)
	gc.OutputGroups = append(gc.OutputGroups, groups...)

	// Seeding for RandomNameServer()
	rand.Seed(time.Now().UnixNano())

	// some modules require multiple passes over a file (this is really just the case for zone files)
	if !factory.AllowStdIn() && gc.InputFilePath == "-" {
		log.Fatal("Specified module does not allow reading from stdin")
	}

	// setup i/o
	gc.InputHandler = iohandlers.NewFileInputHandler(gc.InputFilePath)
	gc.OutputHandler = iohandlers.NewFileOutputHandler(gc.OutputFilePath)

	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		log.Fatal("Factory was unable to initialize:", err.Error())
	}
	// run it.
	if err := DoLookups(factory, &gc); err != nil {
		log.Fatal("Unable to run lookups:", err.Error())
	}
	// allow the factory to finalize itself
	if err := factory.Finalize(); err != nil {
		log.Fatal("Factory was unable to finalize:", err.Error())
	}
}
