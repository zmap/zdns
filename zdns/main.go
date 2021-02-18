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

package main

import (
	"flag"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zdns"
	_ "github.com/zmap/zdns/modules/alookup"
	_ "github.com/zmap/zdns/modules/axfr"
	_ "github.com/zmap/zdns/modules/bindversion"
	_ "github.com/zmap/zdns/modules/dmarc"
	_ "github.com/zmap/zdns/modules/miekg"
	_ "github.com/zmap/zdns/modules/mxlookup"
	_ "github.com/zmap/zdns/modules/nslookup"
	_ "github.com/zmap/zdns/modules/spf"

	"github.com/zmap/zdns/iohandlers"
)

func main() {

	var gc zdns.GlobalConf

	// global flags relevant to every lookup module
	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	flags.IntVar(&gc.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	flags.StringVar(&gc.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	flags.StringVar(&gc.NameOverride, "override-name", "", "name overrides all passed in names")
	flags.BoolVar(&gc.AlexaFormat, "alexa", false, "is input file from Alexa Top Million download")
	flags.BoolVar(&gc.MetadataFormat, "metadata-passthrough", false, "if input records have the form 'name,METADATA', METADATA will be propagated to the output")
	flags.BoolVar(&gc.IterativeResolution, "iterative", false, "Perform own iteration instead of relying on recursive resolver")
	flags.StringVar(&gc.InputFilePath, "input-file", "-", "names to read")
	flags.StringVar(&gc.OutputFilePath, "output-file", "-", "where should JSON output be saved")
	flags.StringVar(&gc.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	flags.StringVar(&gc.LogFilePath, "log-file", "", "where should JSON logs be saved")

	flags.StringVar(&gc.ResultVerbosity, "result-verbosity", "normal", "Sets verbosity of each output record. Options: short, normal, long, trace")
	flags.StringVar(&gc.IncludeInOutput, "include-fields", "", "Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags")

	flags.IntVar(&gc.Verbosity, "verbosity", 3, "log verbosity: 1 (lowest)--5 (highest)")
	flags.IntVar(&gc.Retries, "retries", 1, "how many times should zdns retry query if timeout or temporary failure")
	flags.IntVar(&gc.MaxDepth, "max-depth", 10, "how deep should we recurse when performing iterative lookups")
	flags.IntVar(&gc.CacheSize, "cache-size", 10000, "how many items can be stored in internal recursive cache")
	flags.BoolVar(&gc.TCPOnly, "tcp-only", false, "Only perform lookups over TCP")
	flags.BoolVar(&gc.UDPOnly, "udp-only", false, "Only perform lookups over UDP")
	flags.BoolVar(&gc.NameServerMode, "name-server-mode", false, "Treats input as nameservers to query with a static query rather than queries to send to a static name server")
	servers_string := flags.String("name-servers", "", "List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53.")
	localaddr_string := flags.String("local-addr", "", "comma-delimited list of local addresses to use")
	localif_string := flags.String("local-interface", "", "local interface to use")
	config_file := flags.String("conf-file", "/etc/resolv.conf", "config file for DNS servers")
	timeout := flags.Int("timeout", 15, "timeout for resolving an individual name")
	iterationTimeout := flags.Int("iteration-timeout", 4, "timeout for resolving a single iteration in an iterative query")
	class_string := flags.String("class", "INET", "DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY. Default: INET.")
	nanoSeconds := flags.Bool("nanoseconds", false, "Use nanosecond resolution timestamps")
	// allow module to initialize and add its own flags before we parse
	if len(os.Args) < 2 {
		log.Fatal("No lookup module specified. Valid modules: ", zdns.ValidlookupsString(), ".")
	}
	gc.Module = strings.ToUpper(os.Args[1])
	factory := zdns.GetLookup(gc.Module)
	if factory == nil {
		flags.Parse(os.Args[1:])
		log.Fatal("Invalid lookup module specified. Valid modules: ", zdns.ValidlookupsString(), ".")
	}
	factory.AddFlags(flags)
	flags.Parse(os.Args[2:])
	// Do some basic sanity checking
	// setup global logging
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
	if *servers_string == "" {
		// if we're doing recursive resolution, figure out default OS name servers
		// otherwise, use the set of 13 root name servers
		if gc.IterativeResolution {
			gc.NameServers = zdns.RootServers[:]
		} else {
			ns, err := zdns.GetDNSServers(*config_file)
			if err != nil {
				log.Fatal("Unable to fetch correct name servers:", err.Error())
			}
			gc.NameServers = ns
		}
		gc.NameServersSpecified = false
		log.Info("no name servers specified. will use: ", strings.Join(gc.NameServers, ", "))
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
			ns[i] = zdns.AddDefaultPortToDNSServerName(s)
		}
		gc.NameServers = ns
		gc.NameServersSpecified = true
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
	} else if *localif_string != "" {
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
	} else {
		// Find local address for use in unbound UDP sockets
		if conn, err := net.Dial("udp", "8.8.8.8:53"); err != nil {
			log.Fatal("Unable to find default IP address: ", err)
		} else {
			gc.LocalAddrs = append(gc.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
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

	if len(flags.Args()) > 0 {
		stat, _ := os.Stdin.Stat()
		// If stdin is piped from the terminal, and we haven't specified a file, and if we have unparsed args
		// use them for a dig-like resolution
		if (stat.Mode()&os.ModeCharDevice) != 0 && gc.InputFilePath == "-" && len(flags.Args()) == 1 {
			gc.PassedName = flags.Args()[0]
		} else {
			log.Fatal("Unused command line flags: ", flags.Args())
		}
	}

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
	if err := zdns.DoLookups(factory, &gc); err != nil {
		log.Fatal("Unable to run lookups:", err.Error())
	}
	// allow the factory to finalize itself
	if err := factory.Finalize(); err != nil {
		log.Fatal("Factory was unable to finalize:", err.Error())
	}
}
