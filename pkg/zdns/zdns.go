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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/internal/util"
	"github.com/zmap/zdns/iohandlers"
)

func Run(run ZdnsRun) {

	gc := run.GlobalConf

	factory := GetLookup(gc.Module)

	if factory == nil {
		log.Fatal("Invalid lookup module specified. Valid modules: ", ValidlookupsString())
	}

	factory.SetFlags(run.ModuleFlags)

	if gc.LogFilePath != "" {
		f, err := os.OpenFile(gc.LogFilePath, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Fatalf("Unable to open log file (%s): %s", gc.LogFilePath, err.Error())
		}
		log.SetOutput(f)
	}

	if gc.Verbosity == 0 {
		log.Warn("Verbosity level unspecified or set to 0, defaulting to 3")
		gc.Verbosity = 3
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
		log.Warn("Unknown verbosity level specified. Must be between 1 (lowest)--5 (highest)")
	}

	// complete post facto global initialization based on command line arguments
	gc.Timeout = time.Duration(time.Second * time.Duration(run.Timeout))
	gc.IterationTimeout = time.Duration(time.Second * time.Duration(run.IterationTimeout))

	// class initialization
	switch strings.ToUpper(run.Class) {
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

	if run.Servers == "" {
		// if we're doing recursive resolution, figure out default OS name servers
		// otherwise, use the set of 13 root name servers
		if gc.IterativeResolution {
			gc.NameServers = RootServers[:]
		} else {
			ns, err := GetDNSServers(run.ConfigFile)
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
		if (run.Servers)[0] == '@' {
			filepath := (run.Servers)[1:]
			f, err := ioutil.ReadFile(filepath)
			if err != nil {
				log.Fatalf("Unable to read file (%s): %s", filepath, err.Error())
			}
			if len(f) == 0 {
				log.Fatalf("Empty file (%s)", filepath)
			}
			ns = strings.Split(strings.Trim(string(f), "\n"), "\n")
		} else {
			ns = strings.Split(run.Servers, ",")
		}
		for i, s := range ns {
			ns[i] = util.AddDefaultPortToDNSServerName(s)
		}
		gc.NameServers = ns
		gc.NameServersSpecified = true
	}

	if run.LocalAddr != "" {
		for _, la := range strings.Split(run.LocalAddr, ",") {
			ip := net.ParseIP(la)
			if ip != nil {
				gc.LocalAddrs = append(gc.LocalAddrs, ip)
			} else {
				log.Fatal("Invalid argument for --local-addr (", la, "). Must be a comma-separated list of valid IP addresses.")
			}
		}
		log.Info("using local address: ", run.LocalAddr)
		gc.LocalAddrSpecified = true
	}

	if run.LocalIF != "" {
		if gc.LocalAddrSpecified {
			log.Fatal("Both --local-addr and --local-interface specified.")
		} else {
			li, err := net.InterfaceByName(run.LocalIF)
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
			log.Info("using local interface: ", run.LocalIF)
		}
	}
	if !gc.LocalAddrSpecified {
		// Find local address for use in unbound UDP sockets
		if conn, err := net.Dial("udp", "8.8.8.8:53"); err != nil {
			log.Fatal("Unable to find default IP address: ", err)
		} else {
			gc.LocalAddrs = append(gc.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
		}
	}
	if run.NanoSeconds {
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

	if gc.ResultVerbosity == "" {
		log.Warn("Result verbosity level unspecified, defaulting to short")
		gc.ResultVerbosity = "short"
	}

	if gc.ResultVerbosity != "short" && gc.ResultVerbosity != "normal" && gc.ResultVerbosity != "long" && gc.ResultVerbosity != "trace" {
		log.Fatal("Invalid result verbosity. Options: short, normal, long, trace")
	}

	gc.OutputGroups = append(gc.OutputGroups, gc.ResultVerbosity)
	gc.OutputGroups = append(gc.OutputGroups, groups...)

	// Seeding for RandomNameServer()
	rand.Seed(time.Now().UnixNano())

	if gc.InputFilePath == "" {
		log.Warn("No InputFilePath specified, defaulting to STDIN (\"-\")")
		gc.InputFilePath = "-"
	}
	if gc.OutputFilePath == "" {
		log.Warn("No OutputFilePath specified, defaulting to STDOUT (\"-\")")
		gc.OutputFilePath = "-"
	}

	// some modules require multiple passes over a file (this is really just the case for zone files)
	if !factory.AllowStdIn() && gc.InputFilePath == "-" {
		log.Fatal("Specified module does not allow reading from stdin")
	}

	// setup i/o
	if len(gc.PassedNames) != 0 {
		// warn the user if they're overriding a setting
		if gc.InputFilePath != "-" && gc.InputFilePath != "" {
			log.Warn("Using ZDNS in dig-like mode with arguments as inputs, ZdnsRun.GlobalConf.InputFilePath setting ignored")
		}
		// Pass input to a stream reader as a newline-delimited string of args
		gc.InputHandler = iohandlers.NewStreamInputHandler(strings.NewReader(strings.Join(gc.PassedNames, "\n")))
	} else {
		gc.InputHandler = iohandlers.NewFileInputHandler(gc.InputFilePath)
	}
	gc.OutputHandler = iohandlers.NewFileOutputHandler(gc.OutputFilePath)

	if gc.Threads == 0 {
		log.Warn("Number of Threads (goroutines) set to zero (or left unset), defaulting to 1000")
		gc.Threads = 1000
	}

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
