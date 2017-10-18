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
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zdns"
	_ "github.com/zmap/zdns/modules/alookup"
	_ "github.com/zmap/zdns/modules/axfr"
	_ "github.com/zmap/zdns/modules/dmarc"
	_ "github.com/zmap/zdns/modules/miekg"
	_ "github.com/zmap/zdns/modules/mxlookup"
	_ "github.com/zmap/zdns/modules/nslookup"
	_ "github.com/zmap/zdns/modules/spf"
)

func main() {

	var gc zdns.GlobalConf
	// global flags relevant to every lookup module
	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	flags.IntVar(&gc.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	flags.StringVar(&gc.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	flags.BoolVar(&gc.AlexaFormat, "alexa", false, "is input file from Alexa Top Million download")
	flags.BoolVar(&gc.IterativeResolution, "iterative", false, "Perform own iteration instead of relying on recursive resolver")
	flags.BoolVar(&gc.Trace, "trace", false, "Output a trace of individual steps for each resolution")
	flags.StringVar(&gc.InputFilePath, "input-file", "-", "names to read")
	flags.StringVar(&gc.OutputFilePath, "output-file", "-", "where should JSON output be saved")
	flags.StringVar(&gc.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	flags.StringVar(&gc.LogFilePath, "log-file", "", "where should JSON logs be saved")
	flags.IntVar(&gc.Verbosity, "verbosity", 3, "log verbosity: 1 (lowest)--5 (highest)")
	flags.IntVar(&gc.Retries, "retries", 1, "how many times should zdns retry query if timeout or temporary failure")
	flags.IntVar(&gc.MaxDepth, "max-depth", 10, "how deep should we recurse when performing iterative lookups")
	flags.IntVar(&gc.CacheSize, "cache-size", 10000, "how many items can be stored in internal recursive cache")
	servers_string := flags.String("name-servers", "", "comma-delimited list of DNS servers to use")
	config_file := flags.String("conf-file", "/etc/resolv.conf", "config file for DNS servers")
	timeout := flags.Int("timeout", 15, "timeout for resolving an individual name")
	iterationTimeout := flags.Int("iteration-timeout", 4, "timeout for resolving a single iteration in an iterative query")
	class_string := flags.String("class", "INET", "DNS class to query (INET, CSNET, CHAOS, HESIOD, NONE, ANY (default INET)")
	nanoSeconds := flags.Bool("nanoseconds", false, "Use nanosecond resolution timestamps")
	// allow module to initialize and add its own flags before we parse
	if len(os.Args) < 2 {
		log.Fatal("No lookup module specified. Valid modules: ", zdns.ValidlookupsString())
	}
	gc.Module = strings.ToUpper(os.Args[1])
	factory := zdns.GetLookup(gc.Module)
	if factory == nil {
		flags.Parse(os.Args[1:])
		log.Fatal("Invalid lookup module specified. Valid modules: ", zdns.ValidlookupsString())
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
		gc.NameServers = strings.Split(*servers_string, ",")
		gc.NameServersSpecified = true
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
	if len(flags.Args()) > 0 {
		stat, _ := os.Stdin.Stat()
		// If stdin is piped from the terminal, and we havent specified a file, and if we have unparsed args
		// use them for a dig like reslution
		if (stat.Mode()&os.ModeCharDevice) != 0 && gc.InputFilePath == "-" && len(flags.Args()) == 1 {
			gc.PassedName = flags.Args()[0]
		} else {
			log.Fatal("Unused command line flags: ", flags.Args())
		}
	}

	// some modules require multiple passes over a file (this is really just the case for zone files)
	if !factory.AllowStdIn() && gc.InputFilePath == "-" {
		log.Fatal("Specified module does not allow reading from stdin")
	}

	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		log.Fatal("Factory was unable to initialize:", err.Error())
	}
	// run it.
	if err := zdns.DoLookups(&factory, &gc); err != nil {
		log.Fatal("Unable to run lookups:", err.Error())
	}
	// allow the factory to initialize itself
	if err := factory.Finalize(); err != nil {
		log.Fatal("Factory was unable to finalize:", err.Error())
	}
}
