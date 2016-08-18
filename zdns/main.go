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

	log "github.com/Sirupsen/logrus"
	"github.com/zmap/zdns"
	_ "github.com/zmap/zdns/modules/a"
	_ "github.com/zmap/zdns/modules/aaaa"
	_ "github.com/zmap/zdns/modules/alookup"
	_ "github.com/zmap/zdns/modules/any"
	_ "github.com/zmap/zdns/modules/axfr"
	_ "github.com/zmap/zdns/modules/cname"
	_ "github.com/zmap/zdns/modules/dmarc"
	_ "github.com/zmap/zdns/modules/mx"
	_ "github.com/zmap/zdns/modules/mxlookup"
	_ "github.com/zmap/zdns/modules/ns"
	_ "github.com/zmap/zdns/modules/nslookup"
	_ "github.com/zmap/zdns/modules/ptr"
	_ "github.com/zmap/zdns/modules/soa"
	_ "github.com/zmap/zdns/modules/spf"
	_ "github.com/zmap/zdns/modules/txt"
	_ "github.com/zmap/zdns/modules/zone"
)

func main() {

	var gc zdns.GlobalConf
	// global flags relevant to every lookup module
	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	flags.IntVar(&gc.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	flags.StringVar(&gc.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	flags.BoolVar(&gc.AlexaFormat, "alexa", false, "is input file from Alexa Top Million download")
	flags.StringVar(&gc.InputFilePath, "input-file", "-", "names to read")
	flags.StringVar(&gc.OutputFilePath, "output-file", "-", "comma-delimited list of DNS servers to use")
	flags.StringVar(&gc.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	flags.StringVar(&gc.LogFilePath, "log-file", "", "where should JSON metadata be saved")
	flags.IntVar(&gc.Verbosity, "verbosity", 3, "log verbosity: 1--5")
	servers_string := flags.String("name-servers", "", "comma-delimited list of DNS servers to use")
	config_file := flags.String("conf-file", "/etc/resolv.conf", "config file for DNS servers")
	timeout := flags.Int("timeout", 10, "timeout for resolving an individual name")
	// allow module to initialize and add its own flags before we parse
	if len(os.Args) < 2 {
		log.Fatal("No lookup module specified. Valid modules: ", zdns.ValidlookupsString())
	}
	gc.Module = strings.ToUpper(os.Args[1])
	factory := zdns.GetLookup(gc.Module)
	if factory == nil {
		log.Fatal("Invalid lookup module specified. Valid modules: ", zdns.ValidlookupsString())
	}
	factory.AddFlags(flags)
	flags.Parse(os.Args[2:])
	// Do some basic sanity checking
	// setup global logging
	if gc.LogFilePath != "" {
		f, err := os.Open(gc.LogFilePath)
		if err != nil {
			log.Fatalf("Unable to open log file (%s): %s", gc.LogFilePath, err.Error())
		}
		log.SetOutput(f)
	}
	// complete post facto global initialization based on command line arguments
	gc.Timeout = time.Duration(time.Second * time.Duration(*timeout))
	if *servers_string == "" {
		// figure out default OS name servers
		ns, err := zdns.GetDNSServers(*config_file)
		if err != nil {
			log.Fatal("Unable to fetch correct name servers:", err.Error())
		}
		gc.NameServers = ns
		gc.NameServersSpecified = false
		log.Info("no name servers specified. will use: ", strings.Join(gc.NameServers, ", "))
	} else {
		gc.NameServers = strings.Split(*servers_string, ",")
		gc.NameServersSpecified = true
	}
	if gc.GoMaxProcs < 0 {
		log.Fatal("Invalid argument for --go-processes. Must be >1.")
	}
	if gc.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(gc.GoMaxProcs)
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
