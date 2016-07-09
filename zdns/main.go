package main

import (
	"flag"
	_ "fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/zmap/zdns"
	_ "github.com/zmap/zdns/modules"
	"os"
	"runtime"
	"strings"
)

func main() {

	var gc zdns.GlobalConf
	// global flags relevant to every lookup module
	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	flags.IntVar(&gc.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	flags.IntVar(&gc.Timeout, "timeout", 10, "timeout for resolving an individual name")
	flags.StringVar(&gc.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	flags.BoolVar(&gc.AlexaFormat, "alexa", false, "is input file from alexa top million download")
	flags.StringVar(&gc.InputFilePath, "input-file", "-", "names to read")
	flags.StringVar(&gc.OutputFilePath, "output-file", "-", "comma-delimited list of DNS servers to use")
	flags.StringVar(&gc.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	flags.StringVar(&gc.LogFilePath, "log-file", "", "where should JSON metadata be saved")
	flags.IntVar(&gc.Verbosity, "verbosity", 3, "log verbosity: 1--5")
	servers_string := flags.String("name-servers", "", "comma-delimited list of DNS servers to use")
	config_file := flags.String("conf-file", "/etc/resolv.conf", "config file for DNS servers")
	// allow module to initialize and add its own flags before we parse
	if len(os.Args) < 2 {
		log.Fatal("No lookup module specified.")
	}
	factory := zdns.GetLookup(os.Args[1])
	if factory == nil {
		log.Fatal("Invalid lookup module specified.")
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
	if *servers_string == "" {
		// figure out default OS name servers
		ns, err := zdns.GetDNSServers(*config_file)
		if err != nil {
			log.Fatal("Unable to fetch correct name servers:", err.Error())
		}
		gc.NameServers = ns
		gc.NameServersSpecified = false
		log.Info("no name servers specified. will use:", gc.NameServers)
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
	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		log.Fatal("Factory was unable to initialize:", err.Error())
	}
	// run it.
	f := &factory
	if err := zdns.DoLookups(f, &gc); err != nil {
		log.Fatal("Unable to run lookups:", err.Error())
	}
}
