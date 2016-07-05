package main

import (
	"os"
	"log"
	"flag"
	"strings"
	_"github.com/zmap/zdns/modules"
	"github.com/zmap/zdns"
)


func main() {

	var gc zdns.GlobalConf
	// global flags relevant to every lookup module
	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	flags.IntVar(&gc.Timeout, "timeout", 10, "timeout for resolving an individual name")
	flags.StringVar(&gc.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	flags.BoolVar(&gc.AlexaFormat, "alexa", false, "is input file from alexa top million download")
	flags.StringVar(&gc.InputFilePath, "input-file", "-", "names to read")
	flags.StringVar(&gc.OutputFilePath, "output-file", "-", "comma-delimited list of DNS servers to use")
	flags.StringVar(&gc.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	flags.StringVar(&gc.LogFilePath, "log-file", "", "where should JSON metadata be saved")
	servers_string := flags.String("name-servers", "", "comma-delimited list of DNS servers to use")
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
		gc.NameServers = zdns.GetDNSServers()
		gc.NameServersSpecified = false
	} else {
		gc.NameServers = strings.Split(*servers_string, ",")
		gc.NameServersSpecified = true
	}
	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		log.Fatal("Factory was unable to initialize:", err.Error())
	}
}
