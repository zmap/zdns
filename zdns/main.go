package main

import (
	"encoding/json"
	"flag"
	_ "fmt"
	"github.com/zmap/zdns"
	_ "github.com/zmap/zdns/modules"
	"log"
	"os"
	"strings"
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
	} else {
		gc.NameServers = strings.Split(*servers_string, ",")
		gc.NameServersSpecified = true
	}
	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		log.Fatal("Factory was unable to initialize:", err.Error())
	}
	// run it.
	f := &factory
	metadata, err := zdns.DoLookups(f, &gc)
	if err != nil {
		log.Fatal("Unable to run lookups:", err.Error())
	}
	if gc.MetadataFilePath != "" {
		var f *os.File
		if gc.MetadataFilePath == "" || gc.MetadataFilePath == "-" {
			f = os.Stdout
		} else {
			var err error
			f, err = os.OpenFile(gc.MetadataFilePath, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				log.Fatal("unable to open metadata file:", err.Error())
			}
			defer f.Close()
		}
		j, err := json.Marshal(metadata)
		if err != nil {
			log.Fatal("unable to JSON encode metadata:", err.Error())
		}
		f.WriteString(string(j))
	}
}
