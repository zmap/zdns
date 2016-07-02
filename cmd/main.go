package main

import (
	"os"
	"flag"
	"fmt"
	"strings"
	"encoding/json"
	"github.com/zmap/zdns/lookups"
)

func processName(factory LookupFactory, name string, prefix string) string {

	if prefix != "" {
		name =
	}

	data, err := factory.MakeLookup().DoLookup(name)

}

func processLoop(factory, LookupFactory, in *file, out *file) {


}



func main() {

	var gc conf.GlobalConf
	// global flags relevant to every lookup module
	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	flags.IntVar("timeout", 10, "timeout for resolving an individual name")
	flags.StringVar(&gc.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	flags.BooleanVar(&gc.AlexaFormat, "alexa", false, "is input file from alexa top million download")
	flags.StringVar(&gc.InputFilePath, "input-file", "-", "names to read")
	flags.StringVar(&gc.OutputFilePath"output-file", "-", "comma-delimited list of DNS servers to use")
	flags.StringVar(&gc.MetadataFilePath"metadata-file", "", "where should JSON metadata be saved")
	flags.StringVar(&gc.LogFilePath, "log-file", "", "where should JSON metadata be saved")
	servers_string := flags.String("name-servers", "", "comma-delimited list of DNS servers to use")
	// allow module to initialize and add its own flags before we parse
	if len(os.Args) < 2 {
		fmt.Println("[error] No module specified.")
		os.Exit(1)
	}
	factory = GetLookupFactory(os.Args[1])
	factory.AddFlags(flags)
	flags.Parse(os.Args[2:])
	// complete post facto global initialization based on command line arguments
	if servers_string == "" {
		// figure out default OS name servers
		gc.NameServers = conf.GetDNSServers()
		gc.NameServersSpecified = false
	} else {
		gc.NameServers = strings.Split(*servers_string, ",")
		gc.NameServersSpecified = true
	}
	if

	// allow the factory to initialize itself
	if factory.initialize(&gc) != nil {
		fmt.Println("[error] factory could not initialize")
		os.Exit(1)
	}
	//

}
