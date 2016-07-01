package main

import (
	"os"
	"flag"
	"fmt"
	"strings"
	//"reflect"
	"github.com/zmap/zdns/scanners"
)

func main() {

	// debug
	for k, _ := range scanner.Scanners {
		fmt.Println("loaded module:", k)
	}

	var gc scanner.GlobalConf

	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	servers_string := flags.String("servers", "", "comma-delimited list of DNS servers to use")
	gc.Servers = strings.Split(*servers_string, ",")
	//output_file := flag.String("output-file", "-", "comma-delimited list of DNS servers to use")
	//input_file := flag.String("input-file", "-", "comma-delimited list of DNS servers to use")
	//metadata_file := flag.String("metadata-file", "", "comma-delimited list of DNS servers to use")

	// allow module to initialize and add its own flags before we parse what the usre passed
	if len(os.Args) < 2 {
		fmt.Println("[error] No module specified.")
		os.Exit(1)
	}
	module, ok := scanner.Scanners[os.Args[1]]
	if !ok {
		fmt.Println("[error] Invalid module:", os.Args[1])
		os.Exit(1)
	}

	//reflect.ValueOf(&module).MethodByName("AddFlags")
	module.AddFlags(flags)
	flags.Parse(os.Args[2:])

	// parse out global flags and make global configuration

}
