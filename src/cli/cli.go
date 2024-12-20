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

package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	flags "github.com/zmap/zflags"

	"github.com/zmap/zdns/src/zdns"
)

var parser *flags.Parser

type InputHandler interface {
	FeedChannel(in chan<- string, wg *sync.WaitGroup) error
}
type OutputHandler interface {
	WriteResults(results <-chan string, wg *sync.WaitGroup) error
}
type StatusHandler interface {
	LogPeriodicUpdates(statusChan <-chan zdns.Status, wg *sync.WaitGroup) error
}

// GeneralOptions core options for all ZDNS modules
// Order here is the order they'll be printed to the user, so preserve alphabetical order
type GeneralOptions struct {
	LookupAllNameServers bool   `long:"all-nameservers" description:"Behavior is dependent on --iterative. In --iterative, --all-name-servers will query all root servers, then all gtld servers, etc. recording the responses at each layer. In non-iterative mode, the query will be sent to all external resolvers specified in --name-servers."`
	CacheSize            int    `long:"cache-size" default:"10000" description:"how many items can be stored in internal recursive cache"`
	GoMaxProcs           int    `long:"go-processes" default:"0" description:"number of OS processes (GOMAXPROCS by default)"`
	IterationTimeout     int    `long:"iteration-timeout" default:"8" description:"timeout for a single iterative step in an iterative query, in seconds. Only applicable with --iterative"`
	IterativeResolution  bool   `long:"iterative" description:"Perform own iteration instead of relying on recursive resolver"`
	MaxDepth             int    `long:"max-depth" default:"10" description:"how deep should we recurse when performing iterative lookups"`
	NameServerMode       bool   `long:"name-server-mode" description:"Treats input as nameservers to query with a static query rather than queries to send to a static name server"`
	NameServersString    string `long:"name-servers" description:"List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53. If not provided, defaults to either the default root servers in --iterative or the recursive resolvers specified in /etc/resolv.conf or OS equivalent."`
	UseNanoseconds       bool   `long:"nanoseconds" description:"Use nanosecond resolution timestamps in output"`
	NetworkTimeout       int    `long:"network-timeout" default:"2" description:"timeout for round trip network operations, in seconds"`
	DisableFollowCNAMEs  bool   `long:"no-follow-cnames" description:"do not follow CNAMEs/DNAMEs in the lookup process"`
	Retries              int    `long:"retries" default:"3" description:"how many times should zdns retry query against a new nameserver if timeout or temporary failure"`
	Threads              int    `short:"t" long:"threads" default:"100" description:"number of lightweight go threads"`
	Timeout              int    `long:"timeout" default:"20" description:"timeout for resolving a individual name, in seconds"`
	Version              bool   `long:"version" short:"v" description:"Print the version of zdns and exit"`
}

// QueryOptions affect the fields of the actual DNS queries. Applicable to all modules.
type QueryOptions struct {
	CheckingDisabled   bool   `long:"checking-disabled" description:"Sends DNS packets with the CD bit set"`
	ClassString        string `long:"class" default:"INET" description:"DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY."`
	ClientSubnetString string `long:"client-subnet" description:"Client subnet in CIDR format for EDNS0."`
	Dnssec             bool   `long:"dnssec" description:"Requests DNSSEC records by setting the DNSSEC OK (DO) bit"`
	ValidateDNSSEC     bool   `long:"validate-dnssec" description:"Validate DNSSEC records, only applicable with --iterative"`
	UseNSID            bool   `long:"nsid" description:"Request NSID."`
}

// NetworkOptions options for controlling the network behavior. Applicable to all modules.
type NetworkOptions struct {
	IPv4TransportOnly     bool   `long:"4" description:"utilize IPv4 query transport only, incompatible with --6"`
	IPv6TransportOnly     bool   `long:"6" description:"utilize IPv6 query transport only, incompatible with --4"`
	DNSOverHTTPS          bool   `long:"https" description:"Use DNS over HTTPS for lookups, mutually exclusive with --udp-only, --iterative, and --tls"`
	LocalAddrString       string `long:"local-addr" description:"comma-delimited list of local addresses to use, serve as the source IP for outbound queries"`
	LocalIfaceString      string `long:"local-interface" description:"local interface to use"`
	DisableRecycleSockets bool   `long:"no-recycle-sockets" description:"do not create long-lived unbound UDP socket for each thread at launch and reuse for all (UDP) queries"`
	PreferIPv4Iteration   bool   `long:"prefer-ipv4-iteration" description:"Prefer IPv4/A record lookups during iterative resolution. Ignored unless used with both IPv4 and IPv6 query transport"`
	PreferIPv6Iteration   bool   `long:"prefer-ipv6-iteration" description:"Prefer IPv6/AAAA record lookups during iterative resolution. Ignored unless used with both IPv4 and IPv6 query transport"`
	RootCAsFile           string `long:"root-cas-file" description:"Path to a file containing PEM-encoded root CAs to use for verifying server certificates, required for --verify-server-cert"`
	TCPOnly               bool   `long:"tcp-only" description:"Only perform lookups over TCP"`
	DNSOverTLS            bool   `long:"tls" description:"Use DNS over TLS for lookups, mutually exclusive with --udp-only, --iterative, and --https"`
	UDPOnly               bool   `long:"udp-only" description:"Only perform lookups over UDP"`
	VerifyServerCert      bool   `long:"verify-server-cert" description:"Verify the server's certificate when using DNS over TLS or DNS over HTTPS"`
}

// InputOutputOptions options for controlling the input and output behavior of zdns. Applicable to all modules.
type InputOutputOptions struct {
	AlexaFormat                  bool   `long:"alexa" description:"is input file from Alexa Top Million download"`
	BlacklistFilePath            string `long:"blacklist-file" description:"blacklist file for servers to exclude from lookups"`
	DNSConfigFilePath            string `long:"conf-file" default:"/etc/resolv.conf" description:"config file for DNS servers"`
	MultipleModuleConfigFilePath string `short:"c" long:"multi-config-file" description:"config file path for multiple module"`
	IncludeInOutput              string `long:"include-fields" description:"Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags, dnssec"`
	InputFilePath                string `short:"f" long:"input-file" default:"-" description:"names to read, defaults to stdin"`
	LogFilePath                  string `long:"log-file" default:"-" description:"where should JSON logs be saved, defaults to stderr"`
	MetadataFilePath             string `long:"metadata-file" description:"where should JSON metadata be saved, defaults to no metadata output. Use '-' for stderr."`
	MetadataFormat               bool   `long:"metadata-passthrough" description:"if input records have the form 'name,METADATA', METADATA will be propagated to the output"`
	OutputFilePath               string `short:"o" long:"output-file" default:"-" description:"where should JSON output be saved, defaults to stdout"`
	QuietStatusUpdates           bool   `short:"q" long:"quiet" description:"do not print status updates"`
	NameOverride                 string `long:"override-name" description:"name overrides all passed in names. Commonly used with --name-server-mode."`
	NamePrefix                   string `long:"prefix" description:"name to be prepended to what's passed in (e.g., www.)"`
	ResultVerbosity              string `long:"result-verbosity" default:"normal" description:"Sets verbosity of each output record. Options: short, normal, long, trace"`
	StatusUpdatesFilePath        string `short:"u" long:"status-updates-file" default:"-" description:"file to write scan progress to, defaults to stderr"`
	Verbosity                    int    `long:"verbosity" default:"3" description:"log verbosity: 1 (lowest)--5 (highest)"`
}

type CLIConf struct {
	GeneralOptions
	NetworkOptions
	InputOutputOptions
	QueryOptions
	OutputGroups       []string
	TimeFormat         string
	NameServers        []string // recursive resolvers if not in iterative mode, root servers/servers to start iteration if in iterative mode
	Domains            []string // if user provides domain names as arguments, dig-style
	LocalAddrSpecified bool
	LocalAddrs         []net.IP
	ClientSubnet       *dns.EDNS0_SUBNET
	InputHandler       InputHandler
	OutputHandler      OutputHandler
	StatusHandler      StatusHandler
	CLIModule          string                  // the module name as passed in by the user
	ActiveModuleNames  []string                // names of modules that are active in this invocation of zdns. Mostly used with MULTIPLE
	ActiveModules      map[string]LookupModule // map of module names to modules
	Class              uint16
}

var GC CLIConf

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	parseArgs()
	if strings.EqualFold(GC.CLIModule, "MULTIPLE") {
		err := handleMultipleModule(&GC)
		if err != nil {
			log.Fatalf("error in handling multiple modules: %v", err)
		}
	} else {
		lookupModule, err := GetLookupModule(GC.CLIModule)
		if err != nil {
			log.Fatal("could not get lookup module: ", err)
		}
		GC.ActiveModules = make(map[string]LookupModule)
		GC.ActiveModules[GC.CLIModule] = lookupModule
		GC.ActiveModuleNames = []string{GC.CLIModule}
	}
	Run(GC)
}

func handleMultipleModule(GC *CLIConf) error {
	// need to parse the multiple module config file first
	if GC.MultipleModuleConfigFilePath == "" {
		return errors.New("must specify a config file for the multiple module, see -c")
	}
	ini := flags.NewIniParser(parser)
	moduleStrings, modules, err := ini.ParseFile(GC.MultipleModuleConfigFilePath)
	if err != nil {
		return fmt.Errorf("could not parse multi-module file: %v", err)
	}
	if len(moduleStrings) != len(modules) {
		return errors.New("number of module names does not match number of modules retrieved from file")
	}
	GC.ActiveModuleNames = moduleStrings
	GC.ActiveModules = make(map[string]LookupModule, len(moduleStrings))
	for i, name := range moduleStrings {
		lm, ok := modules[i].(LookupModule)
		if !ok {
			return fmt.Errorf("module %s is not a LookupModule", name)
		}
		if _, ok = GC.ActiveModules[name]; ok {
			return fmt.Errorf("module %s is defined multiple times in the config file", name)
		}
		GC.ActiveModules[name] = lm
	}
	return nil
}

// parseArgs parses the command line arguments and sets the global configuration
// One limitation of the zflags library is you can't have "command-less" flags like ./zdns --version without turning
// SubCommandsOptional = true. But then you don't get ZFlag's great command suggestion if you barely mistype a cmd.
// Ex:./zdns AAAB -> Unknown command `AAAB', did you mean `AAAA'?
// The below is a workaround to get the best of both worlds where we set SubcommandsOptiional to true, check for any
// command-less flags, and then re-parse with SubcommandsOptional = false
func parseArgs() {
	if len(os.Args) >= 0 {
		for i, arg := range os.Args {
			// the below is necessary or else zdns --help is converted to zdns --HELP
			if _, ok := GetValidLookups()[strings.ToUpper(arg)]; ok {
				// we want users to be able to use `zdns nslookup` as well as `zdns NSLOOKUP`
				os.Args[i] = strings.ToUpper(os.Args[i])
				break // only capitalize the module, following strings could be domains
			}

		}
	}
	// setting this to true, only to get those flags that don't need a module (--version)
	parser.SubcommandsOptional = true
	parser.Options = flags.Default ^ flags.PrintErrors // we'll print errors in the 2nd invocation, otherwise we get the error printed twice
	_, _, _, _ = parser.ParseCommandLine(os.Args[1:])
	if GC.Version {
		fmt.Printf("zdns version %s", zdns.ZDNSVersion)
		fmt.Println()
		os.Exit(0)
	}
	parser.SubcommandsOptional = false
	parser.Options = flags.Default
	args, moduleType, _, err := parser.ParseCommandLine(os.Args[1:])
	if err != nil {
		var flagErr *flags.Error
		if errors.As(err, &flagErr) {
			// parser already printed error, exit without printing
			os.Exit(1)
		}
		// exit and print
		log.Fatal(err)
	}
	if len(args) != 0 {
		GC.Domains = args
	}
	GC.CLIModule = strings.ToUpper(moduleType)
}

func init() {
	parser = flags.NewParser(nil, flags.None) // options set in Execute()
	parser.Command.SubcommandsOptional = true // without this, the user must use a command, makes ./zdns --version impossible, we'll enforce specifying modules ourselves
	parser.Name = "zdns"
	// ZFlags will pre-pend the parser.Name and append "<command>" to the Usage string. So this is a work-around to indicate
	// to users that [DOMAINS] must come after the command. ex: "./zdns A google.com yahoo.com
	parser.Usage = "[OPTIONS] <command> [DOMAINS]\n  zdns [OPTIONS]"
	parser.ShortDescription = "High-speed, low-drag DNS lookups"
	parser.LongDescription = `ZDNS is a library and CLI tool for making very fast DNS requests. It's built upon
https://github.com/zmap/dns (and in turn https://github.com/miekg/dns) for constructing
and parsing raw DNS packets.
ZDNS also includes its own recursive resolution and a cache to further optimize performance.

Usage
Domains can be taken from a new-line delimited file, stdin, or passed as arguments.
./zdns A --input-file domains.txt
echo "google.com" | ./zdns A
cat domains.txt | ./zdns A
./zdns A google.com yahoo.com

Name Servers can either be specified as a global list or a per-domain name server.
./zdns A google.com --name-servers=1.1.1.1,8.8.8.8
echo "google.com,1.0.0.1" | ./zdns A

For more information, see the README
`

	_, err := parser.AddGroup("General Options", "General options for controlling the behavior of zdns", &GC.GeneralOptions)
	if err != nil {
		log.Fatalf("could not add ZDNS Options group: %v", err)
	}
	_, err = parser.AddGroup("Query Options", "Options for controlling the fields of the actual DNS queries", &GC.QueryOptions)
	if err != nil {
		log.Fatalf("could not add Query Options group: %v", err)
	}
	_, err = parser.AddGroup("Network Options", "Options for controlling the network behavior of zdns", &GC.NetworkOptions)
	if err != nil {
		log.Fatalf("could not add Network Options group: %v", err)
	}
	_, err = parser.AddGroup("Input/Output Options", "Options for controlling the input and output behavior of zdns", &GC.InputOutputOptions)
	if err != nil {
		log.Fatalf("could not add Input/Output Options group: %v", err)
	}
	// this is necessary since the .ini file parser expects that all global options are a part of Application Options
	appOptions, err := parser.AddGroup("Application Options", "Hidden group including all global options", &GC)
	if err != nil {
		log.Fatalf("could not add Application Options group: %v", err)
	}
	appOptions.Hidden = true
}
