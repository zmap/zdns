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
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	flags "github.com/zmap/zflags"

	"github.com/zmap/dns"
)

const (
	zdnsCLIVersion = "1.1.0"
)

var parser *flags.Parser

type InputHandler interface {
	FeedChannel(in chan<- string, wg *sync.WaitGroup) error
}
type OutputHandler interface {
	WriteResults(results <-chan string, wg *sync.WaitGroup) error
}

type ApplicationOptions struct {
	Threads             int  `short:"t" long:"threads" default:"1000" description:"number of lightweight go threads"`
	Timeout             int  `long:"timeout" default:"15" description:"timeout for resolving a individual name, in seconds"`
	IterationTimeout    int  `long:"iteration-timeout" default:"4" description:"timeout for a single iterative step in an iterative query, in seconds. Only applicable with --iterative"`
	Retries             int  `long:"retries" default:"1" description:"how many times should zdns retry query if timeout or temporary failure"`
	AlexaFormat         bool `long:"alexa" description:"is input file from Alexa Top Million download"`
	MetadataFormat      bool `long:"metadata-passthrough" description:"if input records have the form 'name,METADATA', METADATA will be propagated to the output"`
	IterativeResolution bool `long:"iterative" description:"Perform own iteration instead of relying on recursive resolver"`

	NameServersString  string `long:"name-servers" description:"List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53."`
	LocalAddrString    string `long:"local-addr" description:"comma-delimited list of local addresses to use, serve as the source IP for outbound queries"`
	LocalIfaceString   string `long:"local-interface" description:"local interface to use"`
	ConfigFilePath     string `long:"conf-file" default:"/etc/resolv.conf" description:"config file for DNS servers"`
	ClassString        string `long:"class" default:"INET" description:"DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY."`
	UseNanoseconds     bool   `long:"nanoseconds" description:"Use nanosecond resolution timestamps in output"`
	ClientSubnetString string `long:"client-subnet" description:"Client subnet in CIDR format for EDNS0."`

	ResultVerbosity string `long:"result-verbosity" default:"normal" description:"Sets verbosity of each output record. Options: short, normal, long, trace"`
	IncludeInOutput string `long:"include-fields" description:"Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags"`
	MaxDepth        int    `long:"max-depth" default:"10" description:"how deep should we recurse when performing iterative lookups"`
	CacheSize       int    `long:"cache-size" default:"10000" description:"how many items can be stored in internal recursive cache"`
	GoMaxProcs      int    `long:"go-processes" default:"0" description:"number of OS processes (GOMAXPROCS by default)"`
	Verbosity       int    `long:"verbosity" default:"3" description:"log verbosity: 1 (lowest)--5 (highest)"`

	LookupAllNameServers  bool `long:"all-nameservers" description:"Perform the lookup via all the nameservers for the domain."`
	TCPOnly               bool `long:"tcp-only" description:"Only perform lookups over TCP"`
	UDPOnly               bool `long:"udp-only" description:"Only perform lookups over UDP"`
	IPv4TransportOnly     bool `long:"4" description:"utilize IPv4 query transport only, incompatible with --6"`
	IPv6TransportOnly     bool `long:"6" description:"utilize IPv6 query transport only, incompatible with --4"`
	PreferIPv4Iteration   bool `long:"prefer-ipv4-iteration" description:"Prefer IPv4/A record lookups during iterative resolution. Ignored unless used with both IPv4 and IPv6 query transport"`
	PreferIPv6Iteration   bool `long:"prefer-ipv6-iteration" description:"Prefer IPv6/AAAA record lookups during iterative resolution. Ignored unless used with both IPv4 and IPv6 query transport"`
	DisableRecycleSockets bool `long:"no-recycle-sockets" description:"do not create long-lived unbound UDP socket for each thread at launch and reuse for all (UDP) queries"`
	UseNSID               bool `long:"nsid" description:"Request NSID."`
	Dnssec                bool `long:"dnssec" description:"Requests DNSSEC records by setting the DNSSEC OK (DO) bit"`
	CheckingDisabled      bool `long:"checking-disabled" description:"Sends DNS packets with the CD bit set"`

	InputFilePath     string `short:"f" long:"input-file" default:"-" description:"names to read, defaults to stdin"`
	OutputFilePath    string `short:"o" long:"output-file" default:"-" description:"where should JSON output be saved, defaults to stdout"`
	BlacklistFilePath string `long:"blacklist-file" description:"blacklist file for servers to exclude from lookups"`

	LogFilePath      string `long:"log-file" default:"-" description:"where should JSON logs be saved, defaults to stderr"`
	MetadataFilePath string `long:"metadata-file" description:"where should JSON metadata be saved, defaults to no metadata output. Use '-' for stderr."`

	NamePrefix          string `long:"prefix" description:"name to be prepended to what's passed in (e.g., www.)"`
	NameOverride        string `long:"override-name" description:"name overrides all passed in names. Commonly used with --name-server-mode."`
	NameServerMode      bool   `long:"name-server-mode" description:"Treats input as nameservers to query with a static query rather than queries to send to a static name server"`
	DisableFollowCNAMEs bool   `long:"no-follow-cnames" description:"do not follow CNAMEs/DNAMEs in the lookup process"`
}

type CLIConf struct {
	ApplicationOptions
	OutputGroups       []string
	TimeFormat         string
	NameServers        []string // recursive resolvers if not in iterative mode, root servers/servers to start iteration if in iterative mode
	LocalAddrSpecified bool
	LocalAddrs         []net.IP
	ClientSubnet       *dns.EDNS0_SUBNET
	InputHandler       InputHandler
	OutputHandler      OutputHandler
	Module             string
	Class              uint16
}

// var cfgFile string
var GC CLIConf

//// rootCmd represents the base command when called without any subcommands
//var rootCmd = &cobra.Command{
//	Use:   "zdns",
//	Short: "High-speed, low-drag DNS lookups",
//	Long: `ZDNS is a library and CLI tool for making very fast DNS requests. It's built upon
//https://github.com/zmap/dns (and in turn https://github.com/miekg/dns) for constructing
//and parsing raw DNS packets.
//
//ZDNS also includes its own recursive resolution and a cache to further optimize performance.`,
//	ValidArgs: GetValidLookups(),
//	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
//	Run: func(cmd *cobra.Command, args []string) {
//		GC.Module = strings.ToUpper(args[0])
//		Run(GC, cmd.Flags())
//	},
//	Version: zdnsCLIVersion,
//}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	//err := rootCmd.Execute()
	posArgs, moduleType, f, err := parser.ParseCommandLine(os.Args[1:])
	fmt.Println(posArgs, moduleType, f)
	if err != nil {
		os.Exit(1)
	}
	fmt.Println(cliconf)
	cliconf.Module = strings.ToUpper(posArgs[0])
	Run(cliconf, nil)
}

var cliconf = CLIConf{}

func init() {
	parser = flags.NewParser(&cliconf, flags.Default)
	//cobra.OnInitialize(initConfig)
	//
	//// Here you will define your flags and configuration settings.
	//// Cobra supports persistent flags, which, if defined here,
	//// will be global for your application.
	//
	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.zdns.yaml)")
	//
	//// Cobra also supports local flags, which will only run
	//// when this action is called directly.
	//rootCmd.PersistentFlags().IntVar(&GC.Threads, "threads", 1000, "number of lightweight go threads")
	//rootCmd.PersistentFlags().IntVar(&GC.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	//rootCmd.PersistentFlags().StringVar(&GC.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	//rootCmd.PersistentFlags().StringVar(&GC.NameOverride, "override-name", "", "name overrides all passed in names")
	//rootCmd.PersistentFlags().BoolVar(&GC.AlexaFormat, "alexa", false, "is input file from Alexa Top Million download")
	//rootCmd.PersistentFlags().BoolVar(&GC.MetadataFormat, "metadata-passthrough", false, "if input records have the form 'name,METADATA', METADATA will be propagated to the output")
	//rootCmd.PersistentFlags().BoolVar(&GC.IterativeResolution, "iterative", false, "Perform own iteration instead of relying on recursive resolver")
	//rootCmd.PersistentFlags().BoolVar(&GC.LookupAllNameServers, "all-nameservers", false, "Perform the lookup via all the nameservers for the domain.")
	//rootCmd.PersistentFlags().StringVar(&GC.InputFilePath, "input-file", "-", "names to read, defaults to stdin")
	//rootCmd.PersistentFlags().StringVar(&GC.OutputFilePath, "output-file", "-", "where should JSON output be saved, defaults to stdout")
	//rootCmd.PersistentFlags().StringVar(&GC.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved, defaults to no metadata output. Use '-' for stderr.")
	//rootCmd.PersistentFlags().StringVar(&GC.LogFilePath, "log-file", "", "where should JSON logs be saved, defaults to stderr")
	//
	//rootCmd.PersistentFlags().StringVar(&GC.ResultVerbosity, "result-verbosity", "normal", "Sets verbosity of each output record. Options: short, normal, long, trace")
	//rootCmd.PersistentFlags().StringVar(&GC.IncludeInOutput, "include-fields", "", "Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags")
	//
	//rootCmd.PersistentFlags().IntVar(&GC.Verbosity, "verbosity", 3, "log verbosity: 1 (lowest)--5 (highest)")
	//rootCmd.PersistentFlags().IntVar(&GC.Retries, "retries", 1, "how many times should zdns retry query if timeout or temporary failure")
	//rootCmd.PersistentFlags().IntVar(&GC.MaxDepth, "max-depth", 10, "how deep should we recurse when performing iterative lookups")
	//rootCmd.PersistentFlags().IntVar(&GC.CacheSize, "cache-size", 10000, "how many items can be stored in internal recursive cache")
	//rootCmd.PersistentFlags().BoolVar(&GC.TCPOnly, "tcp-only", false, "Only perform lookups over TCP")
	//rootCmd.PersistentFlags().BoolVar(&GC.UDPOnly, "udp-only", false, "Only perform lookups over UDP")
	//rootCmd.PersistentFlags().BoolVar(&GC.CheckingDisabled, "checking-disabled", false, "Sends DNS packets with the CD bit set")
	//rootCmd.PersistentFlags().BoolVar(&GC.RecycleSockets, "recycle-sockets", true, "Create long-lived unbound UDP socket for each thread at launch and reuse for all (UDP) queries")
	//rootCmd.PersistentFlags().BoolVar(&GC.NameServerMode, "name-server-mode", false, "Treats input as nameservers to query with a static query rather than queries to send to a static name server")
	//rootCmd.PersistentFlags().BoolVar(&GC.DisableFollowCNAMEs, "follow-cnames", true, "Follow CNAMEs/DNAMEs in the lookup process")
	//
	//rootCmd.PersistentFlags().StringVar(&GC.NameServersString, "name-servers", "", "List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53.")
	//rootCmd.PersistentFlags().StringVar(&GC.LocalAddrString, "local-addr", "", "comma-delimited list of local addresses to use, serve as the source IP for outbound queries")
	//rootCmd.PersistentFlags().StringVar(&GC.LocalIfaceString, "local-interface", "", "local interface to use")
	//rootCmd.PersistentFlags().BoolVar(&GC.IPv4TransportOnly, "4", false, "utilize IPv4 query transport only, incompatible with --6")
	//rootCmd.PersistentFlags().BoolVar(&GC.IPv6TransportOnly, "6", false, "utilize IPv6 query transport only, incompatible with --4")
	//rootCmd.PersistentFlags().BoolVar(&GC.PreferIPv4Iteration, "prefer-ipv4-iteration", false, "Prefer IPv4/A record lookups during iterative resolution. Ignored unless used with both IPv4 and IPv6")
	//rootCmd.PersistentFlags().BoolVar(&GC.PreferIPv6Iteration, "prefer-ipv6-iteration", false, "Prefer IPv6/AAAA record lookups during iterative resolution. Ignored unless used with both IPv4 and IPv6")
	//
	//rootCmd.PersistentFlags().StringVar(&GC.ConfigFilePath, "conf-file", zdns.DefaultNameServerConfigFile, "config file for DNS servers")
	//rootCmd.PersistentFlags().IntVar(&GC.Timeout, "timeout", 15, "timeout for resolving a individual name, in seconds")
	//rootCmd.PersistentFlags().IntVar(&GC.IterationTimeout, "iteration-timeout", 4, "timeout for a single iterative step in an iterative query, in seconds. Only applicable with --iterative")
	//rootCmd.PersistentFlags().StringVar(&GC.ClassString, "class", "INET", "DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY.")
	//rootCmd.PersistentFlags().BoolVar(&GC.UseNanoseconds, "nanoseconds", false, "Use nanosecond resolution timestamps")
	//rootCmd.PersistentFlags().StringVar(&GC.ClientSubnetString, "client-subnet", "", "Client subnet in CIDR format for EDNS0.")
	//rootCmd.PersistentFlags().BoolVar(&GC.Dnssec, "dnssec", false, "Requests DNSSEC records by setting the DNSSEC OK (DO) bit")
	//rootCmd.PersistentFlags().BoolVar(&GC.UseNSID, "nsid", false, "Request NSID.")
	//
	//rootCmd.PersistentFlags().Bool("ipv4-lookup", false, "Perform an IPv4 Lookup (requests A records) in modules")
	//rootCmd.PersistentFlags().Bool("ipv6-lookup", false, "Perform an IPv6 Lookup (requests AAAA recoreds) in modules")
	//rootCmd.PersistentFlags().StringVar(&GC.BlacklistFilePath, "blacklist-file", "", "blacklist file for servers to exclude from lookups")
}

//// initConfig reads in config file and ENV variables if set.
//func initConfig() {
//	if cfgFile != "" {
//		// Use config file from the flag.
//		viper.SetConfigFile(cfgFile)
//	} else {
//		// Find home directory.
//		home, err := os.UserHomeDir()
//		cobra.CheckErr(err)
//
//		// Search config in home directory with name ".zdns" (without extension).
//		viper.AddConfigPath(home)
//		viper.SetConfigType("yaml")
//		viper.SetConfigName(".zdns")
//	}
//
//	viper.SetEnvPrefix(util.EnvPrefix)
//	viper.AutomaticEnv()
//
//	// If a config file is found, read it in.
//	if err := viper.ReadInConfig(); err == nil {
//		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
//	}
//	// Bind the current command's flags to viper
//	util.BindFlags(rootCmd, viper.GetViper(), util.EnvPrefix)
//}
