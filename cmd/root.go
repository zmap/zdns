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
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zmap/zdns/internal/util"
	"github.com/zmap/zdns/pkg/zdns"
)

var cfgFile string
var GC zdns.GlobalConf

// TODO: these options may need to be set as flags or in GC, to standardize.
var (
	Servers_string      string
	Localaddr_string    string
	Localif_string      string
	Config_file         string
	Timeout             int
	IterationTimeout    int
	Class_string        string
	NanoSeconds         bool
	ClientSubnet_string string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "zdns",
	Short: "High-speed, low-drag DNS lookups",
	Long: `ZDNS is a library and CLI tool for making very fast DNS requests. It's built upon
https://github.com/zmap/dns (and in turn https://github.com/miekg/dns) for constructing
and parsing raw DNS packets.

ZDNS also includes its own recursive resolution and a cache to further optimize performance.`,
	ValidArgs: zdns.Validlookups(),
	Args:      cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		GC.Module = strings.ToUpper(args[0])
		zdns.Run(GC, cmd.Flags(),
			&Timeout, &IterationTimeout,
			&Class_string, &Servers_string,
			&Config_file, &Localaddr_string,
			&Localif_string, &NanoSeconds, &ClientSubnet_string)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.zdns.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().IntVar(&GC.Threads, "threads", 1000, "number of lightweight go threads")
	rootCmd.PersistentFlags().IntVar(&GC.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	rootCmd.PersistentFlags().StringVar(&GC.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	rootCmd.PersistentFlags().StringVar(&GC.NameOverride, "override-name", "", "name overrides all passed in names")
	rootCmd.PersistentFlags().BoolVar(&GC.AlexaFormat, "alexa", false, "is input file from Alexa Top Million download")
	rootCmd.PersistentFlags().BoolVar(&GC.MetadataFormat, "metadata-passthrough", false, "if input records have the form 'name,METADATA', METADATA will be propagated to the output")
	rootCmd.PersistentFlags().BoolVar(&GC.IterativeResolution, "iterative", false, "Perform own iteration instead of relying on recursive resolver")
	rootCmd.PersistentFlags().BoolVar(&GC.LookupAllNameServers, "all-nameservers", false, "Perform the lookup via all the nameservers for the domain.")
	rootCmd.PersistentFlags().StringVar(&GC.InputFilePath, "input-file", "-", "names to read")
	rootCmd.PersistentFlags().StringVar(&GC.OutputFilePath, "output-file", "-", "where should JSON output be saved")
	rootCmd.PersistentFlags().StringVar(&GC.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	rootCmd.PersistentFlags().StringVar(&GC.LogFilePath, "log-file", "", "where should JSON logs be saved")

	rootCmd.PersistentFlags().StringVar(&GC.ResultVerbosity, "result-verbosity", "normal", "Sets verbosity of each output record. Options: short, normal, long, trace")
	rootCmd.PersistentFlags().StringVar(&GC.IncludeInOutput, "include-fields", "", "Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags")

	rootCmd.PersistentFlags().IntVar(&GC.Verbosity, "verbosity", 3, "log verbosity: 1 (lowest)--5 (highest)")
	rootCmd.PersistentFlags().IntVar(&GC.Retries, "retries", 1, "how many times should zdns retry query if timeout or temporary failure")
	rootCmd.PersistentFlags().IntVar(&GC.MaxDepth, "max-depth", 10, "how deep should we recurse when performing iterative lookups")
	rootCmd.PersistentFlags().IntVar(&GC.CacheSize, "cache-size", 10000, "how many items can be stored in internal recursive cache")
	rootCmd.PersistentFlags().BoolVar(&GC.TCPOnly, "tcp-only", false, "Only perform lookups over TCP")
	rootCmd.PersistentFlags().BoolVar(&GC.UDPOnly, "udp-only", false, "Only perform lookups over UDP")
	rootCmd.PersistentFlags().BoolVar(&GC.CheckingDisabled, "checking-disabled", false, "Sends DNS packets with the CD bit set")
	rootCmd.PersistentFlags().BoolVar(&GC.RecycleSockets, "recycle-sockets", true, "Create long-lived unbound UDP socket for each thread at launch and reuse for all (UDP) queries")
	rootCmd.PersistentFlags().BoolVar(&GC.NameServerMode, "name-server-mode", false, "Treats input as nameservers to query with a static query rather than queries to send to a static name server")

	rootCmd.PersistentFlags().StringVar(&Servers_string, "name-servers", "", "List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53.")
	rootCmd.PersistentFlags().StringVar(&Localaddr_string, "local-addr", "", "comma-delimited list of local addresses to use")
	rootCmd.PersistentFlags().StringVar(&Localif_string, "local-interface", "", "local interface to use")
	rootCmd.PersistentFlags().StringVar(&Config_file, "conf-file", "/etc/resolv.conf", "config file for DNS servers")
	rootCmd.PersistentFlags().IntVar(&Timeout, "timeout", 15, "timeout for resolving an individual name")
	rootCmd.PersistentFlags().IntVar(&IterationTimeout, "iteration-timeout", 4, "timeout for resolving a single iteration in an iterative query")
	rootCmd.PersistentFlags().StringVar(&Class_string, "class", "INET", "DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY. Default: INET.")
	rootCmd.PersistentFlags().BoolVar(&NanoSeconds, "nanoseconds", false, "Use nanosecond resolution timestamps")
	rootCmd.PersistentFlags().StringVar(&ClientSubnet_string, "client-subnet", "", "Client subnet in CIDR format for EDNS0.")
	rootCmd.PersistentFlags().BoolVar(&GC.Dnssec, "dnssec", false, "Requests DNSSEC records by setting the DNSSEC OK (DO) bit")

	rootCmd.PersistentFlags().Bool("ipv4-lookup", false, "Perform an IPv4 Lookup in modules")
	rootCmd.PersistentFlags().Bool("ipv6-lookup", false, "Perform an IPv6 Lookup in modules")
	rootCmd.PersistentFlags().String("blacklist-file", "", "blacklist file for servers to exclude from lookups")
	rootCmd.PersistentFlags().Int("mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".zdns" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".zdns")
	}

	viper.SetEnvPrefix(util.EnvPrefix)
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
	// Bind the current command's flags to viper
	util.BindFlags(rootCmd, viper.GetViper(), util.EnvPrefix)
}
