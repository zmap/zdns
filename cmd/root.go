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
var Run zdns.ZdnsRun

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "zdns",
	Short: "High-speed, low-drag DNS lookups",
	Long: `ZDNS is a library and CLI tool for making very fast DNS requests. It's built upon
https://github.com/zmap/dns (and in turn https://github.com/miekg/dns) for constructing
and parsing raw DNS packets. 

ZDNS also includes its own recursive resolution and a cache to further optimize performance.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			// Needs at least one arg
			return fmt.Errorf("at least one lookup module must be specified. valid modules: %s", zdns.ValidlookupsString())
		} else if len(args) == 1 && zdns.Validlookups()[strings.ToUpper(args[0])] {
			// In the case we have only one argument, it should be specifying the lookup module
			return nil
		} else if len(args) == 2 && zdns.Validlookups()[strings.ToUpper(args[0])] {
			// In the case we have two args, the first should be the module and the second should be a dns name.
			// TODO (spencer): consider adding a DNS name verification regex here.
			return nil
		}
		// Return an error otherwise
		return fmt.Errorf("usage: zdns module [dig-like dns name]. valid modules: %s", zdns.ValidlookupsString())
	},
	Run: func(cmd *cobra.Command, args []string) {
		Run.GlobalConf.Module = strings.ToUpper(args[0])
		if len(args) == 2 {
			Run.GlobalConf.PassedName = args[1]
		}
		zdns.Run(Run)
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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.zdns.yaml)")

	// Global Configuration, available to all goroutines running ZDNS
	rootCmd.PersistentFlags().IntVar(&Run.GlobalConf.Threads, "threads", 1000, "number of lightweight go threads")
	rootCmd.PersistentFlags().IntVar(&Run.GlobalConf.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.NameOverride, "override-name", "", "name overrides all passed in names")
	rootCmd.PersistentFlags().BoolVar(&Run.GlobalConf.AlexaFormat, "alexa", false, "is input file from Alexa Top Million download")
	rootCmd.PersistentFlags().BoolVar(&Run.GlobalConf.MetadataFormat, "metadata-passthrough", false, "if input records have the form 'name,METADATA', METADATA will be propagated to the output")
	rootCmd.PersistentFlags().BoolVar(&Run.GlobalConf.IterativeResolution, "iterative", false, "Perform own iteration instead of relying on recursive resolver")
	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.InputFilePath, "input-file", "-", "names to read")
	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.OutputFilePath, "output-file", "-", "where should JSON output be saved")
	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.LogFilePath, "log-file", "", "where should JSON logs be saved")

	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.ResultVerbosity, "result-verbosity", "normal", "Sets verbosity of each output record. Options: short, normal, long, trace")
	rootCmd.PersistentFlags().StringVar(&Run.GlobalConf.IncludeInOutput, "include-fields", "", "Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags")

	rootCmd.PersistentFlags().IntVar(&Run.GlobalConf.Verbosity, "verbosity", 3, "log verbosity: 1 (lowest)--5 (highest)")
	rootCmd.PersistentFlags().IntVar(&Run.GlobalConf.Retries, "retries", 1, "how many times should zdns retry query if timeout or temporary failure")
	rootCmd.PersistentFlags().IntVar(&Run.GlobalConf.MaxDepth, "max-depth", 10, "how deep should we recurse when performing iterative lookups")
	rootCmd.PersistentFlags().IntVar(&Run.GlobalConf.CacheSize, "cache-size", 10000, "how many items can be stored in internal recursive cache")
	rootCmd.PersistentFlags().BoolVar(&Run.GlobalConf.TCPOnly, "tcp-only", false, "Only perform lookups over TCP")
	rootCmd.PersistentFlags().BoolVar(&Run.GlobalConf.UDPOnly, "udp-only", false, "Only perform lookups over UDP")
	rootCmd.PersistentFlags().BoolVar(&Run.GlobalConf.NameServerMode, "name-server-mode", false, "Treats input as nameservers to query with a static query rather than queries to send to a static name server")

	// Run-specific conf, not directly passed to goroutines
	rootCmd.PersistentFlags().StringVar(&Run.Servers, "name-servers", "", "List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53.")
	rootCmd.PersistentFlags().StringVar(&Run.LocalAddr, "local-addr", "", "comma-delimited list of local addresses to use")
	rootCmd.PersistentFlags().StringVar(&Run.LocalIF, "local-interface", "", "local interface to use")
	rootCmd.PersistentFlags().StringVar(&Run.ConfigFile, "conf-file", "/etc/resolv.conf", "config file for DNS servers")
	rootCmd.PersistentFlags().IntVar(&Run.Timeout, "timeout", 15, "timeout for resolving an individual name")
	rootCmd.PersistentFlags().IntVar(&Run.IterationTimeout, "iteration-timeout", 4, "timeout for resolving a single iteration in an iterative query")
	rootCmd.PersistentFlags().StringVar(&Run.Class, "class", "INET", "DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY. Default: INET.")
	rootCmd.PersistentFlags().BoolVar(&Run.NanoSeconds, "nanoseconds", false, "Use nanosecond resolution timestamps")

	// Module-specific flags.
	rootCmd.PersistentFlags().BoolVar(&Run.ModuleFlags.Ipv4Lookup, "ipv4-lookup", false, "Perform an IPv4 Lookup in modules")
	rootCmd.PersistentFlags().BoolVar(&Run.ModuleFlags.Ipv6Lookup, "ipv6-lookup", false, "Perform an IPv6 Lookup in modules")
	rootCmd.PersistentFlags().StringVar(&Run.ModuleFlags.BlacklistFile, "blacklist-file", "", "blacklist file for servers to exclude from lookups")
	rootCmd.PersistentFlags().IntVar(&Run.ModuleFlags.MxCacheSize, "mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")

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
