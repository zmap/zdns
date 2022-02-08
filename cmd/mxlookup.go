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
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zmap/zdns/internal/util"
	"github.com/zmap/zdns/pkg/zdns"
)

// mxlookupCmd represents the mxlookup command
var mxlookupCmd = &cobra.Command{
	Use:   "mxlookup",
	Short: "Run a more exhaustive mxlookup",
	Long: `mxlookup will additionally do an A lookup for the IP addresses that
correspond with an exchange record.`,
	Run: func(cmd *cobra.Command, args []string) {
		Run.GlobalConf.Module = strings.ToUpper("mxlookup")
		zdns.Run(Run)
	},
}

func init() {
	rootCmd.AddCommand(mxlookupCmd)

	mxlookupCmd.PersistentFlags().BoolVar(&Run.ModuleFlags.Ipv4Lookup, "ipv4-lookup", false, "Perform an IPv4 Lookup in modules")
	mxlookupCmd.PersistentFlags().BoolVar(&Run.ModuleFlags.Ipv6Lookup, "ipv6-lookup", false, "Perform an IPv6 Lookup in modules")
	mxlookupCmd.PersistentFlags().IntVar(&Run.ModuleFlags.MxCacheSize, "mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")

	util.BindFlags(mxlookupCmd, viper.GetViper(), util.EnvPrefix)
}
