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
		GC.Module = strings.ToUpper("mxlookup")
		zdns.Run(GC, cmd.Flags(),
			&Timeout, &IterationTimeout,
			&Class_string, &Servers_string,
			&Config_file, &Localaddr_string,
			&Localif_string, &NanoSeconds, &ClientSubnet_string)
	},
}

func init() {
	rootCmd.AddCommand(mxlookupCmd)

	mxlookupCmd.PersistentFlags().Bool("ipv4-lookup", false, "perform A lookups for each MX server")
	mxlookupCmd.PersistentFlags().Bool("ipv6-lookup", false, "perform AAAA record lookups for each MX server")
	mxlookupCmd.PersistentFlags().Int("mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")

	util.BindFlags(mxlookupCmd, viper.GetViper(), util.EnvPrefix)
}
