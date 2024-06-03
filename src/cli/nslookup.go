/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
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
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zmap/zdns/src/internal/util"
)

// nslookupCmd represents the nslookup command
var nslookupCmd = &cobra.Command{
	Use:   "nslookup",
	Short: "Run a more exhaustive nslookup",
	Long:  `nslookup will additionally do an A/AAAA lookup for the IP addresses that correspond with name server records.`,
	Run: func(cmd *cobra.Command, args []string) {
		GC.Module = strings.ToUpper("nslookup")
		Run(GC, cmd.Flags())
	},
}

func init() {
	rootCmd.AddCommand(nslookupCmd)

	nslookupCmd.PersistentFlags().Bool("ipv4-lookup", false, "perform A lookups for each NS server")
	nslookupCmd.PersistentFlags().Bool("ipv6-lookup", false, "perform AAAA record lookups for each NS server")

	util.BindFlags(nslookupCmd, viper.GetViper(), util.EnvPrefix)
}
