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

// alookupCmd represents the alookup command
var alookupCmd = &cobra.Command{
	Use:   "alookup",
	Short: "A record lookups that follow CNAME records",
	Long: `alookup will get the information that is typically desired, instead of just
the information that exists in a single record.

Specifically, alookup acts similar to nslookup and will follow CNAME records.`,
	Run: func(cmd *cobra.Command, args []string) {
		Run.GlobalConf.Module = strings.ToUpper("alookup")
		zdns.Run(Run)
	},
}

func init() {
	rootCmd.AddCommand(alookupCmd)

	alookupCmd.PersistentFlags().BoolVar(&Run.ModuleFlags.Ipv4Lookup, "ipv4-lookup", false, "Perform an IPv4 Lookup in modules")
	alookupCmd.PersistentFlags().BoolVar(&Run.ModuleFlags.Ipv6Lookup, "ipv6-lookup", false, "Perform an IPv6 Lookup in modules")

	util.BindFlags(alookupCmd, viper.GetViper(), util.EnvPrefix)
}
