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

// alookupCmd represents the alookup command
var alookupCmd = &cobra.Command{
	Use:   "alookup",
	Short: "A record lookups that follow CNAME records",
	Long: `alookup will get the information that is typically desired, instead of just
the information that exists in a single record.

Specifically, alookup acts similar to nslookup and will follow CNAME records.`,
	Args: cobra.MatchAll(cobra.ExactArgs(0), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		GC.Module = strings.ToUpper("alookup")
		Run(GC, cmd.Flags())
	},
}

func init() {
	rootCmd.AddCommand(alookupCmd)

	alookupCmd.PersistentFlags().Bool("ipv4-lookup", false, "perform A lookups for each server")
	alookupCmd.PersistentFlags().Bool("ipv6-lookup", false, "perform AAAA record lookups for each server")

	util.BindFlags(alookupCmd, viper.GetViper(), util.EnvPrefix)
}
