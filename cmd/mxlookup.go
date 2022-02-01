/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

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
		//TODO: don't think these params exist.
		zdns.Run(GC, cmd.Flags(),
			&Timeout, &IterationTimeout,
			&Class_string, &Servers_string,
			&Config_file, &Localaddr_string,
			&Localif_string, &NanoSeconds)
	},
}

func init() {
	rootCmd.AddCommand(mxlookupCmd)

	mxlookupCmd.PersistentFlags().Bool("ipv4-lookup", false, "perform A lookups for each MX server")
	mxlookupCmd.PersistentFlags().Bool("ipv6-lookup", false, "perform AAAA record lookups for each MX server")
	mxlookupCmd.PersistentFlags().Int("mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")

	util.BindFlags(mxlookupCmd, viper.GetViper(), util.EnvPrefix)
}
