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
		gc.Module = strings.ToUpper("mxlookup")
		zdns.Run(gc, cmd.Flags(),
			&timeout, &iterationTimeout,
			&class_string, &servers_string,
			&config_file, &localaddr_string,
			&localif_string, &nanoSeconds)
	},
}

func init() {
	rootCmd.AddCommand(mxlookupCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// mxlookupCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// mxlookupCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	mxlookupCmd.PersistentFlags().Bool("ipv4-lookup", false, "perform A lookups for each MX server")
	mxlookupCmd.PersistentFlags().Bool("ipv6-lookup", false, "perform AAAA record lookups for each MX server")
	mxlookupCmd.PersistentFlags().Int("mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")

	util.BindFlags(mxlookupCmd, viper.GetViper(), util.EnvPrefix)
}
