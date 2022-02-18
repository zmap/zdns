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
		GC.Module = strings.ToUpper("alookup")
		zdns.Run(GC, cmd.Flags(),
			&Timeout, &IterationTimeout,
			&Class_string, &Servers_string,
			&Config_file, &Localaddr_string,
			&Localif_string, &NanoSeconds)
	},
}

func init() {
	rootCmd.AddCommand(alookupCmd)

	alookupCmd.PersistentFlags().Bool("ipv4-lookup", false, "perform A lookups for each MX server")
	alookupCmd.PersistentFlags().Bool("ipv6-lookup", false, "perform AAAA record lookups for each MX server")

	util.BindFlags(alookupCmd, viper.GetViper(), util.EnvPrefix)
}
