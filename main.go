/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package main

import (
	"github.com/zmap/zdns/cmd"
	_ "github.com/zmap/zdns/pkg/alookup"
	_ "github.com/zmap/zdns/pkg/axfr"
	_ "github.com/zmap/zdns/pkg/bindversion"
	_ "github.com/zmap/zdns/pkg/dmarc"
	_ "github.com/zmap/zdns/pkg/miekg"
	_ "github.com/zmap/zdns/pkg/mxlookup"
	_ "github.com/zmap/zdns/pkg/nslookup"
	_ "github.com/zmap/zdns/pkg/spf"
)

func main() {
	cmd.Execute()
}
