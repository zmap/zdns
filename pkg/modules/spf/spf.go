package spf

import (
	"errors"
	"github.com/spf13/pflag"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/cmd"
	"github.com/zmap/zdns/pkg/zdns"
	"regexp"
)

const spfPrefixRegexp = "(?i)^v=spf1"

// result to be returned by scan of host
type Result struct {
	Spf string `json:"spf,omitempty" groups:"short,normal,long,trace"`
}

func init() {
	spf := new(SpfLookupModule)
	cmd.RegisterLookupModule("SPF", spf)
}

type SpfLookupModule struct {
	cmd.BasicLookupModule
	re *regexp.Regexp
}

func (spfMod *SpfLookupModule) CLIInit(gc *cmd.CLIConf, rc *zdns.ResolverConfig, flags *pflag.FlagSet) error {
	spfMod.re = regexp.MustCompile(spfPrefixRegexp)
	spfMod.BasicLookupModule.DNSType = dns.TypeTXT
	spfMod.BasicLookupModule.DNSClass = dns.ClassINET
	return spfMod.BasicLookupModule.CLIInit(gc, rc, flags)
}

func (spfMod *SpfLookupModule) Lookup(r *zdns.Resolver, name, resolver string) (interface{}, zdns.Trace, zdns.Status, error) {
	innerRes, trace, status, err := spfMod.BasicLookupModule.Lookup(r, name, resolver)
	castedInnerRes, ok := innerRes.(*zdns.SingleQueryResult)
	if !ok {
		return nil, trace, status, errors.New("lookup didn't return a single query result type")
	}
	resString, resStatus, err := zdns.CheckTxtRecords(castedInnerRes, status, spfMod.re, err)
	res := Result{Spf: resString}
	return res, trace, resStatus, err
}

// Help
func (spfMod *SpfLookupModule) Help() string {
	return ""
}
