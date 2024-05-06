package spf

import (
	"errors"
	"github.com/spf13/pflag"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/cmd"
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

func (spf *SpfLookupModule) CLIInit(gc *cmd.CLIConf, rc *zdns.ResolverConfig, flags *pflag.FlagSet) error {
	spf.re = regexp.MustCompile(spfPrefixRegexp)
	spf.BasicLookupModule.DNSType = dns.TypeTXT
	spf.BasicLookupModule.DNSClass = dns.ClassINET
	return spf.BasicLookupModule.CLIInit(gc, rc, flags)
}

func (spf *SpfLookupModule) Lookup(r *zdns.Resolver, name, resolver string) (interface{}, zdns.Trace, zdns.Status, error) {
	innerRes, trace, status, err := spf.BasicLookupModule.Lookup(r, name, resolver)
	castedInnerRes, ok := innerRes.(*zdns.SingleQueryResult)
	if !ok {
		return nil, trace, status, errors.New("lookup didn't return a single query result type")
	}
	resString, resStatus, err := zdns.CheckTxtRecords(castedInnerRes, status, spf.re, err)
	res := Result{Spf: resString}
	return res, trace, resStatus, err
}

// Help
func (spf *SpfLookupModule) Help() string {
	return ""
}
