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
package spf

import (
	"errors"
	"regexp"

	"github.com/miekg/dns"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

const spfPrefixRegexp = "(?i)^v=spf1"

// result to be returned by scan of host
type Result struct {
	Spf string `json:"spf,omitempty" groups:"short,normal,long,trace"`
}

func init() {
	spf := new(SpfLookupModule)
	cli.RegisterLookupModule("SPF", spf)
}

type SpfLookupModule struct {
	cli.BasicLookupModule
	re *regexp.Regexp
}

// CLIInit initializes the SPF lookup module
func (spfMod *SpfLookupModule) CLIInit(gc *cli.CLIConf, rc *zdns.ResolverConfig) error {
	if gc.LookupAllNameServers {
		return errors.New("SPF module does not support --all-nameservers")
	}
	spfMod.re = regexp.MustCompile(spfPrefixRegexp)
	spfMod.BasicLookupModule.DNSType = dns.TypeTXT
	spfMod.BasicLookupModule.DNSClass = dns.ClassINET
	return spfMod.BasicLookupModule.CLIInit(gc, rc)
}

func (spfMod *SpfLookupModule) Lookup(r *zdns.Resolver, name string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error) {
	innerRes, trace, status, err := spfMod.BasicLookupModule.Lookup(r, name, nameServer)
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

// Validate
func (spfMod *SpfLookupModule) Validate(args []string) error {
	return nil
}

// Description
func (spfMod *SpfLookupModule) GetDescription() string {
	return ""
}

func (spfMod *SpfLookupModule) NewFlags() interface{} {
	return spfMod
}
