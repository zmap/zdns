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
package dmarc

import (
	"errors"
	"regexp"

	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

const dmarcPrefixRegexp = "^[vV][\x09\x20]*=[\x09\x20]*DMARC1[\x09\x20]*;[\x09\x20]*"

// result to be returned by scan of host
type Result struct {
	Dmarc string `json:"dmarc,omitempty" groups:"short,normal,long,trace"`
}

func init() {
	dmarc := new(DmarcLookupModule)
	cli.RegisterLookupModule("DMARC", dmarc)
}

type DmarcLookupModule struct {
	cli.BasicLookupModule
	re *regexp.Regexp
}

// CLIInit initializes the DMARC lookup module
func (dmarcMod *DmarcLookupModule) CLIInit(gc *cli.CLIConf, rc *zdns.ResolverConfig) error {
	dmarcMod.re = regexp.MustCompile(dmarcPrefixRegexp)
	dmarcMod.BasicLookupModule.DNSType = dns.TypeTXT
	dmarcMod.BasicLookupModule.DNSClass = dns.ClassINET
	return dmarcMod.BasicLookupModule.CLIInit(gc, rc)
}

func (dmarcMod *DmarcLookupModule) Lookup(r *zdns.Resolver, lookupName string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error) {
	innerRes, trace, status, err := dmarcMod.BasicLookupModule.Lookup(r, lookupName, nameServer)
	castedInnerRes, ok := innerRes.(*zdns.SingleQueryResult)
	if !ok {
		return nil, trace, status, errors.New("lookup didn't return a single query result type")
	}
	resString, resStatus, err := zdns.CheckTxtRecords(castedInnerRes, status, dmarcMod.re, err)
	res := Result{Dmarc: resString}
	return res, trace, resStatus, err
}

func (dmarcMod *DmarcLookupModule) Help() string {
	return ""
}

func (dmarcMod *DmarcLookupModule) Validate(args []string) error {
	return nil
}

func (dmarcMod *DmarcLookupModule) GetDescription() string {
	return ""
}

func (dmarcMod *DmarcLookupModule) NewFlags() interface{} {
	return dmarcMod
}
