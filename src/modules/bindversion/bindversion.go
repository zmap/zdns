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

package bindversion

import (
	"github.com/spf13/pflag"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

const (
	BindVersionQueryName = "VERSION.BIND"
)

// result to be returned by scan of host
type Result struct {
	BindVersion string `json:"version,omitempty" groups:"short,normal,long,trace"`
	Resolver    string `json:"resolver" groups:"resolver,short,normal,long,trace"`
}

type BindVersionLookupModule struct {
	cli.BasicLookupModule
}

func init() {
	b := new(BindVersionLookupModule)
	cli.RegisterLookupModule("BINDVERSION", b)
}

// CLIInit initializes the BindVersion lookup module
func (bindVersionMod *BindVersionLookupModule) CLIInit(gc *cli.CLIConf, rc *zdns.ResolverConfig, flags *pflag.FlagSet) error {
	return bindVersionMod.BasicLookupModule.CLIInit(gc, rc, flags)
}

func (bindVersionMod *BindVersionLookupModule) Lookup(r *zdns.Resolver, lookupName, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	var innerRes *zdns.SingleQueryResult
	var trace zdns.Trace
	var status zdns.Status
	var err error
	if bindVersionMod.IsIterative {
		innerRes, trace, status, err = r.IterativeLookup(&zdns.Question{Name: BindVersionQueryName, Type: dns.TypeTXT, Class: dns.ClassCHAOS})
	} else {
		innerRes, trace, status, err = r.ExternalLookup(&zdns.Question{Name: BindVersionQueryName, Type: dns.TypeTXT, Class: dns.ClassCHAOS}, nameServer)
	}
	resString, resStatus, err := zdns.CheckTxtRecords(innerRes, status, nil, err)
	res := Result{BindVersion: resString}
	return res, trace, resStatus, err
}
