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

package alookup

import (
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/zmap/zdns/cmd"
	"github.com/zmap/zdns/pkg/zdns"
)

type ALookupModule struct {
	IPv4Lookup bool
	IPv6Lookup bool
	baseModule cmd.BasicLookupModule
}

func init() {
	al := new(ALookupModule)
	cmd.RegisterLookupModule("ALOOKUP", al)
}

func (aMod *ALookupModule) CLIInit(gc *cmd.CLIConf, resolverConfig *zdns.ResolverConfig, f *pflag.FlagSet) error {
	ipv4Lookup, err := f.GetBool("ipv4-lookup")
	if err != nil {
		panic(err)
	}
	ipv6Lookup, err := f.GetBool("ipv6-lookup")
	if err != nil {
		panic(err)
	}
	aMod.Init(ipv4Lookup, ipv6Lookup)
	err = aMod.baseModule.CLIInit(gc, resolverConfig, f)
	if err != nil {
		return errors.Wrap(err, "failed to initialize base module")
	}
	return nil
}

func (aMod *ALookupModule) Init(ipv4Lookup bool, ipv6Lookup bool) {
	aMod.IPv4Lookup = ipv4Lookup || !ipv6Lookup
	aMod.IPv6Lookup = ipv6Lookup
}

func (aMod *ALookupModule) Lookup(r *zdns.Resolver, lookupName, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	ipResult, trace, status, err := r.DoTargetedLookup(lookupName, nameServer, zdns.GetIPVersionMode(aMod.IPv4Lookup, aMod.IPv6Lookup), aMod.baseModule.IsIterative)
	return ipResult, trace, status, err
}

// Help returns the module's help string
func (aMod *ALookupModule) Help() string {
	return ""
}
