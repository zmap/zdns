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

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

type ALookupModule struct {
	IPv4Lookup bool `long:"ipv4-lookup" description:"perform A lookups for each server"`
	IPv6Lookup bool `long:"ipv6-lookup" description:"perform AAAA lookups for each server"`
	baseModule cli.BasicLookupModule
}

func init() {
	al := new(ALookupModule)
	cli.RegisterLookupModule("ALOOKUP", al)
}

// CLIInit initializes the ALookupModule with the given parameters, used to call ALOOKUP from the command line
func (aMod *ALookupModule) CLIInit(gc *cli.CLIConf, resolverConfig *zdns.ResolverConfig) error {
	if gc.LookupAllNameServers {
		return errors.New("ALOOKUP module does not support --all-nameservers")
	}
	aMod.Init(aMod.IPv4Lookup, aMod.IPv6Lookup)
	err := aMod.baseModule.CLIInit(gc, resolverConfig)
	if err != nil {
		return errors.Wrap(err, "failed to initialize base module")
	}
	return nil
}

// Init initializes the ALookupModule with the given parameters, used to call ALOOKUP programmatically
func (aMod *ALookupModule) Init(ipv4Lookup bool, ipv6Lookup bool) {
	aMod.IPv4Lookup = ipv4Lookup || !ipv6Lookup
	aMod.IPv6Lookup = ipv6Lookup
}

func (aMod *ALookupModule) Lookup(r *zdns.Resolver, lookupName string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error) {
	ipResult, trace, status, err := r.DoTargetedLookup(lookupName, nameServer, aMod.baseModule.IsIterative, aMod.IPv4Lookup, aMod.IPv6Lookup)
	return ipResult, trace, status, err
}

func (aMod *ALookupModule) Help() string {
	return ""
}

func (aMod *ALookupModule) Validate(args []string) error {
	return nil
}

func (aMod *ALookupModule) NewFlags() interface{} {
	return aMod
}

func (aMod *ALookupModule) GetDescription() string {
	return "alookup will get the information that is typically desired, instead of just the information that exists in a single record. Specifically, alookup acts similar to nslookup and will follow CNAME records."
}
