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

package nslookup

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

func init() {
	ns := new(NSLookupModule)
	cli.RegisterLookupModule("NSLOOKUP", ns)
}

type NSLookupModule struct {
	cli.BasicLookupModule
	IPv4Lookup bool `long:"ipv4-lookup" description:"perform A lookups for each NS server"`
	IPv6Lookup bool `long:"ipv6-lookup" description:"perform AAAA record lookups for each NS server"`
	// used for mocking
	testingLookup func(r *zdns.Resolver, lookupName string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error)
}

// CLIInit initializes the NSLookupModule with the given parameters, used to call NSLookup from the command line
func (nsMod *NSLookupModule) CLIInit(gc *cli.CLIConf, resolverConf *zdns.ResolverConfig) error {
	if gc.LookupAllNameServers {
		return errors.New("NSLOOKUP module does not support --all-nameservers")
	}
	if !nsMod.IPv4Lookup && !nsMod.IPv6Lookup {
		log.Debug("NSModule: neither --ipv4-lookup nor --ipv6-lookup specified, will only request A records for each NS server")
		nsMod.IPv4Lookup = true
	}
	err := nsMod.BasicLookupModule.CLIInit(gc, resolverConf)
	if err != nil {
		return errors.Wrap(err, "failed to initialize basic lookup module")
	}
	nsMod.Init(nsMod.IPv4Lookup, nsMod.IPv6Lookup)
	return nil
}

// Init initializes the NSLookupModule with the given parameters, used to call NSLookup programmatically
func (nsMod *NSLookupModule) Init(ipv4Lookup, ipv6Lookup bool) {
	nsMod.IPv4Lookup = ipv4Lookup || !ipv6Lookup
	nsMod.IPv6Lookup = ipv6Lookup
}

func (nsMod *NSLookupModule) Lookup(r *zdns.Resolver, lookupName string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error) {
	if nsMod.testingLookup != nil {
		// used for mocking
		return nsMod.testingLookup(r, lookupName, nameServer)
	}
	if nsMod.IsIterative && nameServer != nil {
		log.Warn("iterative lookup requested with lookupName server, ignoring lookupName server")
	}

	res, trace, status, err := r.DoNSLookup(lookupName, nameServer, nsMod.IsIterative, nsMod.IPv4Lookup, nsMod.IPv6Lookup)
	if trace == nil {
		trace = zdns.Trace{}
	}
	return res, trace, status, err
}

// Help returns the module's help string
func (nsMod *NSLookupModule) Help() string {
	return ""
}

func (nsMod *NSLookupModule) Validate(args []string) error {
	return nil
}

func (nsMod *NSLookupModule) WithTestingLookup(f func(r *zdns.Resolver, lookupName string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error)) {
	nsMod.testingLookup = f
}

func (nsMod *NSLookupModule) GetDescription() string {
	return "Run a more exhaustive ns lookup, will additionally do an A/AAAA lookup for the IP addresses that correspond with name server records."
}

func (nsMod *NSLookupModule) NewFlags() interface{} {
	return nsMod
}
