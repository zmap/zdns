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
	"github.com/spf13/pflag"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

func init() {
	ns := new(NSLookupModule)
	cli.RegisterLookupModule("NSLOOKUP", ns)
}

type NSLookupModule struct {
	cli.BasicLookupModule
	IPv4Lookup bool
	IPv6Lookup bool
	// used for mocking
	testingLookup func(r *zdns.Resolver, lookupName string, nameServer string) (interface{}, zdns.Trace, zdns.Status, error)
}

// CLIInit initializes the NSLookupModule with the given parameters, used to call NSLookup from the command line
func (nsMod *NSLookupModule) CLIInit(gc *cli.CLIConf, resolverConf *zdns.ResolverConfig, f *pflag.FlagSet) error {
	ipv4Lookup, err := f.GetBool("ipv4-lookup")
	if err != nil {
		return errors.Wrap(err, "failed to get ipv4-lookup flag")
	}
	ipv6Lookup, err := f.GetBool("ipv6-lookup")
	if err != nil {
		return errors.Wrap(err, "failed to get ipv6-lookup flag")
	}
	if !ipv4Lookup && !ipv6Lookup {
		log.Debug("NSModule: No IP version specified, defaulting to IPv4")
		ipv4Lookup = true
	}
	err = nsMod.BasicLookupModule.CLIInit(gc, resolverConf, f)
	if err != nil {
		return errors.Wrap(err, "failed to initialize basic lookup module")
	}
	nsMod.Init(ipv4Lookup, ipv6Lookup)
	return nil
}

// Init initializes the NSLookupModule with the given parameters, used to call NSLookup programmatically
func (nsMod *NSLookupModule) Init(ipv4Lookup, ipv6Lookup bool) {
	nsMod.IPv4Lookup = ipv4Lookup || !ipv6Lookup
	nsMod.IPv6Lookup = ipv6Lookup
}

func (nsMod *NSLookupModule) Lookup(r *zdns.Resolver, lookupName string, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if nsMod.testingLookup != nil {
		// used for mocking
		return nsMod.testingLookup(r, lookupName, nameServer)
	}
	if nsMod.IsIterative && nameServer != "" {
		log.Warn("iterative lookup requested with lookupName server, ignoring lookupName server")
	}

	res, trace, status, err := r.DoNSLookup(lookupName, nameServer, nsMod.IsIterative)
	if trace == nil {
		trace = zdns.Trace{}
	}
	return res, trace, status, err
}

// Help returns the module's help string
func (nsMod *NSLookupModule) Help() string {
	return ""
}

func (nsMod *NSLookupModule) WithTestingLookup(f func(r *zdns.Resolver, lookupName string, nameServer string) (interface{}, zdns.Trace, zdns.Status, error)) {
	nsMod.testingLookup = f
}
