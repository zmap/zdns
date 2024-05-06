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

package axfr

import (
	"github.com/pkg/errors"
	"github.com/zmap/zdns/pkg/cmd"
	"github.com/zmap/zdns/pkg/modules/nslookup"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/zmap/dns"
	"github.com/zmap/go-iptree/blacklist"
	"github.com/zmap/zdns/pkg/zdns"
)

type AxfrLookupModule struct {
	cmd.BasicLookupModule
	NSModule      nslookup.NSLookupModule
	BlacklistPath string
	Blacklist     *blacklist.Blacklist
	BlMu          sync.Mutex
}

type AXFRServerResult struct {
	Server  string `json:"server" groups:"short,normal,long,trace"`
	Status  zdns.Status
	Error   string        `json:"error,omitempty" groups:"short,normal,long,trace"`
	Records []interface{} `json:"records,omitempty" groups:"short,normal,long,trace"`
}

type AXFRResult struct {
	Servers []AXFRServerResult `json:"servers,omitempty" groups:"short,normal,long,trace"`
}

func init() {
	axfr := new(AxfrLookupModule)
	cmd.RegisterLookupModule("AXFR", axfr)
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

type TransferClient struct {
	dns.Transfer
}

func (a *AxfrLookupModule) doAXFR(transfer dns.Transfer, name, server string) AXFRServerResult {
	var retv AXFRServerResult
	retv.Server = server
	// check if the server address is blacklisted and if so, exclude
	if a.Blacklist != nil {
		a.BlMu.Lock()
		if blacklisted, err := a.Blacklist.IsBlacklisted(server); err != nil {
			a.BlMu.Unlock()
			retv.Status = zdns.STATUS_ERROR
			retv.Error = "blacklist-error"
			return retv
		} else if blacklisted {
			a.BlMu.Unlock()
			retv.Status = zdns.STATUS_ERROR
			retv.Error = "blacklisted"
			return retv
		}
		a.BlMu.Unlock()
	}
	m := new(dns.Msg)
	m.SetAxfr(dotName(name))
	if a, err := transfer.In(m, net.JoinHostPort(server, "53")); err != nil {
		retv.Status = zdns.STATUS_ERROR
		retv.Error = err.Error()
		return retv
	} else {
		for ex := range a {
			if ex.Error != nil {
				retv.Status = zdns.STATUS_ERROR
				retv.Error = ex.Error.Error()
				return retv
			} else {
				retv.Status = zdns.STATUS_NOERROR
				for _, rr := range ex.RR {
					ans := zdns.ParseAnswer(rr)
					retv.Records = append(retv.Records, ans)
				}
			}
		}
	}
	return retv
}

func (a *AxfrLookupModule) Lookup(resolver *zdns.Resolver, name, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	var transfer dns.Transfer
	var retv AXFRResult
	if nameServer == "" {
		parsedNS, trace, status, err := a.NSModule.Lookup(resolver, name, nameServer)
		if status != zdns.STATUS_NOERROR {
			return nil, trace, status, err
		}
		castedNS, ok := parsedNS.(nslookup.NSResult)
		if !ok {
			return nil, trace, status, errors.New("failed to cast parsedNS to nslookup.NSResult")
		}
		for _, server := range castedNS.Servers {
			if len(server.IPv4Addresses) > 0 {
				retv.Servers = append(retv.Servers, a.doAXFR(transfer, name, server.IPv4Addresses[0]))
			}
		}
	} else {
		retv.Servers = append(retv.Servers, a.doAXFR(transfer, name, nameServer))
	}
	return retv, nil, zdns.STATUS_NOERROR, nil
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *AxfrLookupModule) Help() string {
	return ""
}

// TODO Phillip - the old code parsed a blacklist and set it as the blacklist. Ensure that we're instantiating the blacklist correctly with just the resolver
func (a *AxfrLookupModule) CLIInit(gc *cmd.CLIConf, rc *zdns.ResolverConfig, flags *pflag.FlagSet) error {
	if gc.IterativeResolution {
		log.Fatal("AXFR module does not support iterative resolution")
	}
	var err error
	a.BlacklistPath, err = flags.GetString("blacklist-file")
	if err != nil {
		return errors.Wrap(err, "failed to get blacklist-file flag")
	}
	if a.BlacklistPath != "" {
		a.Blacklist = blacklist.New()
		if err = a.Blacklist.ParseFromFile(a.BlacklistPath); err != nil {
			return errors.Wrap(err, "failed to parse blacklist")
		}
	}
	a.NSModule.CLIInit(gc, rc, flags)
	if err = a.BasicLookupModule.CLIInit(gc, rc, flags); err != nil {
		return errors.Wrap(err, "failed to initialize basic lookup module")
	}
	return nil
}
