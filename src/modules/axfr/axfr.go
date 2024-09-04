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
	"net"
	"strings"

	"github.com/pkg/errors"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/internal/safeblacklist"
	"github.com/zmap/zdns/src/modules/nslookup"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/zdns"
)

type AxfrLookupModule struct {
	cli.BasicLookupModule
	NSModule      nslookup.NSLookupModule
	BlacklistPath string `long:"blacklist-file" description:"path to blacklist file" default:""`
	Blacklist     *safeblacklist.SafeBlacklist
	dns.Transfer
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
	cli.RegisterLookupModule("AXFR", axfr)
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

type TransferClient struct {
	dns.Transfer
}

func (axfrMod *AxfrLookupModule) doAXFR(name string, server *zdns.NameServer) AXFRServerResult {
	var retv AXFRServerResult
	retv.Server = server.IP.String()
	// check if the server address is blacklisted and if so, exclude
	if axfrMod.Blacklist != nil {
		if blacklisted, err := axfrMod.Blacklist.IsBlacklisted(server.IP.String()); err != nil {
			retv.Status = zdns.StatusError
			retv.Error = "blacklist-error"
			return retv
		} else if blacklisted {
			retv.Status = zdns.StatusError
			retv.Error = "blacklisted"
			return retv
		}
	}
	m := new(dns.Msg)
	m.SetAxfr(dotName(name))
	if a, err := axfrMod.In(m, net.JoinHostPort(server.IP.String(), "53")); err != nil {
		retv.Status = zdns.StatusError
		retv.Error = err.Error()
		return retv
	} else {
		for ex := range a {
			if ex.Error != nil {
				retv.Status = zdns.StatusError
				retv.Error = ex.Error.Error()
				return retv
			} else {
				retv.Status = zdns.StatusNoError
				for _, rr := range ex.RR {
					ans := zdns.ParseAnswer(rr)
					retv.Records = append(retv.Records, ans)
				}
			}
		}
	}
	return retv
}

func (axfrMod *AxfrLookupModule) Lookup(resolver *zdns.Resolver, name string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error) {
	var retv AXFRResult
	if nameServer == nil {
		parsedNS, trace, status, err := axfrMod.NSModule.Lookup(resolver, name, nameServer)
		if status != zdns.StatusNoError {
			return nil, trace, status, err
		}
		castedNS, ok := parsedNS.(*zdns.NSResult)
		if !ok {
			return nil, trace, status, errors.New("failed to cast parsedNS to zdns.NSResult")
		}
		for _, server := range castedNS.Servers {
			if len(server.IPv4Addresses) > 0 {
				ns := &zdns.NameServer{IP: net.ParseIP(server.IPv4Addresses[0])}
				retv.Servers = append(retv.Servers, axfrMod.doAXFR(name, ns))
			}
		}
	} else {
		retv.Servers = append(retv.Servers, axfrMod.doAXFR(name, nameServer))
	}
	return retv, nil, zdns.StatusNoError, nil
}

func (axfrMod *AxfrLookupModule) Help() string {
	return ""
}

func (axfrMod *AxfrLookupModule) Validate(args []string) error {
	return nil
}

func (axfrMod *AxfrLookupModule) NewFlags() interface{} {
	return axfrMod
}

func (axfrMod *AxfrLookupModule) GetDescription() string {
	return ""
}

// CLIInit initializes the AxfrLookupModule with the given parameters, used to call AXFR from the command line
func (axfrMod *AxfrLookupModule) CLIInit(gc *cli.CLIConf, rc *zdns.ResolverConfig) error {
	if gc == nil {
		return errors.New("CLIConfig is nil")
	}
	if rc == nil {
		return errors.New("ResolverConfig is nil")
	}
	if gc.IterativeResolution {
		log.Fatal("AXFR module does not support iterative resolution")
	}
	var err error
	if axfrMod.BlacklistPath != "" {
		axfrMod.Blacklist = safeblacklist.New()
		if err = axfrMod.Blacklist.ParseFromFile(axfrMod.BlacklistPath); err != nil {
			return errors.Wrap(err, "failed to parse blacklist")
		}
	}
	err = axfrMod.NSModule.CLIInit(gc, rc)
	if err != nil {
		return errors.Wrap(err, "failed to initialize NSLookupModule as apart of axfrModule")
	}
	if err = axfrMod.BasicLookupModule.CLIInit(gc, rc); err != nil {
		return errors.Wrap(err, "failed to initialize basic lookup module")
	}
	return nil
}
