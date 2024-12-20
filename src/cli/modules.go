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
package cli

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zdns/src/zdns"
)

type LookupModule interface {
	CLIInit(gc *CLIConf, rc *zdns.ResolverConfig) error
	Lookup(resolver *zdns.Resolver, lookupName string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error)
	Help() string                 // needed to satisfy the ZCommander interface in ZFlags.
	GetDescription() string       // needed to add a command to the parser, printed to the user. Printed to the user when they run the help command for a given module
	Validate(args []string) error // needed to satisfy the ZCommander interface in ZFlags
	NewFlags() interface{}        // needed to satisfy the ZModule interface in ZFlags
}

const (
	BINDVERSION = "BINDVERSION"
)

var moduleToLookupModule map[string]LookupModule

func init() {
	moduleToLookupModule = map[string]LookupModule{}

	RegisterLookupModule("A", &BasicLookupModule{DNSType: dns.TypeA, DNSClass: dns.ClassINET})
	RegisterLookupModule("AAAA", &BasicLookupModule{DNSType: dns.TypeAAAA, DNSClass: dns.ClassINET})
	RegisterLookupModule("AFSDB", &BasicLookupModule{DNSType: dns.TypeAFSDB, DNSClass: dns.ClassINET})
	RegisterLookupModule("AMTRELAY", &BasicLookupModule{DNSType: dns.TypeAMTRELAY, DNSClass: dns.ClassINET})
	RegisterLookupModule("ANY", &BasicLookupModule{DNSType: dns.TypeANY, DNSClass: dns.ClassINET})
	RegisterLookupModule("APL", &BasicLookupModule{DNSType: dns.TypeAPL, DNSClass: dns.ClassINET})
	RegisterLookupModule("ATMA", &BasicLookupModule{DNSType: dns.TypeATMA, DNSClass: dns.ClassINET})
	RegisterLookupModule("AVC", &BasicLookupModule{DNSType: dns.TypeAVC, DNSClass: dns.ClassINET})
	RegisterLookupModule("CAA", &BasicLookupModule{DNSType: dns.TypeCAA, DNSClass: dns.ClassINET})
	RegisterLookupModule("CDNSKEY", &BasicLookupModule{DNSType: dns.TypeCDNSKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("CDS", &BasicLookupModule{DNSType: dns.TypeCDS, DNSClass: dns.ClassINET})
	RegisterLookupModule("CERT", &BasicLookupModule{DNSType: dns.TypeCERT, DNSClass: dns.ClassINET})
	RegisterLookupModule("CNAME", &BasicLookupModule{DNSType: dns.TypeCNAME, DNSClass: dns.ClassINET})
	RegisterLookupModule("CSYNC", &BasicLookupModule{DNSType: dns.TypeCSYNC, DNSClass: dns.ClassINET})
	RegisterLookupModule("DHCID", &BasicLookupModule{DNSType: dns.TypeDHCID, DNSClass: dns.ClassINET})
	RegisterLookupModule("DNAME", &BasicLookupModule{DNSType: dns.TypeDNAME, DNSClass: dns.ClassINET})
	RegisterLookupModule("DNSKEY", &BasicLookupModule{DNSType: dns.TypeDNSKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("DS", &BasicLookupModule{DNSType: dns.TypeDS, DNSClass: dns.ClassINET})
	RegisterLookupModule("EID", &BasicLookupModule{DNSType: dns.TypeEID, DNSClass: dns.ClassINET})
	RegisterLookupModule("EUI48", &BasicLookupModule{DNSType: dns.TypeEUI48, DNSClass: dns.ClassINET})
	RegisterLookupModule("EUI64", &BasicLookupModule{DNSType: dns.TypeEUI64, DNSClass: dns.ClassINET})
	RegisterLookupModule("GID", &BasicLookupModule{DNSType: dns.TypeGID, DNSClass: dns.ClassINET})
	RegisterLookupModule("GPOS", &BasicLookupModule{DNSType: dns.TypeGPOS, DNSClass: dns.ClassINET})
	RegisterLookupModule("HINFO", &BasicLookupModule{DNSType: dns.TypeHINFO, DNSClass: dns.ClassINET})
	RegisterLookupModule("HIP", &BasicLookupModule{DNSType: dns.TypeHIP, DNSClass: dns.ClassINET})
	RegisterLookupModule("HTTPS", &BasicLookupModule{DNSType: dns.TypeHTTPS, DNSClass: dns.ClassINET})
	RegisterLookupModule("IPSECKEY", &BasicLookupModule{DNSType: dns.TypeIPSECKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("ISDN", &BasicLookupModule{DNSType: dns.TypeISDN, DNSClass: dns.ClassINET})
	RegisterLookupModule("KEY", &BasicLookupModule{DNSType: dns.TypeKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("KX", &BasicLookupModule{DNSType: dns.TypeKX, DNSClass: dns.ClassINET})
	RegisterLookupModule("L32", &BasicLookupModule{DNSType: dns.TypeL32, DNSClass: dns.ClassINET})
	RegisterLookupModule("L64", &BasicLookupModule{DNSType: dns.TypeL64, DNSClass: dns.ClassINET})
	RegisterLookupModule("LOC", &BasicLookupModule{DNSType: dns.TypeLOC, DNSClass: dns.ClassINET})
	RegisterLookupModule("LP", &BasicLookupModule{DNSType: dns.TypeLP, DNSClass: dns.ClassINET})
	RegisterLookupModule("MB", &BasicLookupModule{DNSType: dns.TypeMB, DNSClass: dns.ClassINET})
	RegisterLookupModule("MD", &BasicLookupModule{DNSType: dns.TypeMD, DNSClass: dns.ClassINET})
	RegisterLookupModule("MF", &BasicLookupModule{DNSType: dns.TypeMF, DNSClass: dns.ClassINET})
	RegisterLookupModule("MG", &BasicLookupModule{DNSType: dns.TypeMG, DNSClass: dns.ClassINET})
	RegisterLookupModule("MINFO", &BasicLookupModule{DNSType: dns.TypeMINFO, DNSClass: dns.ClassINET})
	RegisterLookupModule("MR", &BasicLookupModule{DNSType: dns.TypeMR, DNSClass: dns.ClassINET})
	RegisterLookupModule("MX", &BasicLookupModule{DNSType: dns.TypeMX, DNSClass: dns.ClassINET})
	RegisterLookupModule("NAPTR", &BasicLookupModule{DNSType: dns.TypeNAPTR, DNSClass: dns.ClassINET})
	RegisterLookupModule("NID", &BasicLookupModule{DNSType: dns.TypeNID, DNSClass: dns.ClassINET})
	RegisterLookupModule("NIMLOC", &BasicLookupModule{DNSType: dns.TypeNIMLOC, DNSClass: dns.ClassINET})
	RegisterLookupModule("NINFO", &BasicLookupModule{DNSType: dns.TypeNINFO, DNSClass: dns.ClassINET})
	RegisterLookupModule("NONE", &BasicLookupModule{DNSType: dns.TypeNone, DNSClass: dns.ClassINET})
	RegisterLookupModule("NS", &BasicLookupModule{DNSType: dns.TypeNS, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSAPPTR", &BasicLookupModule{DNSType: dns.TypeNSAPPTR, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSEC", &BasicLookupModule{DNSType: dns.TypeNSEC, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSEC3", &BasicLookupModule{DNSType: dns.TypeNSEC3, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSEC3PARAM", &BasicLookupModule{DNSType: dns.TypeNSEC3PARAM, DNSClass: dns.ClassINET})
	RegisterLookupModule("NULL", &BasicLookupModule{DNSType: dns.TypeNULL, DNSClass: dns.ClassINET})
	RegisterLookupModule("NXNAME", &BasicLookupModule{DNSType: dns.TypeNXNAME, DNSClass: dns.ClassINET})
	RegisterLookupModule("NXT", &BasicLookupModule{DNSType: dns.TypeNXT, DNSClass: dns.ClassINET})
	RegisterLookupModule("OPENPGPKEY", &BasicLookupModule{DNSType: dns.TypeOPENPGPKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("OPT", &BasicLookupModule{DNSType: dns.TypeOPT, DNSClass: dns.ClassINET})
	RegisterLookupModule("PTR", &BasicLookupModule{DNSType: dns.TypePTR, DNSClass: dns.ClassINET})
	RegisterLookupModule("PX", &BasicLookupModule{DNSType: dns.TypePX, DNSClass: dns.ClassINET})
	RegisterLookupModule("RKEY", &BasicLookupModule{DNSType: dns.TypeRKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("RP", &BasicLookupModule{DNSType: dns.TypeRP, DNSClass: dns.ClassINET})
	RegisterLookupModule("RRSIG", &BasicLookupModule{DNSType: dns.TypeRRSIG, DNSClass: dns.ClassINET})
	RegisterLookupModule("RT", &BasicLookupModule{DNSType: dns.TypeRT, DNSClass: dns.ClassINET})
	RegisterLookupModule("SIG", &BasicLookupModule{DNSType: dns.TypeSIG, DNSClass: dns.ClassINET})
	RegisterLookupModule("SMIMEA", &BasicLookupModule{DNSType: dns.TypeSMIMEA, DNSClass: dns.ClassINET})
	RegisterLookupModule("SOA", &BasicLookupModule{DNSType: dns.TypeSOA, DNSClass: dns.ClassINET})
	RegisterLookupModule("SPF", &BasicLookupModule{DNSType: dns.TypeSPF, DNSClass: dns.ClassINET})
	RegisterLookupModule("SRV", &BasicLookupModule{DNSType: dns.TypeSRV, DNSClass: dns.ClassINET})
	RegisterLookupModule("SSHFP", &BasicLookupModule{DNSType: dns.TypeSSHFP, DNSClass: dns.ClassINET})
	RegisterLookupModule("SVCB", &BasicLookupModule{DNSType: dns.TypeSVCB, DNSClass: dns.ClassINET})
	RegisterLookupModule("TALINK", &BasicLookupModule{DNSType: dns.TypeTALINK, DNSClass: dns.ClassINET})
	RegisterLookupModule("TKEY", &BasicLookupModule{DNSType: dns.TypeTKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("TLSA", &BasicLookupModule{DNSType: dns.TypeTLSA, DNSClass: dns.ClassINET})
	RegisterLookupModule("TXT", &BasicLookupModule{DNSType: dns.TypeTXT, DNSClass: dns.ClassINET})
	RegisterLookupModule("UID", &BasicLookupModule{DNSType: dns.TypeUID, DNSClass: dns.ClassINET})
	RegisterLookupModule("UINFO", &BasicLookupModule{DNSType: dns.TypeUINFO, DNSClass: dns.ClassINET})
	RegisterLookupModule("UNSPEC", &BasicLookupModule{DNSType: dns.TypeUNSPEC, DNSClass: dns.ClassINET})
	RegisterLookupModule("URI", &BasicLookupModule{DNSType: dns.TypeURI, DNSClass: dns.ClassINET})
	RegisterLookupModule("X25", &BasicLookupModule{DNSType: dns.TypeX25, DNSClass: dns.ClassINET})
	RegisterLookupModule("ZONEMD", &BasicLookupModule{DNSType: dns.TypeZONEMD, DNSClass: dns.ClassINET})
	RegisterLookupModule("MULTIPLE", &BasicLookupModule{
		DNSType:  dns.TypeANY,
		DNSClass: dns.ClassINET,
		Description: "MULTIPLE is a lookup module used from the CLI to use multiple lookup modules at once with the " +
			"help of a configuration file provided with --multi-config-file/-c. See README.md/Multiple Lookup Modules " +
			"for more information."})
}

func RegisterLookupModule(name string, lm LookupModule) {
	moduleToLookupModule[name] = lm
	_, err := parser.AddCommand(name, "", lm.GetDescription(), lm)
	if err != nil {
		log.Fatalf("could not add command: %v", err)
	}
}

type BasicLookupModule struct {
	IsIterative          bool
	LookupAllNameServers bool
	DNSType              uint16
	DNSClass             uint16
	Description          string
}

func (lm *BasicLookupModule) CLIInit(gc *CLIConf, rc *zdns.ResolverConfig) error {
	if gc == nil {
		return errors.New("CLIConf cannot be nil")
	}
	if rc == nil {
		return errors.New("ResolverConfig cannot be nil")
	}
	lm.LookupAllNameServers = rc.LookupAllNameServers
	if gc.Class != 0 {
		// if the user has specified a class, use it
		lm.DNSClass = gc.Class
	}
	lm.IsIterative = gc.IterativeResolution
	return nil
}

func (lm *BasicLookupModule) Help() string {
	return ""
}

func (lm *BasicLookupModule) GetDescription() string {
	return lm.Description
}

func (lm *BasicLookupModule) Validate(args []string) error {
	return nil
}

func (lm *BasicLookupModule) NewFlags() interface{} {
	return lm
}

// Lookup performs a DNS lookup using the given resolver and lookupName.
// The behavior with respect to the nameServers is determined by the LookupAllNameServers and IsIterative fields.
// non-Iterative + all-Nameservers query -> we'll send a query to each of the resolver's external nameservers
// non-Iterative query -> we'll send a query to the nameserver provided. If none provided, a random nameserver from the resolver's external nameservers will be used
// iterative + all-Nameservers query -> we'll send a query to each root NS and query all nameservers down the chain.
// iterative query -> we'll send a query to a random root NS and query all nameservers down the chain.
func (lm *BasicLookupModule) Lookup(resolver *zdns.Resolver, lookupName string, nameServer *zdns.NameServer) (interface{}, zdns.Trace, zdns.Status, error) {
	if lm.LookupAllNameServers && lm.IsIterative {
		return resolver.LookupAllNameserversIterative(&zdns.Question{Name: lookupName, Type: lm.DNSType, Class: lm.DNSClass}, nil)
	}
	if lm.LookupAllNameServers {
		return resolver.LookupAllNameserversExternal(&zdns.Question{Name: lookupName, Type: lm.DNSType, Class: lm.DNSClass}, nil)
	}
	if lm.IsIterative {
		return resolver.IterativeLookup(context.Background(), &zdns.Question{Name: lookupName, Type: lm.DNSType, Class: lm.DNSClass})
	}
	return resolver.ExternalLookup(context.Background(), &zdns.Question{Type: lm.DNSType, Class: lm.DNSClass, Name: lookupName}, nameServer)
}

func GetLookupModule(name string) (LookupModule, error) {
	module, ok := moduleToLookupModule[name]
	if !ok {
		return nil, fmt.Errorf("module %s not found", name)
	}
	return module, nil
}

func GetValidLookups() map[string]struct{} {
	lookups := make(map[string]struct{}, len(moduleToLookupModule))
	for lookup := range moduleToLookupModule {
		lookups[lookup] = struct{}{}
	}
	return lookups
}
