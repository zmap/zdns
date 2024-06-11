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
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"

	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/zdns"
)

type LookupModule interface {
	CLIInit(gc *CLIConf, rc *zdns.ResolverConfig, flags *pflag.FlagSet) error
	Lookup(resolver *zdns.Resolver, lookupName, nameServer string) (interface{}, zdns.Trace, zdns.Status, error)
	Help() string
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
	RegisterLookupModule("ATMA", &BasicLookupModule{DNSType: dns.TypeATMA, DNSClass: dns.ClassINET})
	RegisterLookupModule("AVC", &BasicLookupModule{DNSType: dns.TypeAVC, DNSClass: dns.ClassINET})
	RegisterLookupModule("CAA", &BasicLookupModule{DNSType: dns.TypeCAA, DNSClass: dns.ClassINET})
	RegisterLookupModule("CERT", &BasicLookupModule{DNSType: dns.TypeCERT, DNSClass: dns.ClassINET})
	RegisterLookupModule("CDS", &BasicLookupModule{DNSType: dns.TypeCDS, DNSClass: dns.ClassINET})
	RegisterLookupModule("CDNSKEY", &BasicLookupModule{DNSType: dns.TypeCDNSKEY, DNSClass: dns.ClassINET})
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
	RegisterLookupModule("ISDN", &BasicLookupModule{DNSType: dns.TypeISDN, DNSClass: dns.ClassINET})
	RegisterLookupModule("KEY", &BasicLookupModule{DNSType: dns.TypeKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("KX", &BasicLookupModule{DNSType: dns.TypeKX, DNSClass: dns.ClassINET})
	RegisterLookupModule("L32", &BasicLookupModule{DNSType: dns.TypeL32, DNSClass: dns.ClassINET})
	RegisterLookupModule("L64", &BasicLookupModule{DNSType: dns.TypeL64, DNSClass: dns.ClassINET})
	RegisterLookupModule("LOC", &BasicLookupModule{DNSType: dns.TypeLOC, DNSClass: dns.ClassINET})
	RegisterLookupModule("LP", &BasicLookupModule{DNSType: dns.TypeLP, DNSClass: dns.ClassINET})
	RegisterLookupModule("MD", &BasicLookupModule{DNSType: dns.TypeMD, DNSClass: dns.ClassINET})
	RegisterLookupModule("MF", &BasicLookupModule{DNSType: dns.TypeMF, DNSClass: dns.ClassINET})
	RegisterLookupModule("MB", &BasicLookupModule{DNSType: dns.TypeMB, DNSClass: dns.ClassINET})
	RegisterLookupModule("MG", &BasicLookupModule{DNSType: dns.TypeMG, DNSClass: dns.ClassINET})
	RegisterLookupModule("MR", &BasicLookupModule{DNSType: dns.TypeMR, DNSClass: dns.ClassINET})
	RegisterLookupModule("MX", &BasicLookupModule{DNSType: dns.TypeMX, DNSClass: dns.ClassINET})
	RegisterLookupModule("NAPTR", &BasicLookupModule{DNSType: dns.TypeNAPTR, DNSClass: dns.ClassINET})
	RegisterLookupModule("NIMLOC", &BasicLookupModule{DNSType: dns.TypeNIMLOC, DNSClass: dns.ClassINET})
	RegisterLookupModule("NID", &BasicLookupModule{DNSType: dns.TypeNID, DNSClass: dns.ClassINET})
	RegisterLookupModule("NINFO", &BasicLookupModule{DNSType: dns.TypeNINFO, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSAPPTR", &BasicLookupModule{DNSType: dns.TypeNSAPPTR, DNSClass: dns.ClassINET})
	RegisterLookupModule("NS", &BasicLookupModule{DNSType: dns.TypeNS, DNSClass: dns.ClassINET})
	RegisterLookupModule("NXT", &BasicLookupModule{DNSType: dns.TypeNXT, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSEC", &BasicLookupModule{DNSType: dns.TypeNSEC, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSEC3", &BasicLookupModule{DNSType: dns.TypeNSEC3, DNSClass: dns.ClassINET})
	RegisterLookupModule("NSEC3PARAM", &BasicLookupModule{DNSType: dns.TypeNSEC3PARAM, DNSClass: dns.ClassINET})
	RegisterLookupModule("NULL", &BasicLookupModule{DNSType: dns.TypeNULL, DNSClass: dns.ClassINET})
	RegisterLookupModule("OPENPGPKEY", &BasicLookupModule{DNSType: dns.TypeOPENPGPKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("PTR", &BasicLookupModule{DNSType: dns.TypePTR, DNSClass: dns.ClassINET})
	RegisterLookupModule("PX", &BasicLookupModule{DNSType: dns.TypePX, DNSClass: dns.ClassINET})
	RegisterLookupModule("RP", &BasicLookupModule{DNSType: dns.TypeRP, DNSClass: dns.ClassINET})
	RegisterLookupModule("RRSIG", &BasicLookupModule{DNSType: dns.TypeRRSIG, DNSClass: dns.ClassINET})
	RegisterLookupModule("RT", &BasicLookupModule{DNSType: dns.TypeRT, DNSClass: dns.ClassINET})
	RegisterLookupModule("SMIMEA", &BasicLookupModule{DNSType: dns.TypeSMIMEA, DNSClass: dns.ClassINET})
	RegisterLookupModule("SSHFP", &BasicLookupModule{DNSType: dns.TypeSSHFP, DNSClass: dns.ClassINET})
	RegisterLookupModule("SOA", &BasicLookupModule{DNSType: dns.TypeSOA, DNSClass: dns.ClassINET})
	RegisterLookupModule("SPF", &BasicLookupModule{DNSType: dns.TypeSPF, DNSClass: dns.ClassINET})
	RegisterLookupModule("SRV", &BasicLookupModule{DNSType: dns.TypeSRV, DNSClass: dns.ClassINET})
	RegisterLookupModule("SVCB", &BasicLookupModule{DNSType: dns.TypeSVCB, DNSClass: dns.ClassINET})
	RegisterLookupModule("TALINK", &BasicLookupModule{DNSType: dns.TypeTALINK, DNSClass: dns.ClassINET})
	RegisterLookupModule("TKEY", &BasicLookupModule{DNSType: dns.TypeTKEY, DNSClass: dns.ClassINET})
	RegisterLookupModule("TLSA", &BasicLookupModule{DNSType: dns.TypeTLSA, DNSClass: dns.ClassINET})
	RegisterLookupModule("TXT", &BasicLookupModule{DNSType: dns.TypeTXT, DNSClass: dns.ClassINET})
	RegisterLookupModule("UID", &BasicLookupModule{DNSType: dns.TypeUID, DNSClass: dns.ClassINET})
	RegisterLookupModule("UINFO", &BasicLookupModule{DNSType: dns.TypeUINFO, DNSClass: dns.ClassINET})
	RegisterLookupModule("UNSPEC", &BasicLookupModule{DNSType: dns.TypeUNSPEC, DNSClass: dns.ClassINET})
	RegisterLookupModule("URI", &BasicLookupModule{DNSType: dns.TypeURI, DNSClass: dns.ClassINET})
	RegisterLookupModule("ANY", &BasicLookupModule{DNSType: dns.TypeANY, DNSClass: dns.ClassINET})
}

func RegisterLookupModule(name string, lm LookupModule) {
	moduleToLookupModule[name] = lm
}

type BasicLookupModule struct {
	IsIterative          bool
	LookupAllNameServers bool
	DNSType              uint16
	DNSClass             uint16
}

func (lm *BasicLookupModule) CLIInit(gc *CLIConf, rc *zdns.ResolverConfig, flags *pflag.FlagSet) error {
	if gc == nil {
		return errors.New("CLIConf cannot be nil")
	}
	if rc == nil {
		return errors.New("ResolverConfig cannot be nil")
	}
	lm.LookupAllNameServers = rc.LookupAllNameServers
	lm.IsIterative = gc.IterativeResolution
	return nil
}

func (lm *BasicLookupModule) Help() string {
	return ""
}

func (lm *BasicLookupModule) Lookup(resolver *zdns.Resolver, lookupName, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	if lm.LookupAllNameServers {
		return resolver.LookupAllNameservers(&zdns.Question{Name: lookupName, Type: lm.DNSType, Class: lm.DNSClass}, nameServer)
	}
	if lm.IsIterative {
		return resolver.IterativeLookup(&zdns.Question{Name: lookupName, Type: lm.DNSType, Class: lm.DNSClass})
	}
	return resolver.ExternalLookup(&zdns.Question{Type: lm.DNSType, Class: lm.DNSClass, Name: lookupName}, nameServer)
}

func GetLookupModule(name string) (LookupModule, error) {
	module, ok := moduleToLookupModule[name]
	if !ok {
		return nil, fmt.Errorf("module %s not found", name)
	}
	return module, nil
}

func GetValidLookups() []string {
	lookups := make([]string, 0, len(moduleToLookupModule))
	for lookup := range moduleToLookupModule {
		lookups = append(lookups, lookup)
	}
	return lookups
}
