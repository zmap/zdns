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
	GetModuleName() string
}

const (
	BINDVERSION = "BINDVERSION"
)

var moduleToLookupModule map[string]LookupModule

func init() {
	moduleToLookupModule = map[string]LookupModule{}

	RegisterLookupModule("A", &BasicLookupModule{DNSType: dns.TypeA, DNSClass: dns.ClassINET, ModuleName: "A"})
	RegisterLookupModule("AAAA", &BasicLookupModule{DNSType: dns.TypeAAAA, DNSClass: dns.ClassINET, ModuleName: "AAAA"})
	RegisterLookupModule("AFSDB", &BasicLookupModule{DNSType: dns.TypeAFSDB, DNSClass: dns.ClassINET, ModuleName: "AFSDB"})
	RegisterLookupModule("ATMA", &BasicLookupModule{DNSType: dns.TypeATMA, DNSClass: dns.ClassINET, ModuleName: "ATMA"})
	RegisterLookupModule("AVC", &BasicLookupModule{DNSType: dns.TypeAVC, DNSClass: dns.ClassINET, ModuleName: "AVC"})
	RegisterLookupModule("CAA", &BasicLookupModule{DNSType: dns.TypeCAA, DNSClass: dns.ClassINET, ModuleName: "CAA"})
	RegisterLookupModule("CERT", &BasicLookupModule{DNSType: dns.TypeCERT, DNSClass: dns.ClassINET, ModuleName: "CERT"})
	RegisterLookupModule("CDS", &BasicLookupModule{DNSType: dns.TypeCDS, DNSClass: dns.ClassINET, ModuleName: "CDS"})
	RegisterLookupModule("CDNSKEY", &BasicLookupModule{DNSType: dns.TypeCDNSKEY, DNSClass: dns.ClassINET, ModuleName: "CDNSKEY"})
	RegisterLookupModule("CNAME", &BasicLookupModule{DNSType: dns.TypeCNAME, DNSClass: dns.ClassINET, ModuleName: "CNAME"})
	RegisterLookupModule("CSYNC", &BasicLookupModule{DNSType: dns.TypeCSYNC, DNSClass: dns.ClassINET, ModuleName: "CSYNC"})
	RegisterLookupModule("DHCID", &BasicLookupModule{DNSType: dns.TypeDHCID, DNSClass: dns.ClassINET, ModuleName: "DHCID"})
	RegisterLookupModule("DNAME", &BasicLookupModule{DNSType: dns.TypeDNAME, DNSClass: dns.ClassINET, ModuleName: "DNAME"})
	RegisterLookupModule("DNSKEY", &BasicLookupModule{DNSType: dns.TypeDNSKEY, DNSClass: dns.ClassINET, ModuleName: "DNSKEY"})
	RegisterLookupModule("DS", &BasicLookupModule{DNSType: dns.TypeDS, DNSClass: dns.ClassINET, ModuleName: "DS"})
	RegisterLookupModule("EID", &BasicLookupModule{DNSType: dns.TypeEID, DNSClass: dns.ClassINET, ModuleName: "EID"})
	RegisterLookupModule("EUI48", &BasicLookupModule{DNSType: dns.TypeEUI48, DNSClass: dns.ClassINET, ModuleName: "EUI48"})
	RegisterLookupModule("EUI64", &BasicLookupModule{DNSType: dns.TypeEUI64, DNSClass: dns.ClassINET, ModuleName: "EUI64"})
	RegisterLookupModule("GID", &BasicLookupModule{DNSType: dns.TypeGID, DNSClass: dns.ClassINET, ModuleName: "GID"})
	RegisterLookupModule("GPOS", &BasicLookupModule{DNSType: dns.TypeGPOS, DNSClass: dns.ClassINET, ModuleName: "GPOS"})
	RegisterLookupModule("HINFO", &BasicLookupModule{DNSType: dns.TypeHINFO, DNSClass: dns.ClassINET, ModuleName: "HINFO"})
	RegisterLookupModule("HIP", &BasicLookupModule{DNSType: dns.TypeHIP, DNSClass: dns.ClassINET, ModuleName: "HIP"})
	RegisterLookupModule("HTTPS", &BasicLookupModule{DNSType: dns.TypeHTTPS, DNSClass: dns.ClassINET, ModuleName: "HTTPS"})
	RegisterLookupModule("ISDN", &BasicLookupModule{DNSType: dns.TypeISDN, DNSClass: dns.ClassINET, ModuleName: "ISDN"})
	RegisterLookupModule("KEY", &BasicLookupModule{DNSType: dns.TypeKEY, DNSClass: dns.ClassINET, ModuleName: "KEY"})
	RegisterLookupModule("KX", &BasicLookupModule{DNSType: dns.TypeKX, DNSClass: dns.ClassINET, ModuleName: "KX"})
	RegisterLookupModule("L32", &BasicLookupModule{DNSType: dns.TypeL32, DNSClass: dns.ClassINET, ModuleName: "L32"})
	RegisterLookupModule("L64", &BasicLookupModule{DNSType: dns.TypeL64, DNSClass: dns.ClassINET, ModuleName: "L64"})
	RegisterLookupModule("LOC", &BasicLookupModule{DNSType: dns.TypeLOC, DNSClass: dns.ClassINET, ModuleName: "LOC"})
	RegisterLookupModule("LP", &BasicLookupModule{DNSType: dns.TypeLP, DNSClass: dns.ClassINET, ModuleName: "LP"})
	RegisterLookupModule("MD", &BasicLookupModule{DNSType: dns.TypeMD, DNSClass: dns.ClassINET, ModuleName: "MD"})
	RegisterLookupModule("MF", &BasicLookupModule{DNSType: dns.TypeMF, DNSClass: dns.ClassINET, ModuleName: "MF"})
	RegisterLookupModule("MB", &BasicLookupModule{DNSType: dns.TypeMB, DNSClass: dns.ClassINET, ModuleName: "MB"})
	RegisterLookupModule("MG", &BasicLookupModule{DNSType: dns.TypeMG, DNSClass: dns.ClassINET, ModuleName: "MG"})
	RegisterLookupModule("MR", &BasicLookupModule{DNSType: dns.TypeMR, DNSClass: dns.ClassINET, ModuleName: "MR"})
	RegisterLookupModule("MX", &BasicLookupModule{DNSType: dns.TypeMX, DNSClass: dns.ClassINET, ModuleName: "MX"})
	RegisterLookupModule("NAPTR", &BasicLookupModule{DNSType: dns.TypeNAPTR, DNSClass: dns.ClassINET, ModuleName: "NAPTR"})
	RegisterLookupModule("NIMLOC", &BasicLookupModule{DNSType: dns.TypeNIMLOC, DNSClass: dns.ClassINET, ModuleName: "NIMLOC"})
	RegisterLookupModule("NID", &BasicLookupModule{DNSType: dns.TypeNID, DNSClass: dns.ClassINET, ModuleName: "NID"})
	RegisterLookupModule("NINFO", &BasicLookupModule{DNSType: dns.TypeNINFO, DNSClass: dns.ClassINET, ModuleName: "NINFO"})
	RegisterLookupModule("NSAPPTR", &BasicLookupModule{DNSType: dns.TypeNSAPPTR, DNSClass: dns.ClassINET, ModuleName: "NSAPPTR"})
	RegisterLookupModule("NS", &BasicLookupModule{DNSType: dns.TypeNS, DNSClass: dns.ClassINET, ModuleName: "NS"})
	RegisterLookupModule("NXT", &BasicLookupModule{DNSType: dns.TypeNXT, DNSClass: dns.ClassINET, ModuleName: "NXT"})
	RegisterLookupModule("NSEC", &BasicLookupModule{DNSType: dns.TypeNSEC, DNSClass: dns.ClassINET, ModuleName: "NSEC"})
	RegisterLookupModule("NSEC3", &BasicLookupModule{DNSType: dns.TypeNSEC3, DNSClass: dns.ClassINET, ModuleName: "NSEC3"})
	RegisterLookupModule("NSEC3PARAM", &BasicLookupModule{DNSType: dns.TypeNSEC3PARAM, DNSClass: dns.ClassINET, ModuleName: "NSEC3PARAM"})
	RegisterLookupModule("NULL", &BasicLookupModule{DNSType: dns.TypeNULL, DNSClass: dns.ClassINET, ModuleName: "NULL"})
	RegisterLookupModule("OPENPGPKEY", &BasicLookupModule{DNSType: dns.TypeOPENPGPKEY, DNSClass: dns.ClassINET, ModuleName: "OPENPGPKEY"})
	RegisterLookupModule("PTR", &BasicLookupModule{DNSType: dns.TypePTR, DNSClass: dns.ClassINET, ModuleName: "PTR"})
	RegisterLookupModule("PX", &BasicLookupModule{DNSType: dns.TypePX, DNSClass: dns.ClassINET, ModuleName: "PX"})
	RegisterLookupModule("RP", &BasicLookupModule{DNSType: dns.TypeRP, DNSClass: dns.ClassINET, ModuleName: "RP"})
	RegisterLookupModule("RRSIG", &BasicLookupModule{DNSType: dns.TypeRRSIG, DNSClass: dns.ClassINET, ModuleName: "RRSIG"})
	RegisterLookupModule("RT", &BasicLookupModule{DNSType: dns.TypeRT, DNSClass: dns.ClassINET, ModuleName: "RT"})
	RegisterLookupModule("SMIMEA", &BasicLookupModule{DNSType: dns.TypeSMIMEA, DNSClass: dns.ClassINET, ModuleName: "SMIMEA"})
	RegisterLookupModule("SSHFP", &BasicLookupModule{DNSType: dns.TypeSSHFP, DNSClass: dns.ClassINET, ModuleName: "SSHFP"})
	RegisterLookupModule("SOA", &BasicLookupModule{DNSType: dns.TypeSOA, DNSClass: dns.ClassINET, ModuleName: "SOA"})
	RegisterLookupModule("SPF", &BasicLookupModule{DNSType: dns.TypeSPF, DNSClass: dns.ClassINET, ModuleName: "SPF"})
	RegisterLookupModule("SRV", &BasicLookupModule{DNSType: dns.TypeSRV, DNSClass: dns.ClassINET, ModuleName: "SRV"})
	RegisterLookupModule("SVCB", &BasicLookupModule{DNSType: dns.TypeSVCB, DNSClass: dns.ClassINET, ModuleName: "SVCB"})
	RegisterLookupModule("TALINK", &BasicLookupModule{DNSType: dns.TypeTALINK, DNSClass: dns.ClassINET, ModuleName: "TALINK"})
	RegisterLookupModule("TKEY", &BasicLookupModule{DNSType: dns.TypeTKEY, DNSClass: dns.ClassINET, ModuleName: "TKEY"})
	RegisterLookupModule("TLSA", &BasicLookupModule{DNSType: dns.TypeTLSA, DNSClass: dns.ClassINET, ModuleName: "TLSA"})
	RegisterLookupModule("TXT", &BasicLookupModule{DNSType: dns.TypeTXT, DNSClass: dns.ClassINET, ModuleName: "TXT"})
	RegisterLookupModule("UID", &BasicLookupModule{DNSType: dns.TypeUID, DNSClass: dns.ClassINET, ModuleName: "UID"})
	RegisterLookupModule("UINFO", &BasicLookupModule{DNSType: dns.TypeUINFO, DNSClass: dns.ClassINET, ModuleName: "UINFO"})
	RegisterLookupModule("UNSPEC", &BasicLookupModule{DNSType: dns.TypeUNSPEC, DNSClass: dns.ClassINET, ModuleName: "UNSPEC"})
	RegisterLookupModule("URI", &BasicLookupModule{DNSType: dns.TypeURI, DNSClass: dns.ClassINET, ModuleName: "URI"})
	RegisterLookupModule("ANY", &BasicLookupModule{DNSType: dns.TypeANY, DNSClass: dns.ClassINET, ModuleName: "ANY"})
}

func RegisterLookupModule(name string, lm LookupModule) {
	moduleToLookupModule[name] = lm
}

type BasicLookupModule struct {
	ModuleName           string
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

func (lm *BasicLookupModule) GetModuleName() string {
	return lm.ModuleName
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
