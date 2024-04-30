package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zmap/zdns/pkg/modules/nslookup"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/modules/mxlookup"
)

var module_to_type map[string]uint16

const (
	MXLOOKUP = "MXLOOKUP"
	NSLOOKUP = "NSLOOKUP"
)

func init() {
	module_to_type = map[string]uint16{
		"A":          dns.TypeA,
		"AAAA":       dns.TypeAAAA,
		"AFSDB":      dns.TypeAFSDB,
		"ATMA":       dns.TypeATMA,
		"AVC":        dns.TypeAVC,
		"CAA":        dns.TypeCAA,
		"CERT":       dns.TypeCERT,
		"CDS":        dns.TypeCDS,
		"CDNSKEY":    dns.TypeCDNSKEY,
		"CNAME":      dns.TypeCNAME,
		"CSYNC":      dns.TypeCSYNC,
		"DHCID":      dns.TypeDHCID,
		"DNAME":      dns.TypeDNAME,
		"DNSKEY":     dns.TypeDNSKEY,
		"DS":         dns.TypeDS,
		"EID":        dns.TypeEID,
		"EUI48":      dns.TypeEUI48,
		"EUI64":      dns.TypeEUI64,
		"GID":        dns.TypeGID,
		"GPOS":       dns.TypeGPOS,
		"HINFO":      dns.TypeHINFO,
		"HIP":        dns.TypeHIP,
		"HTTPS":      dns.TypeHTTPS,
		"ISDN":       dns.TypeISDN,
		"KEY":        dns.TypeKEY,
		"KX":         dns.TypeKX,
		"L32":        dns.TypeL32,
		"L64":        dns.TypeL64,
		"LOC":        dns.TypeLOC,
		"LP":         dns.TypeLP,
		"MD":         dns.TypeMD,
		"MF":         dns.TypeMF,
		"MB":         dns.TypeMB,
		"MG":         dns.TypeMG,
		"MR":         dns.TypeMR,
		"MX":         dns.TypeMX,
		"NAPTR":      dns.TypeNAPTR,
		"NIMLOC":     dns.TypeNIMLOC,
		"NID":        dns.TypeNID,
		"NINFO":      dns.TypeNINFO,
		"NSAPPTR":    dns.TypeNSAPPTR,
		"NS":         dns.TypeNS,
		"NXT":        dns.TypeNXT,
		"NSEC":       dns.TypeNSEC,
		"NSEC3":      dns.TypeNSEC3,
		"NSEC3PARAM": dns.TypeNSEC3PARAM,
		"NULL":       dns.TypeNULL,
		"OPENPGPKEY": dns.TypeOPENPGPKEY,
		"PTR":        dns.TypePTR,
		"PX":         dns.TypePX,
		"RP":         dns.TypeRP,
		"RRSIG":      dns.TypeRRSIG,
		"RT":         dns.TypeRT,
		"SMIMEA":     dns.TypeSMIMEA,
		"SSHFP":      dns.TypeSSHFP,
		"SOA":        dns.TypeSOA,
		"SPF":        dns.TypeSPF,
		"SRV":        dns.TypeSRV,
		"SVCB":       dns.TypeSVCB,
		"TALINK":     dns.TypeTALINK,
		"TKEY":       dns.TypeTKEY,
		"TLSA":       dns.TypeTLSA,
		"TXT":        dns.TypeTXT,
		"UID":        dns.TypeUID,
		"UINFO":      dns.TypeUINFO,
		"UNSPEC":     dns.TypeUNSPEC,
		"URI":        dns.TypeURI,
		"ANY":        dns.TypeANY,
	}
}

type moduleData struct {
	MXLookup *mxlookup.MXLookupConfig
	NSLookup *nslookup.NSLookupConfig
}

func populateModuleData(gc *CLIConf, flags *pflag.FlagSet) *moduleData {
	modData := new(moduleData)
	switch gc.Module {
	case MXLOOKUP:
		modData.MXLookup = mxlookup.Initialize(flags)
	case NSLOOKUP:
		modData.NSLookup = nslookup.Initialize(flags)
	default:
		log.Debug("nothing to be done for module instantiation")
	}
	return modData

}
