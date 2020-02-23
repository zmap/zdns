package miekg

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

var typeNames = map[uint16]string{
	dns.TypeNone:       "None",
	dns.TypeA:          "A",          // Module, Answer
	dns.TypeANY:        "ANY",        // Module, Answer
	dns.TypeNS:         "NS",         // Module, Answer
	dns.TypeMD:         "MD",         // Module, Answer
	dns.TypeMF:         "MF",         // Module, Answer
	dns.TypeCNAME:      "CNAME",      // Module, Type
	dns.TypeSOA:        "SOA",        // Module, Type
	dns.TypeMB:         "MB",         // Module, Default Type
	dns.TypeMG:         "MG",         // Module, Default Type
	dns.TypeMR:         "MR",         // Module, Default Type
	dns.TypeNULL:       "NULL",       // Module, Default Type
	dns.TypePTR:        "PTR",        // Module, Default Type
	dns.TypeHINFO:      "HINFO",      // Module, HInfoAnswer
	dns.TypeMINFO:      "MINFO",      // Module, MInfoAnswer
	dns.TypeMX:         "MX",         // Module, Type
	dns.TypeTXT:        "TXT",        // Module, Type
	dns.TypeRP:         "RP",         // Module
	dns.TypeAFSDB:      "AFSDB",      // Module, AFSDBAnswer (todo)
	dns.TypeX25:        "X25",        // Module, X25Answer (todo)
	dns.TypeISDN:       "ISDN",       // Module
	dns.TypeRT:         "RT",         // Module
	dns.TypeNSAPPTR:    "NSAPPTR",    // Module
	dns.TypeSIG:        "SIG",        // Module, RRSIGAnswer
	dns.TypeKEY:        "KEY",        // Module, DNSKeyAnswer
	dns.TypePX:         "PX",         // Module, PXAnswer (todo)
	dns.TypeGPOS:       "GPOS",       // Module, GPOSAnswer (todo)
	dns.TypeAAAA:       "AAAA",       // Module, Type
	dns.TypeLOC:        "LOC",        // Module
	dns.TypeNXT:        "NXT",        // Module
	dns.TypeEID:        "EID",        // Module
	dns.TypeNIMLOC:     "NIMLOC",     // Module
	dns.TypeSRV:        "SRV",        // Module, SRVAnswer
	dns.TypeATMA:       "ATMA",       // Module
	dns.TypeNAPTR:      "NAPTR",      // Module
	dns.TypeKX:         "KX",         // Module
	dns.TypeCERT:       "CERT",       // Module, CERTAnswer (todo)
	dns.TypeDNAME:      "DNAME",      // Module, Answer
	dns.TypeOPT:        "OPT",        // Module
	dns.TypeDS:         "DS",         // Module
	dns.TypeSSHFP:      "SSHFP",      // Module
	dns.TypeRRSIG:      "RRSIG",      // Module, RRSIGAnswer
	dns.TypeNSEC:       "NSEC",       // Module, ??
	dns.TypeDNSKEY:     "DNSKEY",     // Module, ??
	dns.TypeDHCID:      "DHCID",      // Module
	dns.TypeNSEC3:      "NSEC3",      // Module, ??
	dns.TypeNSEC3PARAM: "NSEC3PARAM", // Module, ??
	dns.TypeTLSA:       "TLSA",       // Module, TLSAAnswer
	dns.TypeSMIMEA:     "SMIMEA",     // Module
	dns.TypeHIP:        "HIP",        // Module
	dns.TypeNINFO:      "NINFO",      // Module, Answer
	dns.TypeRKEY:       "RKEY",       // Module, DNSKeyAnswer
	dns.TypeTALINK:     "TALINK",     // Module
	dns.TypeCDS:        "CDS",        // Module, DNSKeyAnswer
	dns.TypeCDNSKEY:    "CDNSKEY",    // Module, DNSKeyAnswer
	dns.TypeOPENPGPKEY: "OPENPGPKEY", // Module
	dns.TypeCSYNC:      "CSYNC",      // Module
	dns.TypeSPF:        "SPF",        // Module, SPF
	dns.TypeUINFO:      "UINFO",      // Module
	dns.TypeUID:        "UID",        // Module
	dns.TypeGID:        "GID",        // Module
	dns.TypeUNSPEC:     "UNSPEC",     // Module
	dns.TypeNID:        "NID",        // Module
	dns.TypeL32:        "L32",        // Module
	dns.TypeL64:        "L64",        // Module
	dns.TypeLP:         "LP",         // Module
	dns.TypeEUI48:      "EUI48",      // Module
	dns.TypeEUI64:      "EUI64",      // Module
	dns.TypeURI:        "URI",        // Module
	dns.TypeCAA:        "CAA",        // Module, CAAAnswer
	dns.TypeAVC:        "AVC",        // Module, Answer
}

type Answer struct {
	Ttl     uint32 `json:"ttl" groups:"ttl,normal,long,trace"`
	Type    string `json:"type,omitempty" groups:"short,normal,long,trace"`
	rrType  uint16
	Class   string `json:"class,omitempty" groups:"short,normal,long,trace"`
	rrClass uint16
	Name    string `json:"name,omitempty" groups:"short,normal,long,trace"`
	Answer  string `json:"answer,omitempty" groups:"short,normal,long,trace"`
}

// Complex Answers (in alphabetical order)

type AFSDBAnswer struct {
	Answer
	Subtype  uint16 `json:"subtype" groups:"short,normal,long,trace"`
	Hostname string `json:"hostname" groups:"short,normal,long,trace"`
}

type CAAAnswer struct {
	Answer
	Tag   string `json:"tag" groups:"short,normal,long,trace"`
	Value string `json:"value" groups:"short,normal,long,trace"`
	Flag  uint8  `json:"flag" groups:"short,normal,long,trace"`
}

type CERTAnswer struct {
	Answer
	Type        uint16 `json:"type" groups:"short,normal,long,trace"`
	KeyTag      uint16 `json:"keytag" groups:"short,normal,long,trace"`
	Algorithm   uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	Certificate string `json:"certificate" groups:"short,normal,long,trace"`
}

type DNSKEYAnswer struct {
	Answer
	Flags     uint16 `json:"flags" groups:"short,normal,long,trace"`
	Protocol  uint8  `json:"protocol" groups:"short,normal,long,trace"`
	Algorithm uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	PublicKey string `json:"public_key" groups:"short,normal,long,trace"`
}

type DSAnswer struct {
	Answer
	KeyTag     uint16 `json:"key_tag" groups:"short,normal,long,trace"`
	Algorithm  uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	DigestType uint8  `json:"digest_type" groups:"short,normal,long,trace"`
	Digest     string `json:"digest" groups:"short,normal,long,trace"`
}
type GPOSAnswer struct {
	Answer
	Longitude string `json:"preference" groups:"short,normal,long,trace"`
	Latitude  string `json:"map822" groups:"short,normal,long,trace"`
	Altitude  string `json:"mapx400" groups:"short,normal,long,trace"`
}

type HINFOAnswer struct {
	Answer
	Cpu string `json:"cpu" groups:"short,normal,long,trace"`
	Os  string `json:"os" groups:"short,normal,long,trace"`
}

type HIPAnswer struct {
	Answer
	HitLength          uint8    `json:"hit_length" groups:"short,normal,long,trace"`
	PublicKeyAlgorithm uint8    `json:"pubkey_algo" groups:"short,normal,long,trace"`
	PublicKeyLength    uint16   `json:"pubkey_len" groups:"short,normal,long,trace"`
	Hit                string   `json:"hit" groups:"short,normal,long,trace"`
	PublicKey          string   `json:"pubkey" groups:"short,normal,long,trace"`
	RendezvousServers  []string `json:"rendezvous_servers" groups:"short,normal,long,trace"`
}

type MINFOAnswer struct {
	Answer
	Rmail string `json:"rmail" groups:"short,normal,long,trace"`
	Email string `json:"email" groups:"short,normal,long,trace"`
}

type MXAnswer struct {
	Answer
	Preference uint16 `json:"preference" groups:"short,normal,long,trace"`
}

type NAPTRAnswer struct {
	Answer
	Order       uint16 `json:"order" groups:"short,normal,long,trace"`
	Preference  uint16 `json:"preference" groups:"short,normal,long,trace"`
	Flags       string `json:"flags" groups:"short,normal,long,trace"`
	Service     string `json:"service" groups:"short,normal,long,trace"`
	Regexp      string `json:"regexp" groups:"short,normal,long,trace"`
	Replacement string `json:"replacement" groups:"short,normal,long,trace"`
}

type NIDAnswer struct {
	Answer
}

type NSEC3Answer struct {
	Answer
	HashAlgorithm uint8  `json:"hash_algorithm" groups:"short,normal,long,trace"`
	Flags         uint8  `json:"flags" groups:"short,normal,long,trace"`
	Iterations    uint16 `json:"iterations" groups:"short,normal,long,trace"`
	Salt          string `json:"salt" groups:"short,normal,long,trace"`
}

type NSEC3ParamAnswer struct {
	Answer
	HashAlgorithm uint8  `json:"hash_algorithm" groups:"short,normal,long,trace"`
	Flags         uint8  `json:"flags" groups:"short,normal,long,trace"`
	Iterations    uint16 `json:"iterations" groups:"short,normal,long,trace"`
	Salt          string `json:"salt" groups:"short,normal,long,trace"`
}

type PXAnswer struct {
	Answer
	Preference uint16 `json:"preference" groups:"short,normal,long,trace"`
	Map822     string `json:"map822" groups:"short,normal,long,trace"`
	Mapx400    string `json:"mapx400" groups:"short,normal,long,trace"`
}

type RRSIGAnswer struct {
	Answer
	TypeCovered uint16 `json:"type_covered" groups:"short,normal,long,trace"`
	Algorithm   uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	Labels      uint8  `json:"labels" groups:"short,normal,long,trace"`
	OriginalTtl uint32 `json:"original_ttl" groups:"short,normal,long,trace"`
	Expiration  uint32 `json:"expiration" groups:"short,normal,long,trace"`
	Inception   uint32 `json:"inception" groups:"short,normal,long,trace"`
	KeyTag      uint16 `json:"keytag" groups:"short,normal,long,trace"`
	SignerName  string `json:"signer_name" groups:"short,normal,long,trace"`
	Signature   string `json:"signature" groups:"short,normal,long,trace"`
}

type RPAnswer struct {
	Answer
	Mbox string `json:"mbox" groups:"short,normal,long,trace"`
	Txt  string `json:"txt" groups:"short,normal,long,trace"`
}

type RTAnswer struct {
	Answer
	Preference uint16 `json:"preference" groups:"short,normal,long,trace"`
	Host       string `json:"host" groups:"short,normal,long,trace"`
}

type SOAAnswer struct {
	Answer
	Ns      string `json:"ns" groups:"short,normal,long,trace"`
	Mbox    string `json:"mbox" groups:"short,normal,long,trace"`
	Serial  uint32 `json:"serial" groups:"short,normal,long,trace"`
	Refresh uint32 `json:"refresh" groups:"short,normal,long,trace"`
	Retry   uint32 `json:"retry" groups:"short,normal,long,trace"`
	Expire  uint32 `json:"expire" groups:"short,normal,long,trace"`
	Minttl  uint32 `json:"min_ttl" groups:"short,normal,long,trace"`
}

type SRVAnswer struct {
	Answer
	Priority uint16 `json:"priority" groups:"short,normal,long,trace"`
	Weight   uint16 `json:"weight" groups:"short,normal,long,trace"`
	Port     uint16 `json:"port" groups:"short,normal,long,trace"`
	Target   string `json:"target" groups:"short,normal,long,trace"`
}

type TLSAAnswer struct {
	Answer
	CertUsage    uint8  `json:"cert_usage" groups:"short,normal,long,trace"`
	Selector     uint8  `json:"selector" groups:"short,normal,long,trace"`
	MatchingType uint8  `json:"matching_type" groups:"short,normal,long,trace"`
	Certificate  string `json:"certificate" groups:"short,normal,long,trace"`
}

type X25Answer struct {
	Answer
	PSDNAddress string `json:"psdn_address" groups:"short,normal,long,trace"`
}

func makeBaseAnswer(hdr *dns.RR_Header, answer string) Answer {
	retv := Answer{
		Ttl:     hdr.Ttl,
		Type:    dns.Type(hdr.Rrtype).String(),
		rrType:  hdr.Rrtype,
		Class:   dns.Class(hdr.Class).String(),
		rrClass: hdr.Class,
		Name:    hdr.Name,
		Answer:  answer}
	retv.Name = strings.TrimSuffix(retv.Name, ".")
	return retv
}

func ParseAnswer(ans dns.RR) interface{} {
	switch cAns := ans.(type) {
	case *dns.A:
		return makeBaseAnswer(&cAns.Hdr, cAns.A.String())
	case *dns.AAAA:
		ip := cAns.AAAA.String()
		// verify we really got full 16-byte address
		if !cAns.AAAA.IsLoopback() && !cAns.AAAA.IsUnspecified() && len(cAns.AAAA) == net.IPv6len {
			if cAns.AAAA.To4() != nil {
				// we have a IPv4-mapped address, append prefix (#164)
				ip = "::ffff:" + ip
			} else {
				v4compat := true
				for _, o := range cAns.AAAA[:11] {
					if o != 0 {
						v4compat = false
						break
					}
				}
				if v4compat {
					// we have a IPv4-compatible address, append prefix (#164)
					ip = "::" + cAns.AAAA[12:].String()
				}
			}
		}
		return makeBaseAnswer(&cAns.Hdr, ip)
	case *dns.NS:
		return makeBaseAnswer(&cAns.Hdr, strings.TrimRight(cAns.Ns, "."))
	case *dns.CNAME:
		return makeBaseAnswer(&cAns.Hdr, cAns.Target)
	case *dns.DNAME:
		return makeBaseAnswer(&cAns.Hdr, cAns.Target)
	case *dns.TXT:
		return makeBaseAnswer(&cAns.Hdr, strings.Join(cAns.Txt, "\n"))
	case *dns.NULL:
		return makeBaseAnswer(&cAns.Hdr, cAns.Data)
	case *dns.PTR:
		return makeBaseAnswer(&cAns.Hdr, cAns.Ptr)
	case *dns.SPF:
		return makeBaseAnswer(&cAns.Hdr, cAns.String())
	case *dns.MB:
		return makeBaseAnswer(&cAns.Hdr, cAns.Mb)
	case *dns.MG:
		return makeBaseAnswer(&cAns.Hdr, cAns.Mg)
	case *dns.MF:
		return makeBaseAnswer(&cAns.Hdr, cAns.Mf)
	case *dns.MD:
		return makeBaseAnswer(&cAns.Hdr, cAns.Md)
	case *dns.AVC:
		return makeBaseAnswer(&cAns.Hdr, strings.Join(cAns.Txt, "\n"))
	case *dns.NINFO:
		return makeBaseAnswer(&cAns.Hdr, strings.Join(cAns.ZSData, "\n"))
	case *dns.MX:
		return MXAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, strings.TrimRight(cAns.Mx, ".")),
			Preference: cAns.Preference,
		}
	case *dns.DS:
		return DSAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, ""),
			KeyTag:     cAns.KeyTag,
			Algorithm:  cAns.Algorithm,
			DigestType: cAns.DigestType,
			Digest:     cAns.Digest,
		}
	case *dns.CDS:
		return DSAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, ""),
			KeyTag:     cAns.KeyTag,
			Algorithm:  cAns.Algorithm,
			DigestType: cAns.DigestType,
			Digest:     cAns.Digest,
		}
	case *dns.CAA:
		return CAAAnswer{
			Answer: makeBaseAnswer(&cAns.Hdr, ""),
			Tag:    cAns.Tag,
			Value:  cAns.Value,
			Flag:   cAns.Flag,
		}
	case *dns.SOA:
		return SOAAnswer{
			Answer:  makeBaseAnswer(&cAns.Hdr, ""),
			Ns:      strings.TrimSuffix(cAns.Ns, "."),
			Mbox:    strings.TrimSuffix(cAns.Mbox, "."),
			Serial:  cAns.Serial,
			Refresh: cAns.Refresh,
			Retry:   cAns.Retry,
			Expire:  cAns.Expire,
			Minttl:  cAns.Minttl,
		}
	case *dns.SRV:
		return SRVAnswer{
			Answer:   makeBaseAnswer(&cAns.Hdr, ""),
			Priority: cAns.Priority,
			Weight:   cAns.Weight,
			Port:     cAns.Port,
			Target:   cAns.Target,
		}
	case *dns.TLSA:
		return TLSAAnswer{
			Answer:       makeBaseAnswer(&cAns.Hdr, ""),
			CertUsage:    cAns.Usage,
			Selector:     cAns.Selector,
			MatchingType: cAns.MatchingType,
			Certificate:  cAns.Certificate,
		}
	case *dns.NSEC:
		return makeBaseAnswer(&cAns.Hdr, strings.TrimSuffix(cAns.NextDomain, "."))
	case *dns.NAPTR:
		return NAPTRAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			Order:       cAns.Order,
			Preference:  cAns.Preference,
			Flags:       cAns.Flags,
			Service:     cAns.Service,
			Regexp:      cAns.Regexp,
			Replacement: cAns.Replacement,
		}
	case *dns.SIG:
		return RRSIGAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			TypeCovered: cAns.TypeCovered,
			Algorithm:   cAns.Algorithm,
			Labels:      cAns.Labels,
			OriginalTtl: cAns.OrigTtl,
			Expiration:  cAns.Expiration,
			Inception:   cAns.Inception,
			KeyTag:      cAns.KeyTag,
			SignerName:  cAns.SignerName,
			Signature:   cAns.Signature,
		}
	case *dns.RRSIG:
		return RRSIGAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			TypeCovered: cAns.TypeCovered,
			Algorithm:   cAns.Algorithm,
			Labels:      cAns.Labels,
			OriginalTtl: cAns.OrigTtl,
			Expiration:  cAns.Expiration,
			Inception:   cAns.Inception,
			KeyTag:      cAns.KeyTag,
			SignerName:  cAns.SignerName,
			Signature:   cAns.Signature,
		}
	case *dns.HINFO:
		return HINFOAnswer{
			Answer: makeBaseAnswer(&cAns.Hdr, ""),
			Cpu:    cAns.Cpu,
			Os:     cAns.Os,
		}
	case *dns.MINFO:
		return MINFOAnswer{
			Answer: makeBaseAnswer(&cAns.Hdr, ""),
			Rmail:  cAns.Rmail,
			Email:  cAns.Email,
		}
	case *dns.NSEC3:
		return NSEC3Answer{
			Answer:        makeBaseAnswer(&cAns.Hdr, ""),
			HashAlgorithm: cAns.Hash,
			Flags:         cAns.Flags,
			Iterations:    cAns.Iterations,
			Salt:          cAns.Salt,
		}
	case *dns.NSEC3PARAM:
		return NSEC3Answer{
			Answer:        makeBaseAnswer(&cAns.Hdr, ""),
			HashAlgorithm: cAns.Hash,
			Flags:         cAns.Flags,
			Iterations:    cAns.Iterations,
			Salt:          cAns.Salt,
		}
	case *dns.DNSKEY: // does this work for CDNSKEY?
		return DNSKEYAnswer{
			Answer:    makeBaseAnswer(&cAns.Hdr, ""),
			Flags:     cAns.Flags,
			Protocol:  cAns.Protocol,
			Algorithm: cAns.Algorithm,
			PublicKey: cAns.PublicKey,
		}
	case *dns.AFSDB:
		return AFSDBAnswer{
			Answer:   makeBaseAnswer(&cAns.Hdr, ""),
			Subtype:  cAns.Subtype,
			Hostname: cAns.Hostname,
		}
	case *dns.RT:
		return RTAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, ""),
			Preference: cAns.Preference,
			Host:       cAns.Host,
		}
	case *dns.X25:
		return X25Answer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			PSDNAddress: cAns.PSDNAddress,
		}
	case *dns.CERT:
		return CERTAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			Type:        cAns.Type,
			KeyTag:      cAns.KeyTag,
			Algorithm:   cAns.Algorithm,
			Certificate: cAns.Certificate,
		}
	case *dns.PX:
		return PXAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, ""),
			Preference: cAns.Preference,
			Map822:     cAns.Map822,
			Mapx400:    cAns.Mapx400,
		}
	case *dns.GPOS:
		return GPOSAnswer{
			Answer:    makeBaseAnswer(&cAns.Hdr, ""),
			Longitude: cAns.Longitude,
			Latitude:  cAns.Latitude,
			Altitude:  cAns.Altitude,
		}
	case *dns.HIP:
		return HIPAnswer{
			Answer:             makeBaseAnswer(&cAns.Hdr, ""),
			HitLength:          cAns.HitLength,
			PublicKeyAlgorithm: cAns.PublicKeyAlgorithm,
			PublicKeyLength:    cAns.PublicKeyLength,
			Hit:                cAns.Hit,
			PublicKey:          cAns.PublicKey,
			RendezvousServers:  cAns.RendezvousServers,
		}
	default:
		return struct {
			Type     string `json:"type"`
			rrType   uint16
			Class    string `json:"class"`
			rrClass  uint16
			Unparsed dns.RR `json:"-"`
		}{
			Type:     dns.Type(ans.Header().Rrtype).String(),
			rrType:   ans.Header().Rrtype,
			Class:    dns.Class(ans.Header().Class).String(),
			rrClass:  ans.Header().Class,
			Unparsed: ans,
		}
	}
}
