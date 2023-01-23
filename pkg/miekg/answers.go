/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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

package miekg

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/dns"
)

type Answer struct {
	Ttl     uint32 `json:"ttl" groups:"ttl,normal,long,trace"`
	Type    string `json:"type,omitempty" groups:"short,normal,long,trace"`
	RrType  uint16 `json:"-"`
	Class   string `json:"class,omitempty" groups:"short,normal,long,trace"`
	RrClass uint16 `json:"-"`
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
	Type        string `json:"type" groups:"short,normal,long,trace"`
	KeyTag      uint16 `json:"keytag" groups:"short,normal,long,trace"`
	Algorithm   string `json:"algorithm" groups:"short,normal,long,trace"`
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

type EDNSAnswer struct {
	Type    string `json:"type" groups:"short,normal,long,trace"`
	Version uint8  `json:"version" groups:"short,normal,long,trace"`
	Flags   string `json:"flags" groups:"short,normal,long,trace"`
	UDPSize uint16 `json:"udpsize" groups:"short,normal,long,trace"`
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

type LOCAnswer struct {
	Answer
	Version   uint8  `json:"version" groups:"short,normal,long,trace"`
	Size      uint8  `json:"size" groups:"short,normal,long,trace"`
	HorizPre  uint8  `json:"horizontal_pre" groups:"short,normal,long,trace"`
	VertPre   uint8  `json:"vertical_pre" groups:"short,normal,long,trace"`
	Latitude  uint32 `json:"latitude" groups:"short,normal,long,trace"`
	Longitude uint32 `json:"longitude" groups:"short,normal,long,trace"`
	Altitude  uint32 `json:"altitude" groups:"short,normal,long,trace"`
}

type MINFOAnswer struct {
	Answer
	Rmail string `json:"rmail" groups:"short,normal,long,trace"`
	Email string `json:"email" groups:"short,normal,long,trace"`
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

type NSECAnswer struct {
	Answer
	NextDomain string `json:"next_domain" groups:"short,normal,long,trace"`
	// TODO(zakir): this name doesn't seem right. Look at RFC.
	TypeBitMap string `json:"type_bit_map" groups:"short,normal,long,trace"`
}

type NSEC3Answer struct {
	Answer
	HashAlgorithm uint8  `json:"hash_algorithm" groups:"short,normal,long,trace"`
	Flags         uint8  `json:"flags" groups:"short,normal,long,trace"`
	Iterations    uint16 `json:"iterations" groups:"short,normal,long,trace"`
	Salt          string `json:"salt" groups:"short,normal,long,trace"`
	NextDomain    string `json:"next_domain" groups:"short,normal,long,trace"`
	TypeBitMap    string `json:"type_bit_map" groups:"short,normal,long,trace"`
}

type NSEC3ParamAnswer struct {
	Answer
	HashAlgorithm uint8  `json:"hash_algorithm" groups:"short,normal,long,trace"`
	Flags         uint8  `json:"flags" groups:"short,normal,long,trace"`
	Iterations    uint16 `json:"iterations" groups:"short,normal,long,trace"`
	Salt          string `json:"salt" groups:"short,normal,long,trace"`
}

type PrefAnswer struct {
	Answer
	Preference uint16 `json:"preference" groups:"short,normal,long,trace"`
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
	Expiration  string `json:"expiration" groups:"short,normal,long,trace"`
	Inception   string `json:"inception" groups:"short,normal,long,trace"`
	KeyTag      uint16 `json:"keytag" groups:"short,normal,long,trace"`
	SignerName  string `json:"signer_name" groups:"short,normal,long,trace"`
	Signature   string `json:"signature" groups:"short,normal,long,trace"`
}

type RPAnswer struct {
	Answer
	Mbox string `json:"mbox" groups:"short,normal,long,trace"`
	Txt  string `json:"txt" groups:"short,normal,long,trace"`
}

type SMIMEAAnswer struct {
	Answer
	Usage        uint8  `json:"usage" groups:"short,normal,long,trace"`
	Selector     uint8  `json:"selector" groups:"short,normal,long,trace"`
	MatchingType uint8  `json:"matching_type" groups:"short,normal,long,trace"`
	Certificate  string `json:"certificate" groups:"short,normal,long,trace"`
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

type SSHFPAnswer struct {
	Answer
	Algorithm   uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	Type        uint8  `json:"type" groups:"short,normal,long,trace"`
	FingerPrint string `json:"fingerprint" groups:"short,normal,long,trace"`
}

type SRVAnswer struct {
	Answer
	Priority uint16 `json:"priority" groups:"short,normal,long,trace"`
	Weight   uint16 `json:"weight" groups:"short,normal,long,trace"`
	Port     uint16 `json:"port" groups:"short,normal,long,trace"`
	Target   string `json:"target" groups:"short,normal,long,trace"`
}

type SVCBAnswer struct {
	Answer
	Priority  uint16                 `json:"priority" groups:"short,normal,long,trace"`
	Target    string                 `json:"target" groups:"short,normal,long,trace"`
	SVCParams map[string]interface{} `json:"svcparams,omitempty" groups:"short,normal,long,trace"`
}

type TKEYAnswer struct {
	Answer
	Algorithm  string `json:"algorithm" groups:"short,normal,long,trace"`
	Inception  string `json:"inception" groups:"short,normal,long,trace"`
	Expiration string `json:"expiration" groups:"short,normal,long,trace"`
	Mode       uint16 `json:"mode" groups:"short,normal,long,trace"`
	Error      uint16 `json:"error" groups:"short,normal,long,trace"`
	KeySize    uint16 `json:"key_size" groups:"short,normal,long,trace"`
	Key        string `json:"key" groups:"short,normal,long,trace"`
	OtherLen   uint16 `json:"other_len" groups:"short,normal,long,trace"`
	OtherData  string `json:"other_data" groups:"short,normal,long,trace"`
}

type TLSAAnswer struct {
	Answer
	CertUsage    uint8  `json:"cert_usage" groups:"short,normal,long,trace"`
	Selector     uint8  `json:"selector" groups:"short,normal,long,trace"`
	MatchingType uint8  `json:"matching_type" groups:"short,normal,long,trace"`
	Certificate  string `json:"certificate" groups:"short,normal,long,trace"`
}

type TALINKAnswer struct {
	Answer
	PreviousName string `json:"previous_name" groups:"short,normal,long,trace"`
	NextName     string `json:"next_name" groups:"short,normal,long,trace"`
}

type URIAnswer struct {
	Answer
	Priority uint16 `json:"previous_name" groups:"short,normal,long,trace"`
	Weight   uint16 `json:"previous_name" groups:"short,normal,long,trace"`
	Target   string `json:"previous_name" groups:"short,normal,long,trace"`
}

// copy-paste from zmap/dns/types.go >>>>>
//
// Copyright (c) 2009 The Go Authors.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

const (
	escapedByteSmall = "" +
		`\000\001\002\003\004\005\006\007\008\009` +
		`\010\011\012\013\014\015\016\017\018\019` +
		`\020\021\022\023\024\025\026\027\028\029` +
		`\030\031`
	escapedByteLarge = `\127\128\129` +
		`\130\131\132\133\134\135\136\137\138\139` +
		`\140\141\142\143\144\145\146\147\148\149` +
		`\150\151\152\153\154\155\156\157\158\159` +
		`\160\161\162\163\164\165\166\167\168\169` +
		`\170\171\172\173\174\175\176\177\178\179` +
		`\180\181\182\183\184\185\186\187\188\189` +
		`\190\191\192\193\194\195\196\197\198\199` +
		`\200\201\202\203\204\205\206\207\208\209` +
		`\210\211\212\213\214\215\216\217\218\219` +
		`\220\221\222\223\224\225\226\227\228\229` +
		`\230\231\232\233\234\235\236\237\238\239` +
		`\240\241\242\243\244\245\246\247\248\249` +
		`\250\251\252\253\254\255`
)

func escapeByte(b byte) string {
	if b < ' ' {
		return escapedByteSmall[b*4 : b*4+4]
	}

	b -= '~' + 1
	// The cast here is needed as b*4 may overflow byte.
	return escapedByteLarge[int(b)*4 : int(b)*4+4]
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func dddStringToByte(s string) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func nextByte(s string, offset int) (byte, int) {
	if offset >= len(s) {
		return 0, 0
	}
	if s[offset] != '\\' {
		// not an escape sequence
		return s[offset], 1
	}
	switch len(s) - offset {
	case 1: // dangling escape
		return 0, 0
	case 2, 3: // too short to be \ddd
	default: // maybe \ddd
		if isDigit(s[offset+1]) && isDigit(s[offset+2]) && isDigit(s[offset+3]) {
			return dddStringToByte(s[offset+1:]), 4
		}
	}
	// not \ddd, just an RFC 1035 "quoted" character
	return s[offset+1], 2
}
func euiToString(eui uint64, bits int) (hex string) {
	switch bits {
	case 64:
		hex = fmt.Sprintf("%16.16x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12] + "-" + hex[12:14] + "-" + hex[14:16]
	case 48:
		hex = fmt.Sprintf("%12.12x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12]
	}
	return
}

func sprintTxtOctet(s string) string {
	var dst strings.Builder
	dst.Grow(2 + len(s))
	dst.WriteByte('"')
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '\\' && s[i+1] == '.' {
			dst.WriteString(s[i : i+2])
			i += 2
			continue
		}
		b, n := nextByte(s, i)
		switch {
		case n == 0:
			i++ // dangling back slash
		case b == '.':
			dst.WriteByte('.')
		case b < ' ' || b > '~':
			dst.WriteString(escapeByte(b))
		default:
			dst.WriteByte(b)
		}
		i += n
	}
	dst.WriteByte('"')
	return dst.String()
}

// <<<<< END GOOGLE CODE

func makeBitString(bm []uint16) string {
	retv := ""
	for _, v := range bm {
		if retv == "" {
			retv += dns.Type(v).String()
		} else {
			retv += " " + dns.Type(v).String()
		}
	}
	return retv
}

func makeBaseAnswer(hdr *dns.RR_Header, answer string) Answer {
	return Answer{
		Ttl:     hdr.Ttl,
		Type:    dns.Type(hdr.Rrtype).String(),
		RrType:  hdr.Rrtype,
		Class:   dns.Class(hdr.Class).String(),
		RrClass: hdr.Class,
		Name:    strings.TrimSuffix(hdr.Name, "."),
		Answer:  answer}
}

func makeSVCBAnswer(cAns *dns.SVCB) SVCBAnswer {
	var params map[string]interface{}
	if len(cAns.Value) > 0 {
		params = make(map[string]interface{})
		for _, ikv := range cAns.Value {
			// this could be reduced by adding, e.g., a new Data()
			// method to the zmap/dns SVCBKeyValue interface
			switch kv := ikv.(type) {
			case *dns.SVCBMandatory:
				keys := make([]string, len(kv.Code))
				for i, e := range kv.Code {
					keys[i] = e.String()
				}
				params[ikv.Key().String()] = keys
			case *dns.SVCBAlpn:
				params[ikv.Key().String()] = kv.Alpn
			case *dns.SVCBNoDefaultAlpn:
				params[ikv.Key().String()] = true
			case *dns.SVCBPort:
				params[ikv.Key().String()] = kv.Port
			case *dns.SVCBIPv4Hint:
				params[ikv.Key().String()] = kv.Hint
			case *dns.SVCBECHConfig:
				params[ikv.Key().String()] = kv.ECH
			case *dns.SVCBIPv6Hint:
				params[ikv.Key().String()] = kv.Hint
			case *dns.SVCBLocal: //SVCBLocal is the default case for unknown keys
				params[ikv.Key().String()] = kv.Data
			default: //should not happen
				params["unknown"] = true
			}
		}
	}
	return SVCBAnswer{
		Answer:    makeBaseAnswer(&cAns.Hdr, ""),
		Priority:  cAns.Priority,
		Target:    cAns.Target,
		SVCParams: params,
	}
}

func makeEDNSAnswer(cAns *dns.OPT) EDNSAnswer {
	opttype := "EDNS"
	flags := ""
	if cAns.Do() {
		flags = "do"
	}
	return EDNSAnswer{
		Type:       opttype + strconv.Itoa(int(cAns.Version())),
		Version:    cAns.Version(),
		// RCODE omitted for now as no EDNS0 extension is supported in
		// lookups for which an RCODE is defined.
		//Rcode:      dns.RcodeToString[cAns.ExtendedRcode()],
		Flags:      flags,
		UDPSize:    cAns.UDPSize(),
	}
}

func ParseAnswer(ans dns.RR) interface{} {
	switch cAns := ans.(type) {
	// Prioritize common types in expected order
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
		return makeBaseAnswer(&cAns.Hdr, cAns.Ns)
	case *dns.CNAME:
		return makeBaseAnswer(&cAns.Hdr, cAns.Target)
	case *dns.DNAME:
		return makeBaseAnswer(&cAns.Hdr, cAns.Target)
	case *dns.PTR:
		return makeBaseAnswer(&cAns.Hdr, cAns.Ptr)
	case *dns.MX:
		return PrefAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, cAns.Mx),
			Preference: cAns.Preference,
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
	case *dns.TXT:
		return makeBaseAnswer(&cAns.Hdr, strings.Join(cAns.Txt, "\n"))
	case *dns.CAA:
		return CAAAnswer{
			Answer: makeBaseAnswer(&cAns.Hdr, ""),
			Tag:    cAns.Tag,
			Value:  cAns.Value,
			Flag:   cAns.Flag,
		}
	case *dns.SRV:
		return SRVAnswer{
			Answer:   makeBaseAnswer(&cAns.Hdr, ""),
			Priority: cAns.Priority,
			Weight:   cAns.Weight,
			Port:     cAns.Port,
			Target:   cAns.Target,
		}
	case *dns.SPF:
		return makeBaseAnswer(&cAns.Hdr, cAns.String())
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
	case *dns.RRSIG:
		return RRSIGAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			TypeCovered: cAns.TypeCovered,
			Algorithm:   cAns.Algorithm,
			Labels:      cAns.Labels,
			OriginalTtl: cAns.OrigTtl,
			Expiration:  dns.TimeToString(cAns.Expiration),
			Inception:   dns.TimeToString(cAns.Inception),
			KeyTag:      cAns.KeyTag,
			SignerName:  cAns.SignerName,
			Signature:   cAns.Signature,
		}
	// begin "the rest". Protocols we won't very likely ever see and order
	// would is effectively random. Hopefully, folks who are you using these
	// are going to use them everywhere and branch prediction helps out. Not
	// much else that we could do other than not try to parse them, which is
	// worse
	case *dns.NULL:
		return makeBaseAnswer(&cAns.Hdr, cAns.Data)
	case *dns.MB:
		return makeBaseAnswer(&cAns.Hdr, cAns.Mb)
	case *dns.MG:
		return makeBaseAnswer(&cAns.Hdr, cAns.Mg)
	case *dns.MF:
		return makeBaseAnswer(&cAns.Hdr, cAns.Mf)
	case *dns.MD:
		return makeBaseAnswer(&cAns.Hdr, cAns.Md)
	case *dns.NSAPPTR:
		return makeBaseAnswer(&cAns.Hdr, cAns.Ptr)
	case *dns.NIMLOC:
		return makeBaseAnswer(&cAns.Hdr, cAns.Locator)
	case *dns.OPENPGPKEY:
		return makeBaseAnswer(&cAns.Hdr, cAns.PublicKey)
	case *dns.AVC:
		return makeBaseAnswer(&cAns.Hdr, strings.Join(cAns.Txt, "\n"))
	case *dns.EID:
		return makeBaseAnswer(&cAns.Hdr, cAns.Endpoint)
	case *dns.UINFO:
		return makeBaseAnswer(&cAns.Hdr, cAns.Uinfo)
	case *dns.DHCID:
		return makeBaseAnswer(&cAns.Hdr, cAns.Digest)
	case *dns.NINFO:
		return makeBaseAnswer(&cAns.Hdr, strings.Join(cAns.ZSData, "\n"))
	case *dns.TKEY:
		return TKEYAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, ""),
			Algorithm:  cAns.Algorithm,
			Expiration: dns.TimeToString(cAns.Expiration),
			Inception:  dns.TimeToString(cAns.Inception),
			Mode:       cAns.Mode,
			Error:      cAns.Error,
			KeySize:    cAns.KeySize,
			Key:        cAns.Key,
			OtherLen:   cAns.OtherLen,
			OtherData:  cAns.OtherData,
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
		return NSECAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, ""),
			NextDomain: strings.TrimSuffix(cAns.NextDomain, "."),
			TypeBitMap: makeBitString(cAns.TypeBitMap),
		}
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
			Expiration:  dns.TimeToString(cAns.Expiration),
			Inception:   dns.TimeToString(cAns.Inception),
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
			NextDomain:    cAns.NextDomain,
			TypeBitMap:    makeBitString(cAns.TypeBitMap),
		}
	case *dns.NSEC3PARAM:
		return NSEC3Answer{
			Answer:        makeBaseAnswer(&cAns.Hdr, ""),
			HashAlgorithm: cAns.Hash,
			Flags:         cAns.Flags,
			Iterations:    cAns.Iterations,
			Salt:          cAns.Salt,
		}
	case *dns.DNSKEY:
		return DNSKEYAnswer{
			Answer:    makeBaseAnswer(&cAns.Hdr, ""),
			Flags:     cAns.Flags,
			Protocol:  cAns.Protocol,
			Algorithm: cAns.Algorithm,
			PublicKey: cAns.PublicKey,
		}
	case *dns.CDNSKEY:
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
		return PrefAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, cAns.Host),
			Preference: cAns.Preference,
		}
	case *dns.NID:
		node := fmt.Sprintf("%0.16x", cAns.NodeID)
		return PrefAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, node),
			Preference: cAns.Preference,
		}
	case *dns.X25:
		return makeBaseAnswer(&cAns.Hdr, cAns.PSDNAddress)
	case *dns.CERT:
		return CERTAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			Type:        dns.CertTypeToString[cAns.Type],
			KeyTag:      cAns.KeyTag,
			Algorithm:   dns.AlgorithmToString[cAns.Algorithm],
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
	case *dns.LOC:
		// This has the raw DNS values, which are not very human readable
		// TODO: convert DNS types into usable values
		return LOCAnswer{
			Answer:    makeBaseAnswer(&cAns.Hdr, ""),
			Version:   cAns.Version,
			Size:      cAns.Size,
			HorizPre:  cAns.HorizPre,
			VertPre:   cAns.VertPre,
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
	case *dns.KX:
		return PrefAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, cAns.Exchanger),
			Preference: cAns.Preference,
		}
	case *dns.SSHFP:
		return SSHFPAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			Algorithm:   cAns.Algorithm,
			Type:        cAns.Type,
			FingerPrint: cAns.FingerPrint,
		}
	case *dns.SMIMEA:
		return SMIMEAAnswer{
			Answer:       makeBaseAnswer(&cAns.Hdr, ""),
			Usage:        cAns.Usage,
			Selector:     cAns.Selector,
			MatchingType: cAns.MatchingType,
			Certificate:  cAns.Certificate,
		}
	case *dns.TALINK:
		return TALINKAnswer{
			Answer:       makeBaseAnswer(&cAns.Hdr, ""),
			PreviousName: cAns.PreviousName,
			NextName:     cAns.NextName,
		}
	case *dns.L32:
		return PrefAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, cAns.Locator32.String()),
			Preference: cAns.Preference,
		}
	case *dns.L64:
		node := fmt.Sprintf("%0.16X", cAns.Locator64)
		return PrefAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, node),
			Preference: cAns.Preference,
		}
	case *dns.EUI48:
		return makeBaseAnswer(&cAns.Hdr, euiToString(cAns.Address, 48))
	case *dns.EUI64:
		return makeBaseAnswer(&cAns.Hdr, euiToString(cAns.Address, 64))
	case *dns.UID:
		return makeBaseAnswer(&cAns.Hdr, strconv.FormatInt(int64(cAns.Uid), 10))
	case *dns.GID:
		return makeBaseAnswer(&cAns.Hdr, strconv.FormatInt(int64(cAns.Gid), 10))
	case *dns.LP:
		return PrefAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, cAns.Fqdn),
			Preference: cAns.Preference,
		}
	case *dns.HTTPS:
		return makeSVCBAnswer(&cAns.SVCB)
	case *dns.SVCB:
		return makeSVCBAnswer(cAns)
	case *dns.OPT:
		return makeEDNSAnswer(cAns)
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
