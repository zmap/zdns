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

package zdns

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

//go:generate go run answers_generate.go

type WithBaseAnswer interface {
	BaseAns() *Answer
}

type Answer struct {
	TTL     uint32 `json:"ttl" groups:"ttl,normal,long,trace"`
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

type CSYNCAnswer struct {
	Answer
	Serial     uint32 `json:"serial" groups:"short,normal,long,trace"`
	Flags      uint16 `json:"flags" groups:"short,normal,long,trace"`
	TypeBitMap string `json:"type_bit_map" groups:"short,normal,long,trace"`
}

type DNSKEYAnswer struct {
	Answer
	Flags     uint16 `json:"flags" groups:"short,normal,long,trace"`
	Protocol  uint8  `json:"protocol" groups:"short,normal,long,trace"`
	Algorithm uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	PublicKey string `json:"public_key" groups:"short,normal,long,trace"`
}

func (r *DNSKEYAnswer) ToVanillaType() *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.CanonicalName(r.Name),
			Rrtype: r.RrType,
			Class:  dns.StringToClass[r.Class],
			Ttl:    r.TTL,
		},
		Flags:     r.Flags,
		Protocol:  r.Protocol,
		Algorithm: r.Algorithm,
		PublicKey: r.PublicKey,
	}
}

type DSAnswer struct {
	Answer
	KeyTag     uint16 `json:"key_tag" groups:"short,normal,long,trace"`
	Algorithm  uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	DigestType uint8  `json:"digest_type" groups:"short,normal,long,trace"`
	Digest     string `json:"digest" groups:"short,normal,long,trace"`
}

func (r *DSAnswer) ToVanillaType() *dns.DS {
	return &dns.DS{
		Hdr: dns.RR_Header{

			Name:   dns.CanonicalName(r.Name),
			Rrtype: r.RrType,
			Class:  dns.StringToClass[r.Class],
			Ttl:    r.TTL,
		},
		KeyTag:     r.KeyTag,
		Algorithm:  r.Algorithm,
		DigestType: r.DigestType,
		Digest:     r.Digest,
	}
}

type GPOSAnswer struct {
	Answer
	Longitude string `json:"preference" groups:"short,normal,long,trace"`
	Latitude  string `json:"map822" groups:"short,normal,long,trace"`
	Altitude  string `json:"mapx400" groups:"short,normal,long,trace"`
}

type HINFOAnswer struct {
	Answer
	CPU string `json:"cpu" groups:"short,normal,long,trace"`
	OS  string `json:"os" groups:"short,normal,long,trace"`
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

func (r *NSECAnswer) ToVanillaType() *dns.NSEC {
	return &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   dns.CanonicalName(r.Name),
			Rrtype: r.RrType,
			Class:  dns.StringToClass[r.Class],
			Ttl:    r.TTL,
		},
		NextDomain: r.NextDomain,
		TypeBitMap: makeBitArray(r.TypeBitMap),
	}
}

type NSEC3Answer struct {
	Answer
	HashAlgorithm uint8  `json:"hash_algorithm" groups:"short,normal,long,trace"`
	Flags         uint8  `json:"flags" groups:"short,normal,long,trace"`
	Iterations    uint16 `json:"iterations" groups:"short,normal,long,trace"`
	SaltLength    uint8  `json:"salt_length" groups:"short,normal,long,trace"`
	Salt          string `json:"salt" groups:"short,normal,long,trace"`
	HashLength    uint8  `json:"hash_length" groups:"short,normal,long,trace"`
	NextDomain    string `json:"next_domain" groups:"short,normal,long,trace"`
	TypeBitMap    string `json:"type_bit_map" groups:"short,normal,long,trace"`
}

func (r *NSEC3Answer) ToVanillaType() *dns.NSEC3 {
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   dns.CanonicalName(r.Name),
			Rrtype: r.RrType,
			Class:  dns.StringToClass[r.Class],
			Ttl:    r.TTL,
		},
		Hash:       r.HashAlgorithm,
		Flags:      r.Flags,
		Iterations: r.Iterations,
		SaltLength: uint8(len(r.Salt)),
		Salt:       r.Salt,
		HashLength: r.HashLength,
		NextDomain: r.NextDomain,
		TypeBitMap: makeBitArray(r.TypeBitMap),
	}
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
	OriginalTTL uint32 `json:"original_ttl" groups:"short,normal,long,trace"`
	Expiration  string `json:"expiration" groups:"short,normal,long,trace"`
	Inception   string `json:"inception" groups:"short,normal,long,trace"`
	KeyTag      uint16 `json:"keytag" groups:"short,normal,long,trace"`
	SignerName  string `json:"signer_name" groups:"short,normal,long,trace"`
	Signature   string `json:"signature" groups:"short,normal,long,trace"`
}

func (r *RRSIGAnswer) ToVanillaType() *dns.RRSIG {
	expiration, err := dns.StringToTime(r.Expiration)
	if err != nil {
		panic("failed to parse expiration time: " + r.Expiration)
	}

	inception, err := dns.StringToTime(r.Inception)
	if err != nil {
		panic("failed to parse inception time: " + r.Inception)
	}

	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.CanonicalName(r.Name),
			Rrtype: r.RrType,
			Class:  dns.StringToClass[r.Class],
			Ttl:    r.TTL,
		},
		TypeCovered: r.TypeCovered,
		Algorithm:   r.Algorithm,
		Labels:      r.Labels,
		OrigTtl:     r.OriginalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      r.KeyTag,
		SignerName:  r.SignerName,
		Signature:   r.Signature,
	}
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
	Priority uint16 `json:"priority" groups:"short,normal,long,trace"`
	Weight   uint16 `json:"weight" groups:"short,normal,long,trace"`
	Target   string `json:"target" groups:"short,normal,long,trace"`
}

type AMTRELAYAnswer struct {
	Answer      `json:"answer"`
	Precedence  uint8  `json:"precedence,omitempty" groups:"short,normal,long,trace"`
	GatewayType uint8  `json:"gateway_type,omitempty" groups:"short,normal,long,trace"`
	GatewayAddr net.IP `json:"gateway_addr,omitempty" groups:"short,normal,long,trace"`
	GatewayHost string `json:"gateway_host,omitempty" groups:"short,normal,long,trace"`
}

type APLAnswer struct {
	Answer
	Prefixes []APLPrefix `json:"prefixes" groups:"short,normal,long,trace"`
}

type APLPrefix struct {
	Negation bool      `json:"negation" groups:"short,normal,long,trace"`
	Network  net.IPNet `json:"network" groups:"short,normal,long,trace"`
}

type IPSECKEYAnswer struct {
	Answer
	Precedence  uint8  `json:"precedence" groups:"short,normal,long,trace"`
	GatewayType uint8  `json:"gateway_type" groups:"short,normal,long,trace"`
	Algorithm   uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	GatewayAddr net.IP `json:"gateway_addr" groups:"short,normal,long,trace"`
	GatewayHost string `json:"gateway_host" groups:"short,normal,long,trace"`
	PublicKey   string `json:"public_key" groups:"short,normal,long,trace"`
}

type NXTAnswer struct {
	NSECAnswer
}

type RKEYAnswer struct {
	Answer
	Flags     uint16 `json:"flags" groups:"short,normal,long,trace"`
	Protocol  uint8  `json:"protocol" groups:"short,normal,long,trace"`
	Algorithm uint8  `json:"algorithm" groups:"short,normal,long,trace"`
	PublicKey string `json:"public_key" groups:"short,normal,long,trace"`
}

type ZONEMDAnswer struct {
	Answer
	Serial uint32 `json:"serial" groups:"short,normal,long,trace"`
	Scheme uint8  `json:"scheme" groups:"short,normal,long,trace"`
	Hash   uint8  `json:"hash" groups:"short,normal,long,trace"`
	Digest string `json:"digest" groups:"short,normal,long,trace"`
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

func makeBitArray(s string) []uint16 {
	fields := strings.Fields(s)
	retv := make([]uint16, 0, len(fields))
	for _, t := range fields {
		retv = append(retv, dns.StringToType[t])
	}
	return retv
}

func makeBaseAnswer(hdr *dns.RR_Header, answer string) Answer {
	return Answer{
		TTL:     hdr.Ttl,
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
	optRes := EDNSAnswer{
		Type:    opttype + strconv.Itoa(int(cAns.Version())),
		Version: cAns.Version(),
		// RCODE omitted for now as no EDNS0 extension is supported in
		// lookups for which an RCODE is defined.
		//Rcode:      dns.RcodeToString[cAns.ExtendedRcode()],
		Flags:   flags,
		UDPSize: cAns.UDPSize(),
	}

	for _, o := range cAns.Option {
		switch opt := o.(type) {
		case *dns.EDNS0_LLQ: //OPT 1
			optRes.LLQ = &Edns0LLQ{
				Code:      opt.Code,
				Version:   opt.Version,
				Opcode:    opt.Opcode,
				Error:     opt.Error,
				ID:        opt.Id,
				LeaseLife: opt.LeaseLife,
			}
		case *dns.EDNS0_UL: // OPT 2
			optRes.UL = &Edns0UL{
				Code:     opt.Code,
				Lease:    opt.Lease,
				KeyLease: opt.KeyLease,
			}
		case *dns.EDNS0_NSID: //OPT 3
			hexDecoded, err := hex.DecodeString(opt.Nsid)
			if err != nil {
				continue
			}
			optRes.NSID = &Edns0NSID{Nsid: string(hexDecoded)}
		case *dns.EDNS0_DAU: //OPT 5
			optRes.DAU = &Edns0DAU{
				Code:    opt.Code,
				AlgCode: opt.String(),
			}
		case *dns.EDNS0_DHU: //OPT 6
			optRes.DHU = &Edns0DHU{
				Code:    opt.Code,
				AlgCode: opt.String(),
			}
		case *dns.EDNS0_N3U: //OPT 7
			optRes.N3U = &Edns0N3U{
				Code:    opt.Code,
				AlgCode: opt.String(),
			}
		case *dns.EDNS0_SUBNET: //OPT 8
			optRes.ClientSubnet = &Edns0ClientSubnet{
				SourceScope:   opt.SourceScope,
				Family:        opt.Family,
				Address:       opt.Address.String(),
				SourceNetmask: opt.SourceNetmask,
			}
		case *dns.EDNS0_EXPIRE: //OPT 9
			optRes.Expire = &Edns0Expire{
				Code:   opt.Code,
				Expire: opt.Expire,
			}
		case *dns.EDNS0_COOKIE: //OPT 11
			optRes.Cookie = &Edns0Cookie{Cookie: opt.Cookie}
		case *dns.EDNS0_TCP_KEEPALIVE: //OPT 11
			optRes.TCPKeepalive = &Edns0TCPKeepalive{
				Code:    opt.Code,
				Timeout: opt.Timeout,
				Length:  opt.Length, // deprecated, always equal to 0, keeping it here for a better readability
			}
		case *dns.EDNS0_PADDING: //OPT 12
			optRes.Padding = &Edns0Padding{Padding: opt.String()}
		case *dns.EDNS0_EDE: //OPT 15
			optRes.EDE = append(optRes.EDE, &Edns0Ede{
				InfoCode:      opt.InfoCode,
				ErrorCodeText: dns.ExtendedErrorCodeToString[opt.InfoCode],
				ExtraText:     opt.ExtraText,
			})
		}
	}
	return optRes
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
			OriginalTTL: cAns.OrigTtl,
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
			OriginalTTL: cAns.OrigTtl,
			Expiration:  dns.TimeToString(cAns.Expiration),
			Inception:   dns.TimeToString(cAns.Inception),
			KeyTag:      cAns.KeyTag,
			SignerName:  cAns.SignerName,
			Signature:   cAns.Signature,
		}
	case *dns.HINFO:
		return HINFOAnswer{
			Answer: makeBaseAnswer(&cAns.Hdr, ""),
			CPU:    cAns.Cpu,
			OS:     cAns.Os,
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
			SaltLength:    cAns.SaltLength,
			Salt:          cAns.Salt,
			HashLength:    cAns.HashLength,
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
	case *dns.CSYNC:
		return CSYNCAnswer{
			Answer:     makeBaseAnswer(&cAns.Hdr, ""),
			Serial:     cAns.Serial,
			Flags:      cAns.Flags,
			TypeBitMap: makeBitString(cAns.TypeBitMap),
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
	case *dns.AMTRELAY:
		return AMTRELAYAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			Precedence:  cAns.Precedence,
			GatewayType: cAns.GatewayType,
			GatewayAddr: cAns.GatewayAddr,
			GatewayHost: cAns.GatewayHost,
		}
	case *dns.ANY:
		return makeBaseAnswer(&cAns.Hdr, "")
	case *dns.APL:
		ret := APLAnswer{
			Answer:   makeBaseAnswer(&cAns.Hdr, ""),
			Prefixes: make([]APLPrefix, 0, len(cAns.Prefixes)),
		}
		// convert to our types since we'll get json marshall hints
		for _, p := range cAns.Prefixes {
			ret.Prefixes = append(ret.Prefixes, APLPrefix{
				Negation: p.Negation,
				Network:  p.Network,
			})
		}
		return ret
	case *dns.IPSECKEY:
		return IPSECKEYAnswer{
			Answer:      makeBaseAnswer(&cAns.Hdr, ""),
			Precedence:  cAns.Precedence,
			GatewayType: cAns.GatewayType,
			Algorithm:   cAns.Algorithm,
			GatewayAddr: cAns.GatewayAddr,
			GatewayHost: cAns.GatewayHost,
			PublicKey:   cAns.PublicKey,
		}
	case *dns.NXNAME:
		return makeBaseAnswer(&cAns.Hdr, "")
	case *dns.NXT:
		return NXTAnswer{
			NSECAnswer{
				Answer:     makeBaseAnswer(&cAns.Hdr, ""),
				NextDomain: strings.TrimSuffix(cAns.NextDomain, "."),
				TypeBitMap: makeBitString(cAns.TypeBitMap)},
		}
	case *dns.RKEY:
		return RKEYAnswer{
			Answer:    makeBaseAnswer(&cAns.Hdr, ""),
			Flags:     cAns.Flags,
			Protocol:  cAns.Protocol,
			Algorithm: cAns.Algorithm,
			PublicKey: cAns.PublicKey,
		}
	case *dns.ZONEMD:
		return ZONEMDAnswer{
			Answer: makeBaseAnswer(&cAns.Hdr, ""),
			Serial: cAns.Serial,
			Scheme: cAns.Scheme,
			Hash:   cAns.Hash,
			Digest: cAns.Digest,
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
