/*
 * ZDNS Copyright 2023 Regents of the University of Michigan
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

// Structures covering DNS EDNS0 Option Codes (https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)

// Edns0LLQ OPT 1
type Edns0LLQ struct {
	Code      uint16 `json:"code" groups:"short,normal,long,trace"`
	Version   uint16 `json:"version" groups:"short,normal,long,trace"`
	Opcode    uint16 `json:"opcode" groups:"short,normal,long,trace"`
	Error     uint16 `json:"error" groups:"short,normal,long,trace"`
	ID        uint64 `json:"id" groups:"short,normal,long,trace"`
	LeaseLife uint32 `json:"lease_life" groups:"short,normal,long,trace"`
}

// Edns0UL OPT 2
type Edns0UL struct {
	Code     uint16 `json:"code" groups:"short,normal,long,trace"`
	Lease    uint32 `json:"lease" groups:"short,normal,long,trace"`
	KeyLease uint32 `json:"key_lease" groups:"short,normal,long,trace"`
}

// Edns0NSID OPT 3
type Edns0NSID struct {
	Nsid string `json:"nsid" groups:"short,normal,long,trace"`
}

// Edns0DAU OPT 5
type Edns0DAU struct {
	Code    uint16 `json:"code" groups:"short,normal,long,trace"`
	AlgCode string `json:"alg_code" groups:"short,normal,long,trace"`
}

// Edns0DHU OPT 6
type Edns0DHU struct {
	Code    uint16 `json:"code" groups:"short,normal,long,trace"`
	AlgCode string `json:"alg_code" groups:"short,normal,long,trace"`
}

// Edns0N3U OPT 7
type Edns0N3U struct {
	Code    uint16 `json:"code" groups:"short,normal,long,trace"`
	AlgCode string `json:"alg_code" groups:"short,normal,long,trace"`
}

// Edns0ClientSubnet OPT 8
type Edns0ClientSubnet struct {
	Family        uint16 `json:"family" groups:"short,normal,long,trace"`
	SourceNetmask uint8  `json:"source_netmask" groups:"short,normal,long,trace"`
	SourceScope   uint8  `json:"source_scope" groups:"short,normal,long,trace"`
	Address       string `json:"address" groups:"short,normal,long,trace"`
}

// Edns0Expire OPT 9
type Edns0Expire struct {
	Code   uint16 `json:"code" groups:"short,normal,long,trace"`
	Expire uint32 `json:"expire" groups:"short,normal,long,trace"`
}

// Edns0Cookie OPT 10
type Edns0Cookie struct {
	Cookie string `json:"cookie" groups:"short,normal,long,trace"`
}

// Edns0TCPKeepalive OPT 11
type Edns0TCPKeepalive struct {
	Code    uint16 `json:"code" groups:"short,normal,long,trace"`
	Timeout uint16 `json:"timeout" groups:"short,normal,long,trace"`
	Length  uint16 `json:"length" groups:"short,normal,long,trace"`
}

// Edns0Padding OPT 12
type Edns0Padding struct {
	Padding string `json:"padding" groups:"short,normal,long,trace"`
}

// Edns0Ede OPT15
type Edns0Ede struct {
	InfoCode      uint16 `json:"info_code" groups:"short,normal,long,trace"`
	ErrorCodeText string `json:"error_text" groups:"short,normal,long,trace"`
	ExtraText     string `json:"extra_text" groups:"short,normal,long,trace"`
}

type EDNSAnswer struct {
	Type         string             `json:"type" groups:"short,normal,long,trace"`
	Version      uint8              `json:"version" groups:"short,normal,long,trace"`
	Flags        string             `json:"flags" groups:"short,normal,long,trace"`
	UDPSize      uint16             `json:"udpsize" groups:"short,normal,long,trace"`
	LLQ          *Edns0LLQ          `json:"llq,omitempty" groups:"short,normal,long,trace"` //not implemented
	UL           *Edns0UL           `json:"ul,omitempty" groups:"short,normal,long,trace"`  //not implemented
	NSID         *Edns0NSID         `json:"nsid,omitempty" groups:"short,normal,long,trace"`
	DAU          *Edns0DAU          `json:"dau,omitempty" groups:"short,normal,long,trace"` //not implemented
	DHU          *Edns0DHU          `json:"dhu,omitempty" groups:"short,normal,long,trace"` //not implemented
	N3U          *Edns0N3U          `json:"n3u,omitempty" groups:"short,normal,long,trace"` //not implemented
	ClientSubnet *Edns0ClientSubnet `json:"csubnet,omitempty" groups:"short,normal,long,trace"`
	Expire       *Edns0Expire       `json:"expire,omitempty" groups:"short,normal,long,trace"`        //not implemented
	Cookie       *Edns0Cookie       `json:"cookie,omitempty" groups:"short,normal,long,trace"`        //not implemented
	TCPKeepalive *Edns0TCPKeepalive `json:"tcp_keepalive,omitempty" groups:"short,normal,long,trace"` //not implemented
	Padding      *Edns0Padding      `json:"padding,omitempty" groups:"short,normal,long,trace"`       //not implemented
	EDE          []*Edns0Ede        `json:"ede,omitempty" groups:"short,normal,long,trace"`
}
