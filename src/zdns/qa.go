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

package zdns

type DNSFlags struct {
	Response           bool `json:"response" groups:"flags,long,trace"`
	Opcode             int  `json:"opcode" groups:"flags,long,trace"`
	Authoritative      bool `json:"authoritative" groups:"flags,long,trace"`
	Truncated          bool `json:"truncated" groups:"flags,long,trace"`
	RecursionDesired   bool `json:"recursion_desired" groups:"flags,long,trace"`
	RecursionAvailable bool `json:"recursion_available" groups:"flags,long,trace"`
	Authenticated      bool `json:"authenticated" groups:"flags,long,trace"`
	CheckingDisabled   bool `json:"checking_disabled" groups:"flags,long,trace"`
	ErrorCode          int  `json:"error_code" groups:"flags,long,trace"`
}

// QuestionWithMetadata wraps a DNS question with other metadata to be used in the lookup process
type QuestionWithMetadata struct {
	Q                Question
	RetriesRemaining *int // number of retries available
}

type Question struct {
	Type  uint16
	Class uint16
	Name  string
}

type Trace []TraceStep

type TraceStep struct {
	Result     SingleQueryResult `json:"results" groups:"trace"`
	DNSType    uint16            `json:"type" groups:"trace"`
	DNSClass   uint16            `json:"class" groups:"trace"`
	Name       string            `json:"name" groups:"trace"`
	NameServer string            `json:"name_server" groups:"trace"`
	Depth      int               `json:"depth" groups:"trace"`
	Layer      string            `json:"layer" groups:"trace"`
	Cached     IsCached          `json:"cached" groups:"trace"`
	Try        int               `json:"try" groups:"trace"`
}

// Result contains all the metadata from a complete lookup(s) for a name. Results is keyed with the ModuleName.
type Result struct {
	AlteredName string                        `json:"altered_name,omitempty" groups:"short,normal,long,trace"`
	Name        string                        `json:"name,omitempty" groups:"short,normal,long,trace"`
	Nameserver  string                        `json:"nameserver,omitempty" groups:"normal,long,trace"`
	Class       string                        `json:"class,omitempty" groups:"long,trace"`
	AlexaRank   int                           `json:"alexa_rank,omitempty" groups:"short,normal,long,trace"`
	Metadata    string                        `json:"metadata,omitempty" groups:"short,normal,long,trace"`
	Results     map[string]SingleModuleResult `json:"results,omitempty" groups:"short,normal,long,trace"`
}

// SingleModuleResult contains all the metadata from a complete lookup for a name, potentially after following many CNAMEs/etc.
type SingleModuleResult struct {
	Status    string      `json:"status,omitempty" groups:"short,normal,long,trace"`
	Error     string      `json:"error,omitempty" groups:"short,normal,long,trace"`
	Timestamp string      `json:"timestamp,omitempty" groups:"short,normal,long,trace"`
	Duration  float64     `json:"duration,omitempty" groups:"short,normal,long,trace"` // in seconds
	Data      interface{} `json:"data,omitempty" groups:"short,normal,long,trace"`
	Trace     Trace       `json:"trace,omitempty" groups:"trace"`
}

// SingleQueryResult contains the results of a single DNS query
type SingleQueryResult struct {
	Answers            []interface{} `json:"answers,omitempty" groups:"short,normal,long,trace"`
	Additionals        []interface{} `json:"additionals,omitempty" groups:"short,normal,long,trace"`
	Authorities        []interface{} `json:"authorities,omitempty" groups:"short,normal,long,trace"`
	Protocol           string        `json:"protocol" groups:"protocol,normal,long,trace"`
	Resolver           string        `json:"resolver" groups:"resolver,normal,long,trace"` // IP address
	Flags              DNSFlags      `json:"flags" groups:"flags,long,trace"`
	DNSSECResult       *DNSSECResult `json:"dnssec,omitempty" groups:"dnssec,normal,long,trace"`
	TLSServerHandshake interface{}   `json:"tls_handshake,omitempty" groups:"normal,long,trace"` // used for --tls and --https, JSON string of the TLS handshake
}

type ExtendedResult struct {
	Type       string            `json:"type" groups:"short,normal,long,trace"`
	Res        SingleQueryResult `json:"result,omitempty" groups:"short,normal,long,trace"`
	Status     Status            `json:"status" groups:"short,normal,long,trace"`
	Nameserver string            `json:"nameserver" groups:"short,normal,long,trace"` // NS name queried for this result
}

type AllNameServersResult struct {
	LayeredResponses map[string][]ExtendedResult `json:"per_layer_responses" groups:"short,normal,long,trace"`
}

type IPResult struct {
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
}
