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

package zdns

import (
	"net"
	"time"

	"github.com/zmap/dns"
)

type GlobalConf struct {
	Threads               int
	Timeout               time.Duration
	IterationTimeout      time.Duration
	Retries               int
	AlexaFormat           bool
	MetadataFormat        bool
	NameServerInputFormat bool
	IterativeResolution   bool
	LookupAllNameServers  bool

	ResultVerbosity string
	IncludeInOutput string
	OutputGroups    []string

	MaxDepth             int
	CacheSize            int
	GoMaxProcs           int
	Verbosity            int
	TimeFormat           string
	PassedName           string
	NameServersSpecified bool
	NameServers          []string
	TCPOnly              bool
	UDPOnly              bool
	RecycleSockets       bool
	LocalAddrSpecified   bool
	LocalAddrs           []net.IP
	ClientSubnet         *dns.EDNS0_SUBNET
	Dnssec               bool
	CheckingDisabled     bool

	InputHandler  InputHandler
	OutputHandler OutputHandler

	InputFilePath    string
	OutputFilePath   string
	LogFilePath      string
	MetadataFilePath string

	NamePrefix     string
	NameOverride   string
	NameServerMode bool

	Module string
	Class  uint16
}

type Metadata struct {
	Names       int            `json:"names"`
	Status      map[string]int `json:"statuses"`
	StartTime   string         `json:"start_time"`
	EndTime     string         `json:"end_time"`
	NameServers []string       `json:"name_servers"`
	Timeout     int            `json:"timeout"`
	Retries     int            `json:"retries"`
	Conf        *GlobalConf    `json:"conf"`
}

type Result struct {
	AlteredName string        `json:"altered_name,omitempty" groups:"short,normal,long,trace"`
	Name        string        `json:"name,omitempty" groups:"short,normal,long,trace"`
	Nameserver  string        `json:"nameserver,omitempty" groups:"normal,long,trace"`
	Class       string        `json:"class,omitempty" groups:"long,trace"`
	AlexaRank   int           `json:"alexa_rank,omitempty" groups:"short,normal,long,trace"`
	Metadata    string        `json:"metadata,omitempty" groups:"short,normal,long,trace"`
	Status      string        `json:"status,omitempty" groups:"short,normal,long,trace"`
	Error       string        `json:"error,omitempty" groups:"short,normal,long,trace"`
	Timestamp   string        `json:"timestamp,omitempty" groups:"short,normal,long,trace"`
	Data        interface{}   `json:"data,omitempty" groups:"short,normal,long,trace"`
	Trace       []interface{} `json:"trace,omitempty" groups:"trace"`
}

type TargetedDomain struct {
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
}

type Status string

const (
	// Standardized RCODE
	STATUS_NOERROR   Status = "NOERROR" // No Error
	STATUS_FORMERR   Status = "FORMERR" // Format Error
	STATUS_SERVFAIL  Status = "SERVFAIL"
	STATUS_NXDOMAIN  Status = "NXDOMAIN"
	STATUS_NOTIMP    Status = "NOT_IMPL"
	STATUS_REFUSED   Status = "REFUSED"
	STATUS_TRUNCATED Status = "TRUNCATED"

	STATUS_ERROR         Status = "ERROR"
	STATUS_AUTHFAIL      Status = "AUTHFAIL"
	STATUS_NO_RECORD     Status = "NORECORD"
	STATUS_BLACKLIST     Status = "BLACKLIST"
	STATUS_NO_OUTPUT     Status = "NO_OUTPUT"
	STATUS_NO_ANSWER     Status = "NO_ANSWER"
	STATUS_ILLEGAL_INPUT Status = "ILLEGAL_INPUT"
	STATUS_TIMEOUT       Status = "TIMEOUT"
	STATUS_ITER_TIMEOUT  Status = "ITERATIVE_TIMEOUT"
	STATUS_TEMPORARY     Status = "TEMPORARY"
	STATUS_NOAUTH        Status = "NOAUTH"
	STATUS_NODATA        Status = "NODATA"
)

var RootServers = [...]string{
	"198.41.0.4:53",
	"192.228.79.201:53",
	"192.33.4.12:53",
	"199.7.91.13:53",
	"192.203.230.10:53",
	"192.5.5.241:53",
	"192.112.36.4:53",
	"198.97.190.53:53",
	"192.36.148.17:53",
	"192.58.128.30:53",
	"193.0.14.129:53",
	"199.7.83.42:53",
	"202.12.27.33:53"}
