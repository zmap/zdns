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

import "time"

type GlobalConf struct {
	Threads              int
	Timeout              time.Duration
	IterationTimeout     time.Duration
	Retries              int
	AlexaFormat          bool
	IterativeResolution  bool
	Trace                bool
	MaxDepth             int
	CacheSize            int
	GoMaxProcs           int
	Verbosity            int
	TimeFormat           string
	PassedName           string
	NameServersSpecified bool
	NameServers          []string

	InputFilePath    string
	OutputFilePath   string
	LogFilePath      string
	MetadataFilePath string

	NamePrefix string

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
	AlteredName string        `json:"altered_name,omitempty"`
	Name        string        `json:"name,omitempty"`
	Nameserver  string        `json:"nameserver,omitempty"`
	Class       string        `json:"class,omitempty"`
	AlexaRank   int           `json:"alexa_rank,omitempty"`
	Status      string        `json:"status,omitempty"`
	Error       string        `json:"error,omitempty"`
	Timestamp   string        `json:"timestamp,omitempty"`
	Data        interface{}   `json:"data,omitempty"`
	Trace       []interface{} `json:"trace,omitempty"`
}

type TargetedDomain struct {
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
}

type Status string

const (
	STATUS_NOERROR       Status = "NOERROR"
	STATUS_ERROR         Status = "ERROR"
	STATUS_SERVFAIL      Status = "SERVFAIL"
	STATUS_AUTHFAIL      Status = "AUTHFAIL"
	STATUS_NO_RECORD     Status = "NORECORD"
	STATUS_BLACKLIST     Status = "BLACKLIST"
	STATUS_NO_OUTPUT     Status = "NO_OUTPUT"
	STATUS_NO_ANSWER     Status = "NO_ANSWER"
	STATUS_ILLEGAL_INPUT Status = "ILLEGAL_INPUT"
	STATUS_TIMEOUT       Status = "TIMEOUT"
	STATUS_ITER_TIMEOUT  Status = "ITERATIVE_TIMEOUT"
	STATUS_TEMPORARY     Status = "TEMPORARY"
	STATUS_TRUNCATED     Status = "TRUNCATED"
	STATUS_NXDOMAIN      Status = "NXDOMAIN"
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
