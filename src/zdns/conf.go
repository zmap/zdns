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

//type Metadata struct {
//	Names       int            `json:"names"`
//	Status      map[string]int `json:"statuses"`
//	StartTime   string         `json:"start_time"`
//	EndTime     string         `json:"end_time"`
//	NameServers []string       `json:"name_servers"`
//	Timeout     int            `json:"timeout"`
//	Retries     int            `json:"retries"`
//	Conf        *GlobalConf    `json:"conf"`
//}

type TargetedDomain struct {
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
}

type Status string

const (
	// Standardized RCODE
	StatusNoError   Status = "NOERROR" // No Error
	StatusFormErr   Status = "FORMERR" // Format Error
	StatusServFail  Status = "SERVFAIL"
	StatusNXDomain  Status = "NXDOMAIN"
	StatusRefused   Status = "REFUSED"
	StatusTruncated Status = "TRUNCATED"

	StatusError        Status = "ERROR"
	StatusAuthFail     Status = "AUTHFAIL"
	StatusNoRecord     Status = "NORECORD"
	StatusBlacklist    Status = "BLACKLIST"
	StatusNoOutput     Status = "NO_OUTPUT"
	StatusNoAnswer     Status = "NO_ANSWER"
	StatusIllegalInput Status = "ILLEGAL_INPUT"
	StatusTimeout      Status = "TIMEOUT"
	StatusIterTimeout  Status = "ITERATIVE_TIMEOUT"
	StatusNoAuth       Status = "NOAUTH"
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
