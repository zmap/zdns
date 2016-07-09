/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
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

type GlobalConf struct {
	Threads     int
	Timeout     int
	AlexaFormat bool
	GoMaxProcs  int
	Verbosity   int

	NameServersSpecified bool
	NameServers          []string

	InputFilePath    string
	OutputFilePath   string
	LogFilePath      string
	MetadataFilePath string

	NamePrefix string
}

type Metadata struct {
	Names       int            `json:"names"`
	Status      map[string]int `json:"statuses"`
	StartTime   string         `json:"start_time"`
	EndTime     string         `json:"end_time"`
	NameServers []string       `json:"name_servers"`
}

type Result struct {
	OriginalName string      `json:"original,omitempty"`
	Name         string      `json:"name,omitempty"`
	AlexaRank    int         `json:"alexa_rank,omitempty"`
	Status       string      `json:"status,omitempty"`
	Error        string      `json:"error,omitempty"`
	Data         interface{} `json:"data,omitempty"`
}

type Status string

const (
	STATUS_SUCCESS   Status = "success"
	STATUS_ERROR     Status = "error"
	STATUS_TIMEOUT   Status = "timeout"
	STATUS_BAD_RCODE Status = "bad_r_code"
)
