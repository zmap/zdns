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

package spf

import (
	"testing"

	"github.com/zmap/dns"
	"gotest.tools/v3/assert"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

type QueryRecord struct {
	zdns.Question
	NameServer string
}

var mockResults = make(map[string]*zdns.SingleQueryResult)
var queries []QueryRecord

type MockLookup struct{}

func (ml MockLookup) DoSingleDstServerLookup(r *zdns.Resolver, question zdns.Question, nameServer string, isIterative bool) (*zdns.SingleQueryResult, zdns.Trace, zdns.Status, error) {
	queries = append(queries, QueryRecord{question, nameServer})
	if res, ok := mockResults[question.Name]; ok {
		return res, nil, zdns.StatusNoError, nil
	} else {
		return &zdns.SingleQueryResult{}, nil, zdns.StatusNoAnswer, nil
	}
}

func InitTest(t *testing.T) *zdns.Resolver {
	mockResults = make(map[string]*zdns.SingleQueryResult)
	queries = make([]QueryRecord, 0)
	rc := zdns.ResolverConfig{
		ExternalNameServers: []string{"127.0.0.1"},
		LookupClient:        MockLookup{}}
	r, err := zdns.InitResolver(&rc)
	assert.NilError(t, err)

	return r
}

func TestLookup_DoTxtLookup_Valid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "google.com", Answer: "some TXT record"},
			zdns.Answer{Name: "google.com", Answer: "v=spf1 mx include:_spf.google.com -all"}},
	}
	spfModule := SpfLookupModule{}
	err := spfModule.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{LookupClient: MockLookup{}}, nil)
	assert.NilError(t, err)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, zdns.StatusNoError, status)
	assert.Equal(t, res.(Result).Spf, "v=spf1 mx include:_spf.google.com -all")
}

func TestLookup_DoTxtLookup_Valid_2(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "google.com", Answer: "some TXT record"},
			zdns.Answer{Name: "google.com", Answer: "V=SpF1 mx include:_spf.google.com -all"}},
	}
	spfModule := SpfLookupModule{}
	err := spfModule.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{LookupClient: MockLookup{}}, nil)
	assert.NilError(t, err)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, zdns.StatusNoError, status)
	assert.Equal(t, res.(Result).Spf, "V=SpF1 mx include:_spf.google.com -all")
}

func TestLookup_DoTxtLookup_NotValid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "google.com", Answer: "some TXT record"},
			zdns.Answer{Name: "google.com", Answer: "  V  =  SpF1 mx include:_spf.google.com -all"}},
	}
	spfModule := SpfLookupModule{}
	err := spfModule.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{LookupClient: MockLookup{}}, nil)
	assert.NilError(t, err)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, zdns.StatusNoRecord, status)
	assert.Equal(t, res.(Result).Spf, "")
}

func TestLookup_DoTxtLookup_NotValid_2(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "google.com", Answer: "some TXT record"},
			zdns.Answer{Name: "google.com", Answer: "some other TXT record but no SPF"}},
	}
	spfModule := SpfLookupModule{}
	err := spfModule.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{LookupClient: MockLookup{}}, nil)
	assert.NilError(t, err)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, zdns.StatusNoRecord, status)
	assert.Equal(t, res.(Result).Spf, "")
}

func TestLookup_DoTxtLookup_NoTXT(t *testing.T) {
	resolver := InitTest(t)
	spfModule := SpfLookupModule{}
	err := spfModule.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{LookupClient: MockLookup{}}, nil)
	assert.NilError(t, err)
	res, _, status, _ := spfModule.Lookup(resolver, "example.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "example.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, zdns.StatusNoAnswer, status)
	assert.Equal(t, res.(Result).Spf, "")
}
