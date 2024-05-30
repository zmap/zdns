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
	"github.com/zmap/zdns/core"
	"gotest.tools/v3/assert"
)

type QueryRecord struct {
	core.Question
	NameServer string
}

var mockResults = make(map[string]*core.SingleQueryResult)
var queries []QueryRecord

type MockLookup struct{}

func (ml MockLookup) DoSingleDstServerLookup(r *core.Resolver, question core.Question, nameServer string, isIterative bool) (*core.SingleQueryResult, core.Trace, core.Status, error) {
	queries = append(queries, QueryRecord{question, nameServer})
	if res, ok := mockResults[question.Name]; ok {
		return res, nil, core.STATUS_NOERROR, nil
	} else {
		return &core.SingleQueryResult{}, nil, core.STATUS_NO_ANSWER, nil
	}
}

func InitTest(t *testing.T) *core.Resolver {
	mockResults = make(map[string]*core.SingleQueryResult)
	queries = make([]QueryRecord, 0)
	rc := core.ResolverConfig{
		ExternalNameServers: []string{"127.0.0.1"},
		LookupClient:        MockLookup{}}
	r, err := core.InitResolver(&rc)
	assert.NilError(t, err)

	return r
}

func TestLookup_DoTxtLookup_Valid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &core.SingleQueryResult{
		Answers: []interface{}{
			core.Answer{Name: "google.com", Answer: "some TXT record"},
			core.Answer{Name: "google.com", Answer: "v=spf1 mx include:_spf.google.com -all"}},
	}
	spfModule := SpfLookupModule{}
	spfModule.CLIInit(nil, &core.ResolverConfig{IsIterative: false, LookupClient: MockLookup{}}, nil)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, core.STATUS_NOERROR, status)
	assert.Equal(t, res.(Result).Spf, "v=spf1 mx include:_spf.google.com -all")
}

func TestLookup_DoTxtLookup_Valid_2(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &core.SingleQueryResult{
		Answers: []interface{}{
			core.Answer{Name: "google.com", Answer: "some TXT record"},
			core.Answer{Name: "google.com", Answer: "V=SpF1 mx include:_spf.google.com -all"}},
	}
	spfModule := SpfLookupModule{}
	spfModule.CLIInit(nil, &core.ResolverConfig{IsIterative: false, LookupClient: MockLookup{}}, nil)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, core.STATUS_NOERROR, status)
	assert.Equal(t, res.(Result).Spf, "V=SpF1 mx include:_spf.google.com -all")
}

func TestLookup_DoTxtLookup_NotValid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &core.SingleQueryResult{
		Answers: []interface{}{
			core.Answer{Name: "google.com", Answer: "some TXT record"},
			core.Answer{Name: "google.com", Answer: "  V  =  SpF1 mx include:_spf.google.com -all"}},
	}
	spfModule := SpfLookupModule{}
	spfModule.CLIInit(nil, &core.ResolverConfig{IsIterative: false, LookupClient: MockLookup{}}, nil)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, core.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).Spf, "")
}

func TestLookup_DoTxtLookup_NotValid_2(t *testing.T) {
	resolver := InitTest(t)
	mockResults["google.com"] = &core.SingleQueryResult{
		Answers: []interface{}{
			core.Answer{Name: "google.com", Answer: "some TXT record"},
			core.Answer{Name: "google.com", Answer: "some other TXT record but no SPF"}},
	}
	spfModule := SpfLookupModule{}
	spfModule.CLIInit(nil, &core.ResolverConfig{IsIterative: false, LookupClient: MockLookup{}}, nil)
	res, _, status, _ := spfModule.Lookup(resolver, "google.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "google.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, core.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).Spf, "")
}

func TestLookup_DoTxtLookup_NoTXT(t *testing.T) {
	resolver := InitTest(t)
	spfModule := SpfLookupModule{}
	spfModule.CLIInit(nil, &core.ResolverConfig{IsIterative: false, LookupClient: MockLookup{}}, nil)
	res, _, status, _ := spfModule.Lookup(resolver, "example.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "example.com")
	assert.Equal(t, queries[0].NameServer, "127.0.0.1")

	assert.Equal(t, core.STATUS_NO_ANSWER, status)
	assert.Equal(t, res.(Result).Spf, "")
}
