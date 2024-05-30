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

package bindversion

import (
	"testing"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/core"
	"gotest.tools/v3/assert"
)

type QueryRecord struct {
	q          core.Question
	NameServer string
}

var mockResults map[string]*core.SingleQueryResult
var queries []QueryRecord

// DoSingleDstServerLookup(r *Resolver, q Question, nameServer string, isIterative bool) (*SingleQueryResult, Trace, Status, error)
type MockLookup struct{}

func (ml MockLookup) DoSingleDstServerLookup(r *core.Resolver, question core.Question, nameServer string, isIterative bool) (*core.SingleQueryResult, core.Trace, core.Status, error) {
	queries = append(queries, QueryRecord{q: question, NameServer: nameServer})
	if res, ok := mockResults[question.Name]; ok {
		return res, nil, core.STATUS_NOERROR, nil
	} else {
		return &core.SingleQueryResult{}, nil, core.STATUS_NO_ANSWER, nil
	}
}

func InitTest(t *testing.T) *core.Resolver {
	mockResults = make(map[string]*core.SingleQueryResult)
	rc := core.ResolverConfig{
		ExternalNameServers: []string{"127.0.0.1"},
		LookupClient:        MockLookup{}}
	r, err := core.InitResolver(&rc)
	assert.NilError(t, err)

	return r
}

func TestBindVersionLookup_Valid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["VERSION.BIND"] = &core.SingleQueryResult{
		Answers: []interface{}{
			core.Answer{Name: "VERSION.BIND", Answer: "Nominum Vantio 5.4.1.0", Class: "CHAOS"}},
	}
	bvModule := BindVersionLookupModule{}
	res, _, status, _ := bvModule.Lookup(resolver, "", "1.2.3.4")
	assert.Equal(t, queries[0].q.Class, uint16(dns.ClassCHAOS))
	assert.Equal(t, queries[0].q.Type, dns.TypeTXT)
	assert.Equal(t, queries[0].q.Name, "VERSION.BIND")
	assert.Equal(t, queries[0].NameServer, "1.2.3.4")

	assert.Equal(t, core.STATUS_NOERROR, status)
	assert.Equal(t, res.(Result).BindVersion, "Nominum Vantio 5.4.1.0")
}

func TestBindVersionLookup_NotValid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["VERSION.BIND"] = &core.SingleQueryResult{
		Answers: []interface{}{},
	}
	bvModule := BindVersionLookupModule{}
	res, _, status, _ := bvModule.Lookup(resolver, "", "1.2.3.4")
	assert.Equal(t, queries[0].q.Class, uint16(dns.ClassCHAOS))
	assert.Equal(t, queries[0].q.Type, dns.TypeTXT)
	assert.Equal(t, queries[0].q.Name, "VERSION.BIND")
	assert.Equal(t, queries[0].NameServer, "1.2.3.4")

	assert.Equal(t, core.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).BindVersion, "")
}
