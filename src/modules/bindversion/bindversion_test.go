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
	"gotest.tools/v3/assert"

	"github.com/zmap/zdns/src/zdns"
)

type QueryRecord struct {
	q          zdns.Question
	NameServer string
}

var mockResults map[string]*zdns.SingleQueryResult
var queries []QueryRecord

// DoSingleDstServerLookup(r *Resolver, q Question, nameServer string, isIterative bool) (*SingleQueryResult, Trace, Status, error)
type MockLookup struct{}

func (ml MockLookup) DoSingleDstServerLookup(r *zdns.Resolver, question zdns.Question, nameServer string, isIterative bool) (*zdns.SingleQueryResult, zdns.Trace, zdns.Status, error) {
	queries = append(queries, QueryRecord{q: question, NameServer: nameServer})
	if res, ok := mockResults[question.Name]; ok {
		return res, nil, zdns.StatusNoError, nil
	} else {
		return &zdns.SingleQueryResult{}, nil, zdns.StatusNoAnswer, nil
	}
}

func InitTest(t *testing.T) *zdns.Resolver {
	mockResults = make(map[string]*zdns.SingleQueryResult)
	rc := zdns.ResolverConfig{
		ExternalNameServers: []string{"127.0.0.1"},
		LookupClient:        MockLookup{}}
	r, err := zdns.InitResolver(&rc)
	assert.NilError(t, err)

	return r
}

func TestBindVersionLookup_Valid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["VERSION.BIND"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "VERSION.BIND", Answer: "Nominum Vantio 5.4.1.0", Class: "CHAOS"}},
	}
	bvModule := BindVersionLookupModule{}
	res, _, status, _ := bvModule.Lookup(resolver, "", "1.2.3.4")
	assert.Equal(t, queries[0].q.Class, uint16(dns.ClassCHAOS))
	assert.Equal(t, queries[0].q.Type, dns.TypeTXT)
	assert.Equal(t, queries[0].q.Name, "VERSION.BIND")
	assert.Equal(t, queries[0].NameServer, "1.2.3.4")

	assert.Equal(t, zdns.StatusNoError, status)
	assert.Equal(t, res.(Result).BindVersion, "Nominum Vantio 5.4.1.0")
}

func TestBindVersionLookup_NotValid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["VERSION.BIND"] = &zdns.SingleQueryResult{
		Answers: []interface{}{},
	}
	bvModule := BindVersionLookupModule{}
	res, _, status, _ := bvModule.Lookup(resolver, "", "1.2.3.4")
	assert.Equal(t, queries[0].q.Class, uint16(dns.ClassCHAOS))
	assert.Equal(t, queries[0].q.Type, dns.TypeTXT)
	assert.Equal(t, queries[0].q.Name, "VERSION.BIND")
	assert.Equal(t, queries[0].NameServer, "1.2.3.4")

	assert.Equal(t, zdns.StatusNoRecord, status)
	assert.Equal(t, res.(Result).BindVersion, "")
}
