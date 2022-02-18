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

package dmarc

import (
	"testing"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/miekg"
	"github.com/zmap/zdns/pkg/zdns"
	"gotest.tools/v3/assert"
)

type QueryRecord struct {
	miekg.Question
	NameServer string
}

var mockResults = make(map[string]miekg.Result)
var queries []QueryRecord

func (s *Lookup) DoMiekgLookup(question miekg.Question, nameServer string) (miekg.Result, []interface{}, zdns.Status, error) {
	queries = append(queries, QueryRecord{Question: question, NameServer: nameServer})
	if res, ok := mockResults[question.Name]; ok {
		return res, nil, zdns.STATUS_NOERROR, nil
	} else {
		return miekg.Result{}, nil, zdns.STATUS_NO_ANSWER, nil
	}
}

func InitTest() (*zdns.GlobalConf, *GlobalLookupFactory, *RoutineLookupFactory, zdns.Lookup) {
	queries = nil
	mockResults = make(map[string]miekg.Result)
	gc := new(zdns.GlobalConf)
	gc.NameServers = []string{"127.0.0.1"}

	glf := new(GlobalLookupFactory)
	glf.GlobalConf = gc

	rlf := new(RoutineLookupFactory)
	rlf.Factory = glf
	rlf.InitPrefixRegexp()

	l, err := rlf.MakeLookup()
	if l == nil || err != nil {
		panic("Failed to initialize lookup")
	}
	return gc, glf, rlf, l
}

func TestDmarcLookup_Valid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["_dmarc.zdns-testing.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("_dmarc.zdns-testing.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer, "")

	assert.Equal(t, zdns.STATUS_NOERROR, status)
	assert.Equal(t, res.(Result).Dmarc, "v=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_Valid_2(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["_dmarc.zdns-testing.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// Capital V in V=DMARC1; should pass
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "V=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("_dmarc.zdns-testing.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer, "")

	assert.Equal(t, zdns.STATUS_NOERROR, status)
	assert.Equal(t, res.(Result).Dmarc, "V=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_Valid_3(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["_dmarc.zdns-testing.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces and tabs should pass
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("_dmarc.zdns-testing.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer, "")

	assert.Equal(t, zdns.STATUS_NOERROR, status)
	assert.Equal(t, res.(Result).Dmarc, "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_NotValid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["_dmarc.zdns-testing.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces before "v" should not be accepted
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "\t\t   v   =DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("_dmarc.zdns-testing.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer, "")

	assert.Equal(t, zdns.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}

func TestDmarcLookup_NotValid_2(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["_dmarc.zdns-testing.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// DMARC1 should be capital letters
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("_dmarc.zdns-testing.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer, "")

	assert.Equal(t, zdns.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}

func TestDmarcLookup_NotValid_3(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["_dmarc.zdns-testing.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// ; has to be present after DMARC1
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1. p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("_dmarc.zdns-testing.com", "")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer, "")

	assert.Equal(t, zdns.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}
