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
	"net"
	"testing"

	"github.com/zmap/dns"
	"gotest.tools/v3/assert"

	"github.com/zmap/zdns/src/cli"
	"github.com/zmap/zdns/src/zdns"
)

type QueryRecord struct {
	zdns.Question
	NameServer *zdns.NameServer
}

var mockResults = make(map[string]*zdns.SingleQueryResult)
var queries []QueryRecord

type MockLookup struct{}

func (ml MockLookup) DoDstServersLookup(r *zdns.Resolver, question zdns.Question, nameServers []zdns.NameServer, isIterative bool) (*zdns.SingleQueryResult, zdns.Trace, zdns.Status, error) {
	queries = append(queries, QueryRecord{question, &nameServers[0]})
	if res, ok := mockResults[question.Name]; ok {
		return res, nil, zdns.StatusNoError, nil
	} else {
		return &zdns.SingleQueryResult{}, nil, zdns.StatusNoAnswer, nil
	}
}

func InitTest(t *testing.T) *zdns.Resolver {
	mockResults = make(map[string]*zdns.SingleQueryResult)
	rc := zdns.ResolverConfig{
		RootNameServersV4:     []zdns.NameServer{{IP: net.ParseIP("127.0.0.53"), Port: 53}},
		ExternalNameServersV4: []zdns.NameServer{{IP: net.ParseIP("127.0.0.1"), Port: 53}},
		LocalAddrsV4:          []net.IP{net.ParseIP("127.0.0.1")},
		IPVersionMode:         zdns.IPv4Only,
		LookupClient:          MockLookup{}}
	r, err := zdns.InitResolver(&rc)
	assert.NilError(t, err)

	return r
}

func TestDmarcLookup_Valid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["_dmarc.zdns-testing.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	dmarcMod := DmarcLookupModule{}
	err := dmarcMod.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{})
	assert.NilError(t, err)
	res, _, status, _ := dmarcMod.Lookup(resolver, "_dmarc.zdns-testing.com", nil)
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer.String(), "127.0.0.1:53")

	assert.Equal(t, zdns.StatusNoError, status)
	assert.Equal(t, res.(Result).Dmarc, "v=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_Valid_2(t *testing.T) {
	resolver := InitTest(t)
	mockResults["_dmarc.zdns-testing.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// Capital V in V=DMARC1; should pass
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "V=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	dmarcMod := DmarcLookupModule{}
	err := dmarcMod.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{})
	assert.NilError(t, err)
	res, _, status, _ := dmarcMod.Lookup(resolver, "_dmarc.zdns-testing.com", nil)
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer.String(), "127.0.0.1:53")

	assert.Equal(t, zdns.StatusNoError, status)
	assert.Equal(t, res.(Result).Dmarc, "V=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_Valid_3(t *testing.T) {
	resolver := InitTest(t)
	mockResults["_dmarc.zdns-testing.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces and tabs should pass
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io"}},
	}
	dmarcMod := DmarcLookupModule{}
	err := dmarcMod.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{})
	assert.NilError(t, err)
	res, _, status, _ := dmarcMod.Lookup(resolver, "_dmarc.zdns-testing.com", nil)
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer.String(), "127.0.0.1:53")

	assert.Equal(t, zdns.StatusNoError, status)
	assert.Equal(t, res.(Result).Dmarc, "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_NotValid_1(t *testing.T) {
	resolver := InitTest(t)
	mockResults["_dmarc.zdns-testing.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces before "v" should not be accepted
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "\t\t   v   =DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	dmarcMod := DmarcLookupModule{}
	err := dmarcMod.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{})
	assert.NilError(t, err)
	res, _, status, _ := dmarcMod.Lookup(resolver, "_dmarc.zdns-testing.com", nil)
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer.String(), "127.0.0.1:53")

	assert.Equal(t, zdns.StatusNoRecord, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}

func TestDmarcLookup_NotValid_2(t *testing.T) {
	resolver := InitTest(t)
	mockResults["_dmarc.zdns-testing.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// DMARC1 should be capital letters
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	dmarcMod := DmarcLookupModule{}
	err := dmarcMod.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{})
	assert.NilError(t, err)
	res, _, status, _ := dmarcMod.Lookup(resolver, "_dmarc.zdns-testing.com", nil)
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer.String(), "127.0.0.1:53")

	assert.Equal(t, zdns.StatusNoRecord, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}

func TestDmarcLookup_NotValid_3(t *testing.T) {
	resolver := InitTest(t)
	mockResults["_dmarc.zdns-testing.com"] = &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// ; has to be present after DMARC1
			zdns.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1. p=none; rua=mailto:postmaster@censys.io"}},
	}
	dmarcMod := DmarcLookupModule{}
	err := dmarcMod.CLIInit(&cli.CLIConf{}, &zdns.ResolverConfig{})
	assert.NilError(t, err)
	res, _, status, _ := dmarcMod.Lookup(resolver, "_dmarc.zdns-testing.com", nil)
	assert.Equal(t, queries[0].Class, uint16(dns.ClassINET))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "_dmarc.zdns-testing.com")
	assert.Equal(t, queries[0].NameServer.String(), "127.0.0.1:53")

	assert.Equal(t, zdns.StatusNoRecord, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}
