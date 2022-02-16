package bindversion

import (
	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/miekg"
	"github.com/zmap/zdns/pkg/zdns"
	"gotest.tools/v3/assert"
	"testing"
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
	mockResults = make(map[string]miekg.Result)
	gc := new(zdns.GlobalConf)
	gc.NameServers = []string{"127.0.0.1"}

	glf := new(GlobalLookupFactory)
	glf.GlobalConf = gc

	rlf := new(RoutineLookupFactory)
	rlf.Factory = glf

	l, err := rlf.MakeLookup()
	if l == nil || err != nil {
		panic("Failed to initialize lookup")
	}
	return gc, glf, rlf, l
}

func TestBindVersionLookup_Valid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["VERSION.BIND"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "VERSION.BIND", Answer: "Nominum Vantio 5.4.1.0", Class: "CHAOS"}},
	}
	res, _, status, _ := l.DoLookup("VERSION.BIND", "1.2.3.4")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassCHAOS))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "VERSION.BIND")
	assert.Equal(t, queries[0].NameServer, "1.2.3.4")

	assert.Equal(t, zdns.STATUS_NOERROR, status)
	assert.Equal(t, res.(Result).BindVersion, "Nominum Vantio 5.4.1.0")
}

func TestBindVersionLookup_NotValid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["VERSION.BIND"] = miekg.Result{
		Answers: []interface{}{},
	}
	res, _, status, _ := l.DoLookup("VERSION.BIND", "1.2.3.4")
	assert.Equal(t, queries[0].Class, uint16(dns.ClassCHAOS))
	assert.Equal(t, queries[0].Type, dns.TypeTXT)
	assert.Equal(t, queries[0].Name, "VERSION.BIND")
	assert.Equal(t, queries[0].NameServer, "1.2.3.4")

	assert.Equal(t, zdns.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).BindVersion, "")
}
