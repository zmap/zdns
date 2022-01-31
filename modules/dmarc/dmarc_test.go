package dmarc

import (
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
	"gotest.tools/v3/assert"
	"testing"
)

var mockResults = make(map[string]miekg.Result)

func (s *Lookup) DoMiekgLookup(question miekg.Question, nameServer string) (miekg.Result, []interface{}, zdns.Status, error) {
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
	rlf.InitPrefixRegexp()

	l, err := rlf.MakeLookup()
	if l == nil || err != nil {
		panic("Failed to initialize lookup")
	}
	return gc, glf, rlf, l
}

func TestDmarcLookup_Valid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, string(zdns.STATUS_NOERROR), string(status))
	assert.Equal(t, res.(Result).Dmarc, "v=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_Valid_2(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// Capital V in V=DMARC1; should pass
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "V=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, string(zdns.STATUS_NOERROR), string(status))
	assert.Equal(t, res.(Result).Dmarc, "V=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_Valid_3(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces and tabs should pass
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, string(zdns.STATUS_NOERROR), string(status))
	assert.Equal(t, res.(Result).Dmarc, "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io")
}

func TestDmarcLookup_NotValid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces before "v" should not be accepted
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "\t\t   v   =DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, string(zdns.STATUS_NO_RECORD), string(status))
	assert.Equal(t, res.(Result).Dmarc, "")
}

func TestDmarcLookup_NotValid_2(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// DMARC1 should be capital letters
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, zdns.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}

func TestDmarcLookup_NotValid_3(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// ; has to be present after DMARC1
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1. p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, zdns.STATUS_NO_RECORD, status)
	assert.Equal(t, res.(Result).Dmarc, "")
}
