package spf

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

func TestLookup_DoTxtLookup_Valid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "v=spf1 mx include:_spf.google.com -all"}},
	}
	res, _, status, _ := l.DoLookup("google.com", "")
	assert.Equal(t, string(zdns.STATUS_NOERROR), string(status))
	assert.Equal(t, res.(Result).Spf, "v=spf1 mx include:_spf.google.com -all")
}

func TestLookup_DoTxtLookup_Valid_2(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "V=SpF1 mx include:_spf.google.com -all"}},
	}
	res, _, status, _ := l.DoLookup("google.com", "")
	assert.Equal(t, string(zdns.STATUS_NOERROR), string(status))
	assert.Equal(t, res.(Result).Spf, "V=SpF1 mx include:_spf.google.com -all")
}

func TestLookup_DoTxtLookup_NotValid_1(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "  V  =  SpF1 mx include:_spf.google.com -all"}},
	}
	res, _, status, _ := l.DoLookup("google.com", "")
	assert.Equal(t, string(zdns.STATUS_NO_RECORD), string(status))
	assert.Equal(t, res.(Result).Spf, "")
}

func TestLookup_DoTxtLookup_NotValid_2(t *testing.T) {
	_, _, _, l := InitTest()
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "some other TXT record but no SPF"}},
	}
	res, _, status, _ := l.DoLookup("google.com", "")
	assert.Equal(t, string(zdns.STATUS_NO_RECORD), string(status))
	assert.Equal(t, res.(Result).Spf, "")
}

func TestLookup_DoTxtLookup_NoTXT(t *testing.T) {
	_, _, _, l := InitTest()
	res, _, status, _ := l.DoLookup("example.com", "")
	assert.Equal(t, string(zdns.STATUS_NO_ANSWER), string(status))
	assert.Equal(t, res.(Result).Spf, "")
}
