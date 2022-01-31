package spf

import (
	"github.com/stretchr/testify/suite"
	"github.com/zmap/zdns"
	"github.com/zmap/zdns/modules/miekg"
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

type SpfTestSuite struct {
	suite.Suite
	gc  *zdns.GlobalConf
	glf *GlobalLookupFactory
	rlf *RoutineLookupFactory
	l   zdns.Lookup
}

func (suite *SpfTestSuite) SetupTest() {
	mockResults = make(map[string]miekg.Result)
	suite.gc = new(zdns.GlobalConf)
	suite.gc.NameServers = []string{"127.0.0.1"}

	suite.glf = new(GlobalLookupFactory)
	suite.glf.GlobalConf = suite.gc

	suite.rlf = new(RoutineLookupFactory)
	suite.rlf.Factory = suite.glf
	suite.rlf.InitPrefixRegexp()

	var err error
	suite.l, err = suite.rlf.MakeLookup()
	if suite.l == nil || err != nil {
		suite.T().Error("Failed to initialize lookup")
	}
}

func (suite *SpfTestSuite) TestLookup_DoTxtLookup_Valid_1() {
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "v=spf1 mx include:_spf.google.com -all"}},
	}
	res, _, status, _ := suite.l.DoLookup("google.com", "")
	suite.Equal(string(zdns.STATUS_NOERROR), string(status))
	suite.Equal(res.(Result).Spf, "v=spf1 mx include:_spf.google.com -all")
}

func (suite *SpfTestSuite) TestLookup_DoTxtLookup_Valid_2() {
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "V=SpF1 mx include:_spf.google.com -all"}},
	}
	res, _, status, _ := suite.l.DoLookup("google.com", "")
	suite.Equal(string(zdns.STATUS_NOERROR), string(status))
	suite.Equal(res.(Result).Spf, "V=SpF1 mx include:_spf.google.com -all")
}

func (suite *SpfTestSuite) TestLookup_DoTxtLookup_NotValid_1() {
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "  V  =  SpF1 mx include:_spf.google.com -all"}},
	}
	res, _, status, _ := suite.l.DoLookup("google.com", "")
	suite.Equal(string(zdns.STATUS_NO_RECORD), string(status))
	suite.Equal(res.(Result).Spf, "")
}

func (suite *SpfTestSuite) TestLookup_DoTxtLookup_NotValid_2() {
	mockResults["google.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "google.com", Answer: "some TXT record"},
			miekg.Answer{Name: "google.com", Answer: "some other TXT record but no SPF"}},
	}
	res, _, status, _ := suite.l.DoLookup("google.com", "")
	suite.Equal(string(zdns.STATUS_NO_RECORD), string(status))
	suite.Equal(res.(Result).Spf, "")
}

func (suite *SpfTestSuite) TestLookup_DoTxtLookup_NoTXT() {
	res, _, status, _ := suite.l.DoLookup("example.com", "")
	suite.Equal(string(zdns.STATUS_NO_ANSWER), string(status))
	suite.Equal(res.(Result).Spf, "")
}

func TestSpfTestSuite(t *testing.T) {
	suite.Run(t, new(SpfTestSuite))
}
