package dmarc

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

type DmarcTestSuite struct {
	suite.Suite
	gc  *zdns.GlobalConf
	glf *GlobalLookupFactory
	rlf *RoutineLookupFactory
	l   zdns.Lookup
}

func (suite *DmarcTestSuite) SetupTest() {
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

func (suite *DmarcTestSuite) TestLookup_DoTxtLookup_Valid_1() {
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := suite.l.DoLookup("example.com", "")
	suite.Equal(string(zdns.STATUS_NOERROR), string(status))
	suite.Equal(res.(Result).Dmarc, "v=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func (suite *DmarcTestSuite) TestLookup_DoTxtLookup_Valid_2() {
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// Capital V in V=DMARC1; should pass
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "V=DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := suite.l.DoLookup("example.com", "")
	suite.Equal(string(zdns.STATUS_NOERROR), string(status))
	suite.Equal(res.(Result).Dmarc, "V=DMARC1; p=none; rua=mailto:postmaster@censys.io")
}

func (suite *DmarcTestSuite) TestLookup_DoTxtLookup_Valid_3() {
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces and tabs should pass
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := suite.l.DoLookup("example.com", "")
	suite.Equal(string(zdns.STATUS_NOERROR), string(status))
	suite.Equal(res.(Result).Dmarc, "v\t\t\t=\t\t  DMARC1\t\t; p=none; rua=mailto:postmaster@censys.io")
}

func (suite *DmarcTestSuite) TestLookup_DoTxtLookup_NotValid_1() {
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// spaces before "v" should not be accepted
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "\t\t   v   =DMARC1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := suite.l.DoLookup("example.com", "")
	suite.Equal(string(zdns.STATUS_NO_RECORD), string(status))
	suite.Equal(res.(Result).Dmarc, "")
}

func (suite *DmarcTestSuite) TestLookup_DoTxtLookup_NotValid_2() {
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// DMARC1 should be capital letters
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1; p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := suite.l.DoLookup("example.com", "")
	suite.Equal(zdns.STATUS_NO_RECORD, status)
	suite.Equal(res.(Result).Dmarc, "")
}

func (suite *DmarcTestSuite) TestLookup_DoTxtLookup_NotValid_3() {
	mockResults["example.com"] = miekg.Result{
		Answers: []interface{}{
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "some TXT record"},
			// ; has to be present after DMARC1
			miekg.Answer{Name: "_dmarc.zdns-testing.com", Answer: "v=DMARc1. p=none; rua=mailto:postmaster@censys.io"}},
	}
	res, _, status, _ := suite.l.DoLookup("example.com", "")
	suite.Equal(zdns.STATUS_NO_RECORD, status)
	suite.Equal(res.(Result).Dmarc, "")
}

func TestDmarcTestSuite(t *testing.T) {
	suite.Run(t, new(DmarcTestSuite))
}
