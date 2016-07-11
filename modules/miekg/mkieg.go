package miekg

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
)

type Answer struct {
	Ttl    uint32 `json:"ttl"`
	Type   string `json:"type"`
	Answer string `json:"answer"`
}

// result to be returned by scan of host
type Result struct {
	Answers  []Answer `json:"answers"`
	Protocol string   `json:"protocol"`
}

type Lookup struct {
	DNSType dns.Type
	Prefix  string
}

type GlobalLookupFactory struct {
}

type RoutineLookupFactory struct {
	Client    *dns.Client
	TCPClient *dns.Client
}

func (s *RoutineLookupFactory) Initialize() {
	s.Client = new(dns.Client)
	s.TCPClient = new(dns.Client)
	s.TCPClient.Net = "tcp"
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

type ReadResult func(dns.RR) (Answer, bool)

func DoLookup(udp *dns.Client, tcp *dns.Client, nameServer string, parse ReadResult, dnsType uint16, name string) (interface{}, zdns.Status, error) {
	// this is where we do scanning
	res := Result{Answers: []Answer{}}

	m := new(dns.Msg)
	m.SetQuestion(dotName(name), dnsType)
	m.RecursionDesired = true

	useTCP := false
	res.Protocol = "udp"
	r, _, err := udp.Exchange(m, nameServer)
	if err == dns.ErrTruncated {
		r, _, err = tcp.Exchange(m, nameServer)
		useTCP = true
		res.Protocol = "tcp"
	}
	if err != nil {
		return nil, zdns.STATUS_ERROR, err
	}
	if r.Rcode == dns.RcodeBadTrunc && !useTCP {
		r, _, err = tcp.Exchange(m, nameServer)
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, zdns.STATUS_BAD_RCODE, nil
	}
	for _, ans := range r.Answer {
		if innerRes, ok := parse(ans); ok {
			res.Answers = append(res.Answers, innerRes)
		}
	}
	return res, zdns.STATUS_SUCCESS, nil
}

func ParseTXT(res dns.RR) (Answer, bool) {
	if a, ok := res.(*dns.TXT); ok {
		return Answer{a.Hdr.Ttl, dns.Type(a.Hdr.Rrtype).String(), strings.Join(a.Txt, "\n")}, true
	}
	return Answer{}, false
}

func DoTxtLookup(udp *dns.Client, tcp *dns.Client, nameServer string, prefix string, name string) (string, zdns.Status, error) {
	res, status, err := DoLookup(udp, tcp, nameServer, ParseTXT, dns.TypeTXT, name)
	if status != zdns.STATUS_SUCCESS {
		return "", status, err
	}
	if parsedResult, ok := res.(Result); ok {
		for _, ans := range parsedResult.Answers {
			if strings.HasPrefix(ans.Answer, prefix) {
				return ans.Answer, zdns.STATUS_SUCCESS, err
			}
		}
	}
	return "", zdns.STATUS_NO_RECORD, nil
}
