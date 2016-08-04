package miekg

import (
	"strings"
	"time"

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
	Answers     []Answer `json:"answers"`
	Additionals []Answer `json:"additionals"`
	Protocol    string   `json:"protocol"`
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

func (s *RoutineLookupFactory) Initialize(t time.Duration) {
	s.Client = new(dns.Client)
	s.Client.Timeout = t
	s.TCPClient = new(dns.Client)
	s.TCPClient.Net = "tcp"
	s.TCPClient.Timeout = t
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func parseAnswer(ans dns.RR) *Answer {
	if a, ok := ans.(*dns.A); ok {
		return &Answer{a.Hdr.Ttl, dns.Type(a.Hdr.Rrtype).String(), a.A.String()}
	} else if aaaa, ok := ans.(*dns.AAAA); ok {
		return &Answer{aaaa.Hdr.Ttl, dns.Type(aaaa.Hdr.Rrtype).String(), aaaa.AAAA.String()}
	} else if cname, ok := ans.(*dns.CNAME); ok {
		return &Answer{cname.Hdr.Ttl, dns.Type(cname.Hdr.Rrtype).String(), cname.Target}
	} else if txt, ok := ans.(*dns.TXT); ok {
		return &Answer{txt.Hdr.Ttl, dns.Type(a.Hdr.Rrtype).String(), strings.Join(txt.Txt, "\n")}
	}
	return nil
}

func DoLookup(udp *dns.Client, tcp *dns.Client, nameServer string, dnsType uint16, name string) (interface{}, zdns.Status, error) {
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
	if err != nil || r == nil {
		return nil, zdns.STATUS_ERROR, err
	}
	if r.Rcode == dns.RcodeBadTrunc && !useTCP {
		r, _, err = tcp.Exchange(m, nameServer)
	}
	if err != nil || r == nil {
		return nil, zdns.STATUS_ERROR, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, zdns.STATUS_BAD_RCODE, nil
	}
	for _, ans := range r.Answer {
		inner := parseAnswer(ans)
		if inner != nil {
			res.Answers = append(res.Answers, *inner)
		}
	}
	for _, ans := range r.Additional {
		inner := parseAnswer(ans)
		if inner != nil {
			res.Answers = append(res.Answers, *inner)
		}
	}

	return res, zdns.STATUS_SUCCESS, nil
}

func DoTxtLookup(udp *dns.Client, tcp *dns.Client, nameServer string, prefix string, name string) (string, zdns.Status, error) {
	res, status, err := DoLookup(udp, tcp, nameServer, dns.TypeTXT, name)
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
