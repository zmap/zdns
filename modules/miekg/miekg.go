package miekg

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zmap/zdns"
)

type Answer struct {
	Ttl        uint32
	Type       string
	Name       string
	Answer     string
	Preference uint16
	Ns         string
	Mbox       string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	Minttl     uint32
}

func (a *Answer) MarshalJSON() ([]byte, error) {
	// different types of DNS records have different sets of values. unfortunately,
	// 0 is a real value for many of them so we can't jsut omitempty. So here we are
	// with a custom marshaller.
	if a.Type == "MX" {
		return json.Marshal(&struct {
			Ttl        uint32 `json:"ttl"`
			Type       string `json:"type"`
			Name       string `json:"name"`
			Answer     string `json:"data"`
			Preference uint16 `json:"preference"`
		}{
			Ttl:    a.Ttl,
			Type:   a.Type,
			Name:   a.Name,
			Answer: a.Answer,
		})
	} else if a.Type == "SOA" {
		return json.Marshal(&struct {
			Ttl     uint32 `json:"ttl"`
			Type    string `json:"type"`
			Name    string `json:"name"`
			Ns      string `json:"ns"`
			Mbox    string `json:"mbox"`
			Serial  uint32 `json:"serial"`
			Refresh uint32 `json:"refresh"`
			Retry   uint32 `json:"retry"`
			Expire  uint32 `json:"expire"`
			Minttl  uint32 `json:"min_ttl"`
		}{
			Ttl:     a.Ttl,
			Type:    a.Type,
			Name:    a.Name,
			Ns:      a.Ns,
			Mbox:    a.Mbox,
			Serial:  a.Serial,
			Refresh: a.Refresh,
			Retry:   a.Retry,
			Expire:  a.Expire,
			Minttl:  a.Minttl,
		})
	}
	return json.Marshal(&struct {
		Ttl    uint32 `json:"ttl"`
		Type   string `json:"type"`
		Name   string `json:"name"`
		Answer string `json:"data"`
	}{
		Ttl:    a.Ttl,
		Type:   a.Type,
		Name:   a.Name,
		Answer: a.Answer,
	})
}

// result to be returned by scan of host
type Result struct {
	Answers     []Answer `json:"answers"`
	Additional  []Answer `json:"additionals"`
	Authorities []Answer `json:"authorities"`
	Protocol    string   `json:"protocol"`
}

type Lookup struct {
	DNSType dns.Type
	Prefix  string
	zdns.BaseLookup
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

func ParseAnswer(ans dns.RR) *Answer {
	var retv *Answer = nil
	if a, ok := ans.(*dns.A); ok {
		retv = &Answer{Ttl: a.Hdr.Ttl, Type: dns.Type(a.Hdr.Rrtype).String(), Name: a.Hdr.Name, Answer: a.A.String()}
	} else if aaaa, ok := ans.(*dns.AAAA); ok {
		retv = &Answer{Ttl: aaaa.Hdr.Ttl, Type: dns.Type(aaaa.Hdr.Rrtype).String(), Name: aaaa.Hdr.Name, Answer: aaaa.AAAA.String()}
	} else if cname, ok := ans.(*dns.CNAME); ok {
		retv = &Answer{Ttl: cname.Hdr.Ttl, Type: dns.Type(cname.Hdr.Rrtype).String(), Name: cname.Hdr.Name, Answer: cname.Target}
	} else if txt, ok := ans.(*dns.TXT); ok {
		retv = &Answer{Ttl: txt.Hdr.Ttl, Type: dns.Type(txt.Hdr.Rrtype).String(), Name: txt.Hdr.Name, Answer: strings.Join(txt.Txt, "\n")}
	} else if ns, ok := ans.(*dns.NS); ok {
		retv = &Answer{Ttl: ns.Hdr.Ttl, Type: dns.Type(ns.Hdr.Rrtype).String(), Name: ns.Hdr.Name, Answer: ns.Ns}
	} else if mx, ok := ans.(*dns.MX); ok {
		retv = &Answer{Ttl: mx.Hdr.Ttl, Type: dns.Type(mx.Hdr.Rrtype).String(), Name: mx.Hdr.Name, Answer: mx.Mx, Preference: mx.Preference}
	} else if ptr, ok := ans.(*dns.PTR); ok {
		retv = &Answer{Ttl: ptr.Hdr.Ttl, Type: dns.Type(ptr.Hdr.Rrtype).String(), Name: ptr.Hdr.Name, Answer: ptr.Ptr}
	} else if soa, ok := ans.(*dns.SOA); ok {
		retv = &Answer{
			Ttl:     soa.Hdr.Ttl,
			Type:    dns.Type(soa.Hdr.Rrtype).String(),
			Name:    soa.Hdr.Name,
			Ns:      strings.TrimSuffix(soa.Ns, "."),
			Mbox:    soa.Mbox,
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minttl:  soa.Minttl,
		}
	}
	if retv != nil {
		retv.Name = strings.TrimSuffix(retv.Name, ".")
	}
	return retv
}

func TranslateMiekgErrorCode(err int) zdns.Status {
	return zdns.Status(dns.RcodeToString[err])
}

func DoLookup(udp *dns.Client, tcp *dns.Client, nameServer string, dnsType uint16, name string) (interface{}, zdns.Status, error) {
	// this is where we do scanning
	res := Result{Answers: []Answer{}, Authorities: []Answer{}, Additional: []Answer{}}

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
		return nil, TranslateMiekgErrorCode(r.Rcode), nil
	}
	for _, ans := range r.Answer {
		inner := ParseAnswer(ans)
		if inner != nil {
			res.Answers = append(res.Answers, *inner)
		}
	}
	for _, ans := range r.Extra {
		inner := ParseAnswer(ans)
		if inner != nil {
			res.Additional = append(res.Additional, *inner)
		}
	}
	for _, ans := range r.Ns {
		inner := ParseAnswer(ans)
		if inner != nil {
			res.Authorities = append(res.Authorities, *inner)
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
