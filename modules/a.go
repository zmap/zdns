package a

import (
	"flag"
	"github.com/miekg/dns"
	"github.com/zmap/zdns"
	"strings"
)

// result to be returned by scan of host
type Result struct {
	Addresses []string `json:"addresses"`
}

// Per Connection Lookup ======================================================
//
type Lookup struct {
	Factory *RoutineLookupFactory
}

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func (s *Lookup) DoLookup(name string) (interface{}, zdns.Status, error) {
	// get a name server to use for this connection
	nameServer := s.Factory.Factory.RandomNameServer()
	// this is where we do scanning
	res := Result{Addresses: []string{}}

	m := new(dns.Msg)
	m.SetQuestion(dotName(name), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := s.Factory.Client.Exchange(m, nameServer)
	if err != nil {
		return nil, zdns.STATUS_ERROR, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, zdns.STATUS_BAD_RCODE, nil
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			res.Addresses = append(res.Addresses, a.A.String())
		}
	}
	return &res, zdns.STATUS_SUCCESS, nil
}

// Per GoRoutine Factory ======================================================
//
type RoutineLookupFactory struct {
	Factory *GlobalLookupFactory
	Client  *dns.Client
}

func (s *RoutineLookupFactory) Initialize(f *GlobalLookupFactory) {
	s.Factory = f
	s.Client = new(dns.Client)
}

func (s *RoutineLookupFactory) MakeLookup() (zdns.Lookup, error) {
	a := Lookup{Factory: s}
	return &a, nil
}

// Global Factory =============================================================
//
type GlobalLookupFactory struct {
	zdns.BaseGlobalLookupFactory
}

func (s *GlobalLookupFactory) AddFlags(f *flag.FlagSet) {
	//f.IntVar(&s.Timeout, "timeout", 0, "")
}

// Command-line Help Documentation. This is the descriptive text what is
// returned when you run zdns module --help
func (s *GlobalLookupFactory) Help() string {
	return ""
}

func (s *GlobalLookupFactory) MakeRoutineFactory() (zdns.RoutineLookupFactory, error) {
	r := new(RoutineLookupFactory)
	r.Initialize(s)
	return r, nil
}

// Global Registration ========================================================
//
func init() {
	s := new(GlobalLookupFactory)
	zdns.RegisterLookup("a", s)
}
