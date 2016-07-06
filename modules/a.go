package a

import (
	"flag"
	"github.com/miekg/dns"
	"github.com/zmap/zdns"
)

// result to be returned by scan of host
type AResult struct {
	Addresses []string `json:"addresses"`
}

// scanner that will be instantiated for each connection
type ALookup struct {
	zdns.GenericLookup
	Factory *ALookupFactory
}

func (s ALookup) DoLookup(name string) (interface{}, string, error) {
	// this is where we do scanning
	a := AResult{Field: "Asf"}
	return &a, "", nil
}

type ALookupFactory struct {
	zdns.GenericLookupFactory
}

func (s ALookupFactory) AddFlags(f *flag.FlagSet) error {
	f.IntVar(&s.Timeout, "timeout", 0, "")
	return nil
}

func (s ALookupFactory) MakeLookup() (zdns.Lookup, error) {

	a := ALookup{Factory: &s}
	return a, nil
}

// register the scannner globally
func init() {
	var s ALookupFactory
	zdns.RegisterLookup("a", s)
}
