package lookup

import (
	"flag"
)

// result to be returned by scan of host
type AResult struct {
	Field string `json:"field"`
}

// scanner that will be instantiated for each connection
type ALookup struct {
	GenericLookup
	Factory *ALookupFactory
}

func (s ALookup) DoLookup(name string) (interface {}, error) {
	// this is where we do scanning
	a := AResult{Field:"Asf"}
	return &a, nil
}


type ALookupFactory struct {
	GenericLookupFactory
}

func (s ALookupFactory) AddFlags(f *flag.FlagSet) {
	f.IntVar(&s.Timeout, "timeout", 0, "")
}

func (s ALookupFactory) MakeLookup() Lookup {

	a := ALookup{Factory: &s}
	return a
}


// register the scannner globally
func init() {
	var s ALookupFactory
	RegisterLookup("a", s)
}
