package zdns

import (
	"flag"
	_ "log"
	"strings"
)

type Lookup interface {
	DoLookup(name string) (interface{}, error)
}

type GenericLookup struct {
	NameServers *[]string
	Timeout     int
}

type LookupFactory interface {
	// expected to add any necessary commandline flags if being
	// run as a standalone scanner
	AddFlags(flags *flag.FlagSet) error
	// global initialization. Gets called once globally
	// This is called after command line flags have been parsed
	Initialize(conf *GlobalConf) error
	// We can't set variables on an interface, so write functions
	// that define any settings for the factory
	AllowStdIn() bool
	// Return a single scanner which will scan a single host
	MakeLookup() (Lookup, error)
}

type GenericLookupFactory struct {
	NameServers *[]string
	Timeout     int
}

func (l GenericLookupFactory) Initialize(c *GlobalConf) error {
	return nil
}

func (s GenericLookupFactory) AllowStdIn() bool {
	return true
}

// keep a mapping from name to factory
var lookups map[string]LookupFactory

func RegisterLookup(name string, s LookupFactory) {
	if lookups == nil {
		lookups = make(map[string]LookupFactory, 100)
	}
	lookups[name] = s
}

func ValidlookupsString() string {

	valid := make([]string, len(lookups))
	for k, _ := range lookups {
		valid = append(valid, k)
		//log.Debug("loaded module:", k)
	}
	return strings.Join(valid, ", ")
}

func GetLookup(name string) *LookupFactory {

	factory, ok := lookups[name]
	if !ok {
		return nil
	}
	return &factory
}
