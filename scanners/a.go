package scanner

import (
	"flag"
_	"fmt"
)

type AScanner struct {
	GenericScanner
	test int
}

func (s AScanner) AddFlags(f *flag.FlagSet)  {
	f.IntVar(&s.test, "test", 0, "")
}

func (s AScanner) Initialize(*GlobalConf) {

}

func (s AScanner) Lookup(string) (ResultInterface, error) {

	return nil, nil
}

func (s AScanner) Close(*GlobalConf) {


}

// register the scannner globally
func init() {
	var s AScanner
	register_scanner("a", s)
}
