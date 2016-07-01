package scanner

import (
	"flag"
	"fmt"
)

type AScanner struct {
	GenericScanner

}

func (s AScanner) Initialize(*GlobalConf) {

}

func (s AScanner) AddFlags(*flag.FlagSet)  {
	fmt.Println("testing")
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
