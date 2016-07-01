package scanner

import (
	"flag"
)

type AScanner struct {
	GenericScanner

}

func (s AScanner) Initialize(*GlobalConf) {

}

func (s AScanner) AddFlags(*flag.FlagSet)  {

}

func (s AScanner) Lookup(string) (ResultInterface, error) {

	return nil, nil
}

func (s AScanner) Close(*GlobalConf) {


}

func init() {
	var s AScanner
	Scanners["a"] = &s
}

