package scanner

import (
	"flag"
)

type AScanner struct {


}

func (s AScanner) Initialize(*GlobalConf) {

}

func (s AScanner) AddFlags(*flag.FlagSet)  {

}

func (s AScanner) Lookup(string) (ResultInterface, error) {

	return nil, nil
}

func init() {
	var s AScanner
	Scanners["a"] = &s
}

