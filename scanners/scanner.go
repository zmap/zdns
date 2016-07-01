package scanner

import (
	"flag"
)

type GlobalConf struct {

	threads int
	servers []string
	resultsPath string
	metadataPath string

}

type ResultInterface interface {

	Marshal() (string, error)
}
//
//func (r Result) string error {
//
//	return json.Marshal(r);
//
//}
//
//
type Scanner interface {
//
	Initialize(conf *GlobalConf)
	AddFlags(flags *flag.FlagSet)
	Lookup(name string) (ResultInterface, error)
//
//	AllowStdIn bool
//
}
//
//
//
var Scanners map[string]Scanner;
