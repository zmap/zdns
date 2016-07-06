package zdns

import ()

type GlobalConf struct {
	Threads     int
	Timeout     int
	AlexaFormat bool
	GoLangProcs int

	NameServersSpecified bool
	NameServers          []string

	InputFilePath    string
	OutputFilePath   string
	LogFilePath      string
	MetadataFilePath string

	NamePrefix string
}

type Metadata struct {
}

func GetDNSServers() []string {

	return []string{}
}

type Result struct {
	OriginalDomain string
	Domain         string
	AlexaRank      int
	Status         string
	Error          string
	Data           interface{}
}

type Status string

const (
	STATUS_SUCCESS   Status = "success"
	STATUS_ERROR     Status = "error"
	STATUS_TIMEOUT   Status = "timeout"
	STATUS_BAD_RCODE Status = "bad_r_code"
)
