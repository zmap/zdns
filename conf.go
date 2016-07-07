package zdns

import ()

type GlobalConf struct {
	Threads     int
	Timeout     int
	AlexaFormat bool
	GoMaxProcs  int
	Verbosity   int

	NameServersSpecified bool
	NameServers          []string

	InputFilePath    string
	OutputFilePath   string
	LogFilePath      string
	MetadataFilePath string

	NamePrefix string
}

type Metadata struct {
	Names       int            `json:"names"`
	Status      map[string]int `json:"statuses"`
	StartTime   string         `json:"start_time"`
	EndTime     string         `json:"end_time"`
	NameServers []string       `json:"name_servers"`
}

type Result struct {
	OriginalDomain string      `json:"original,omitempty"`
	Domain         string      `json:"domain,omitempty"`
	AlexaRank      int         `json:"alexa_rank,omitempty"`
	Status         string      `json:"status,omitempty"`
	Error          string      `json:"error,omitempty"`
	Data           interface{} `json:"data,omitempty"`
}

type Status string

const (
	STATUS_SUCCESS   Status = "success"
	STATUS_ERROR     Status = "error"
	STATUS_TIMEOUT   Status = "timeout"
	STATUS_BAD_RCODE Status = "bad_r_code"
)
