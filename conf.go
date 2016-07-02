package conf

type GlobalConf struct {

	Threads int
	AlexaFormat bool
	GoLangProcs int

	NameServersSpecified bool
	NameServers []string

	InputFilePath string
	InputFile *file
	OuputFilePath string
	OuputFile *file
	LogFilePath string
	LogFile *file
	MetadataFilePath string
	MetadataFile *file

	NamePrefix string

}


type Metadata struct {




}


func GetDNSServers() []string {


}
