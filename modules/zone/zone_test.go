package zone

import (
	"flag"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	logrus "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/zmap/zdns"
)

const ZoneFile = "testdata/test.zone"

func TestRun(t *testing.T) {
	var gc zdns.GlobalConf
	// global flags relevant to every lookup module
	flags := flag.NewFlagSet("flags", flag.ExitOnError)
	flags.IntVar(&gc.Threads, "threads", 1000, "number of lightweight go threads")
	flags.IntVar(&gc.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	flags.StringVar(&gc.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	flags.BoolVar(&gc.AlexaFormat, "alexa", false, "is input file from alexa top million download")
	gc.InputFilePath = ZoneFile
	gc.OutputFilePath = ""
	gc.MetadataFilePath = ""
	flags.StringVar(&gc.LogFilePath, "log-file", "", "where should JSON metadata be saved")
	flags.IntVar(&gc.Verbosity, "verbosity", 3, "logrus verbosity: 1--5")
	flags.Parse([]string{})
	servers_string := ""
	config_file := "/etc/resolv.conf"
	timeout := flags.Int("timeout", 10, "timeout for resolving an individual name")
	factory := new(GlobalLookupFactory)
	factory.AddFlags(flags)

	// complete post facto global initialization based on command line arguments
	gc.Timeout = time.Duration(time.Second * time.Duration(*timeout))
	if servers_string == "" {
		// figure out default OS name servers
		ns, err := zdns.GetDNSServers(config_file)
		if err != nil {
			logrus.Fatal("Unable to fetch correct name servers:", err.Error())
		}
		gc.NameServers = ns
		gc.NameServersSpecified = false
		logrus.Info("no name servers specified. will use: ", strings.Join(gc.NameServers, ", "))
	} else {
		gc.NameServers = strings.Split(servers_string, ",")
		gc.NameServersSpecified = true
	}
	if gc.GoMaxProcs < 0 {
		logrus.Fatal("Invalid argument for --go-processes. Must be >1.")
	}
	if gc.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(gc.GoMaxProcs)
	}
	// some modules require multiple passes over a file (this is really just the case for zone files)
	if !factory.AllowStdIn() && gc.InputFilePath == "-" {
		logrus.Fatal("Specified module does not allow reading from stdin")
	}

	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		logrus.Fatal("Factory was unable to initialize:", err.Error())
	}
	// run it.
	file, err := os.Open(ZoneFile)
	if err != nil {
		logrus.Fatal("Fatal error:", err.Error())
	}
	f, err := factory.MakeRoutineFactory()
	if err != nil {
		logrus.Fatal("Fatal error:", err.Error())
	}
	tokens := dns.ParseZone(file, ".", ZoneFile)
	for token := range tokens {
		l, err := f.MakeLookup()
		if err != nil {
			logrus.Fatal("Fatal error:", err.Error())
		}
		length := len(token.RR.Header().Name)
		if length == 0 {
			continue
		}
		_, status, err := l.DoZonefileLookup(token)
		if err != nil {
			logrus.Fatal("Fatal error:", err.Error())
		}
		if status != zdns.STATUS_NOERROR && status != zdns.STATUS_NO_OUTPUT {
			t.Error("failed lookup")
		}
	}
	// allow the factory to initialize itself
	if err := factory.Finalize(); err != nil {
		logrus.Fatal("Factory was unable to finalize:", err.Error())
	}
}
