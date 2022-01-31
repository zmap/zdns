/*
 * ZDNS Copyright 2020 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package zdns

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/liip/sheriff"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/internal/util"
	"github.com/zmap/zdns/iohandlers"
)

type routineMetadata struct {
	Names  int
	Status map[Status]int
}

func Run(gc GlobalConf, flags *pflag.FlagSet,
	timeout *int, iterationTimeout *int,
	class_string *string, servers_string *string,
	config_file *string, localaddr_string *string,
	localif_string *string, nanoSeconds *bool) {

	factory := GetLookup(gc.Module)
	log.Info("running still..")

	if factory == nil {
		log.Fatal("Invalid lookup module specified. Valid modules: ", ValidlookupsString())
	}

	if gc.LogFilePath != "" {
		f, err := os.OpenFile(gc.LogFilePath, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Fatalf("Unable to open log file (%s): %s", gc.LogFilePath, err.Error())
		}
		log.SetOutput(f)
	}

	// Translate the assigned verbosity level to a logrus log level.
	switch gc.Verbosity {
	case 1: // Fatal
		log.SetLevel(log.FatalLevel)
	case 2: // Error
		log.SetLevel(log.ErrorLevel)
	case 3: // Warnings  (default)
		log.SetLevel(log.WarnLevel)
	case 4: // Information
		log.SetLevel(log.InfoLevel)
	case 5: // Debugging
		log.SetLevel(log.DebugLevel)
	default:
		log.Fatal("Unknown verbosity level specified. Must be between 1 (lowest)--5 (highest)")
	}

	// complete post facto global initialization based on command line arguments
	gc.Timeout = time.Duration(time.Second * time.Duration(*timeout))
	gc.IterationTimeout = time.Duration(time.Second * time.Duration(*iterationTimeout))

	// class initialization
	switch strings.ToUpper(*class_string) {
	case "INET", "IN":
		gc.Class = dns.ClassINET
	case "CSNET", "CS":
		gc.Class = dns.ClassCSNET
	case "CHAOS", "CH":
		gc.Class = dns.ClassCHAOS
	case "HESIOD", "HS":
		gc.Class = dns.ClassHESIOD
	case "NONE":
		gc.Class = dns.ClassNONE
	case "ANY":
		gc.Class = dns.ClassANY
	default:
		log.Fatal("Unknown record class specified. Valid valued are INET (default), CSNET, CHAOS, HESIOD, NONE, ANY")

	}

	if *servers_string == "" {
		// if we're doing recursive resolution, figure out default OS name servers
		// otherwise, use the set of 13 root name servers
		if gc.IterativeResolution {
			gc.NameServers = RootServers[:]
		} else {
			ns, err := GetDNSServers(*config_file)
			if err != nil {
				ns = util.GetDefaultResolvers()
				log.Warn("Unable to parse resolvers file. Using ZDNS defaults: ", strings.Join(ns, ", "))
			}
			gc.NameServers = ns
		}
		gc.NameServersSpecified = false
		log.Info("No name servers specified. will use: ", strings.Join(gc.NameServers, ", "))
	} else {
		if gc.NameServerMode {
			log.Fatal("name servers cannot be specified on command line in --name-server-mode")
		}
		var ns []string
		if (*servers_string)[0] == '@' {
			filepath := (*servers_string)[1:]
			f, err := ioutil.ReadFile(filepath)
			if err != nil {
				log.Fatalf("Unable to read file (%s): %s", filepath, err.Error())
			}
			if len(f) == 0 {
				log.Fatalf("Empty file (%s)", filepath)
			}
			ns = strings.Split(strings.Trim(string(f), "\n"), "\n")
		} else {
			ns = strings.Split(*servers_string, ",")
		}
		for i, s := range ns {
			ns[i] = util.AddDefaultPortToDNSServerName(s)
		}
		gc.NameServers = ns
		gc.NameServersSpecified = true
	}

	if *localaddr_string != "" {
		for _, la := range strings.Split(*localaddr_string, ",") {
			ip := net.ParseIP(la)
			if ip != nil {
				gc.LocalAddrs = append(gc.LocalAddrs, ip)
			} else {
				log.Fatal("Invalid argument for --local-addr (", la, "). Must be a comma-separated list of valid IP addresses.")
			}
		}
		log.Info("using local address: ", localaddr_string)
		gc.LocalAddrSpecified = true
	}
	if *localif_string != "" {
		if gc.LocalAddrSpecified {
			log.Fatal("Both --local-addr and --local-interface specified.")
		} else {
			li, err := net.InterfaceByName(*localif_string)
			if err != nil {
				log.Fatal("Invalid local interface specified: ", err)
			}
			addrs, err := li.Addrs()
			if err != nil {
				log.Fatal("Unable to detect addresses of local interface: ", err)
			}
			for _, la := range addrs {
				gc.LocalAddrs = append(gc.LocalAddrs, la.(*net.IPNet).IP)
				gc.LocalAddrSpecified = true
			}
			log.Info("using local interface: ", localif_string)
		}
	}
	if !gc.LocalAddrSpecified {
		// Find local address for use in unbound UDP sockets
		if conn, err := net.Dial("udp", "8.8.8.8:53"); err != nil {
			log.Fatal("Unable to find default IP address: ", err)
		} else {
			gc.LocalAddrs = append(gc.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
		}
	}
	if *nanoSeconds {
		gc.TimeFormat = time.RFC3339Nano
	} else {
		gc.TimeFormat = time.RFC3339
	}
	if gc.GoMaxProcs < 0 {
		log.Fatal("Invalid argument for --go-processes. Must be >1.")
	}
	if gc.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(gc.GoMaxProcs)
	}
	if gc.UDPOnly && gc.TCPOnly {
		log.Fatal("TCP Only and UDP Only are conflicting")
	}
	if gc.NameServerMode && gc.AlexaFormat {
		log.Fatal("Alexa mode is incompatible with name server mode")
	}
	if gc.NameServerMode && gc.MetadataFormat {
		log.Fatal("Metadata mode is incompatible with name server mode")
	}
	if gc.NameServerMode && gc.NameOverride == "" && gc.Module != "BINDVERSION" {
		log.Fatal("Static Name must be defined with --override-name in --name-server-mode unless DNS module does not expect names (e.g., BINDVERSION).")
	}
	// Output Groups are defined by a base + any additional fields that the user wants
	groups := strings.Split(gc.IncludeInOutput, ",")
	if gc.ResultVerbosity != "short" && gc.ResultVerbosity != "normal" && gc.ResultVerbosity != "long" && gc.ResultVerbosity != "trace" {
		log.Fatal("Invalid result verbosity. Options: short, normal, long, trace")
	}

	gc.OutputGroups = append(gc.OutputGroups, gc.ResultVerbosity)
	gc.OutputGroups = append(gc.OutputGroups, groups...)

	if len(flags.Args()) > 0 {
		stat, _ := os.Stdin.Stat()
		// If stdin is piped from the terminal, and we haven't specified a file, and if we have unparsed args
		// use them for a dig-like resolution
		log.Info(stat.Mode() & os.ModeCharDevice)
		log.Info(gc.InputFilePath)
		log.Info(len(flags.Args()))
		if (stat.Mode()&os.ModeCharDevice) != 0 && gc.InputFilePath == "-" && len(flags.Args()) == 1 {
			gc.PassedName = flags.Args()[0]
		} else {
			log.Fatal("Unused command line flags: ", flags.Args())
		}
	}

	// Seeding for RandomNameServer()
	rand.Seed(time.Now().UnixNano())

	// some modules require multiple passes over a file (this is really just the case for zone files)
	if !factory.AllowStdIn() && gc.InputFilePath == "-" {
		log.Fatal("Specified module does not allow reading from stdin")
	}

	// setup i/o
	gc.InputHandler = iohandlers.NewFileInputHandler(gc.InputFilePath)
	gc.OutputHandler = iohandlers.NewFileOutputHandler(gc.OutputFilePath)

	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		log.Fatal("Factory was unable to initialize:", err.Error())
	}
	// run it.
	if err := DoLookups(factory, &gc); err != nil {
		log.Fatal("Unable to run lookups:", err.Error())
	}
	// allow the factory to finalize itself
	if err := factory.Finalize(); err != nil {
		log.Fatal("Factory was unable to finalize:", err.Error())
	}
}

func GetDNSServers(path string) ([]string, error) {
	c, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return []string{}, err
	}
	var servers []string
	for _, s := range c.Servers {
		if s[0:1] != "[" && strings.Contains(s, ":") {
			s = "[" + s + "]"
		}
		full := strings.Join([]string{s, c.Port}, ":")
		servers = append(servers, full)
	}
	return servers, nil
}

func parseAlexa(line string) (string, int) {
	s := strings.SplitN(line, ",", 2)
	rank, err := strconv.Atoi(s[0])
	if err != nil {
		log.Fatal("Malformed Alexa Top Million file")
	}
	return s[1], rank
}

func parseMetadataInputLine(line string) (string, string) {
	s := strings.SplitN(line, ",", 2)
	if len(s) == 1 {
		return s[0], ""
	}
	return s[0], s[1]
}

func parseNormalInputLine(line string) (string, string) {
	s := strings.SplitN(line, ",", 2)
	if len(s) == 1 {
		return s[0], ""
	} else {
		return s[0], util.AddDefaultPortToDNSServerName(s[1])
	}
}

func makeName(name, prefix, nameOverride string) (string, bool) {
	if nameOverride != "" {
		return nameOverride, true
	}
	trimmedName := strings.TrimSuffix(name, ".")
	if prefix == "" {
		return trimmedName, name != trimmedName
	} else {
		return strings.Join([]string{prefix, trimmedName}, ""), true
	}
}

func doLookup(g GlobalLookupFactory, gc *GlobalConf, input <-chan interface{}, output chan<- string, metaChan chan<- routineMetadata, wg *sync.WaitGroup, threadID int) error {
	f, err := g.MakeRoutineFactory(threadID)
	if err != nil {
		log.Fatal("Unable to create new routine factory", err.Error())
	}
	var metadata routineMetadata
	metadata.Status = make(map[Status]int)
	for genericInput := range input {
		var res Result
		var innerRes interface{}
		var trace []interface{}
		var status Status
		var err error
		l, err := f.MakeLookup()
		if err != nil {
			log.Fatal("Unable to build lookup instance", err)
		}
		line := genericInput.(string)
		var changed bool
		var lookupName string
		rawName := ""
		nameServer := ""
		var rank int
		var entryMetadata string
		if gc.AlexaFormat == true {
			rawName, rank = parseAlexa(line)
			res.AlexaRank = rank
		} else if gc.MetadataFormat {
			rawName, entryMetadata = parseMetadataInputLine(line)
			res.Metadata = entryMetadata
		} else if gc.NameServerMode {
			nameServer = util.AddDefaultPortToDNSServerName(line)
		} else {
			rawName, nameServer = parseNormalInputLine(line)
		}
		lookupName, changed = makeName(rawName, gc.NamePrefix, gc.NameOverride)
		if changed {
			res.AlteredName = lookupName
		}
		res.Name = rawName
		res.Class = dns.Class(gc.Class).String()
		innerRes, trace, status, err = l.DoLookup(lookupName, nameServer)
		res.Timestamp = time.Now().Format(gc.TimeFormat)
		if status != STATUS_NO_OUTPUT {
			res.Status = string(status)
			res.Data = innerRes
			res.Trace = trace
			if err != nil {
				res.Error = err.Error()
			}
			v, _ := version.NewVersion("0.0.0")
			o := &sheriff.Options{
				Groups:     gc.OutputGroups,
				ApiVersion: v,
			}
			data, err := sheriff.Marshal(o, res)
			jsonRes, err := json.Marshal(data)
			if err != nil {
				log.Fatal("Unable to marshal JSON result", err)
			}
			output <- string(jsonRes)
		}
		metadata.Names++
		metadata.Status[status]++
	}
	metaChan <- metadata
	wg.Done()
	return nil
}

func aggregateMetadata(c <-chan routineMetadata) Metadata {
	var meta Metadata
	meta.Status = make(map[string]int)
	for m := range c {
		meta.Names += m.Names
		for k, v := range m.Status {
			meta.Status[string(k)] += v
		}
	}
	return meta
}

func DoLookups(g GlobalLookupFactory, c *GlobalConf) error {
	// DoLookup:
	//	- n threads that do processing from in and place results in out
	//	- process until inChan closes, then wg.done()
	// Once we processing threads have all finished, wait until the
	// output and metadata threads have completed
	inChan := make(chan interface{})
	outChan := make(chan string)
	metaChan := make(chan routineMetadata, c.Threads)
	var routineWG sync.WaitGroup

	inHandler := c.InputHandler
	if inHandler == nil {
		log.Fatal("Input handler is nil")
	}

	outHandler := c.OutputHandler
	if outHandler == nil {
		log.Fatal("Output handler is nil")
	}

	// Use handlers to populate the input and output/results channel
	go inHandler.FeedChannel(inChan, &routineWG)
	go outHandler.WriteResults(outChan, &routineWG)
	routineWG.Add(2)

	// create pool of worker goroutines
	var lookupWG sync.WaitGroup
	lookupWG.Add(c.Threads)
	startTime := time.Now().Format(c.TimeFormat)
	for i := 0; i < c.Threads; i++ {
		go doLookup(g, c, inChan, outChan, metaChan, &lookupWG, i)
	}
	lookupWG.Wait()
	close(outChan)
	close(metaChan)
	routineWG.Wait()
	if c.MetadataFilePath != "" {
		// we're done processing data. aggregate all the data from individual routines
		metaData := aggregateMetadata(metaChan)
		metaData.StartTime = startTime
		metaData.EndTime = time.Now().Format(c.TimeFormat)
		metaData.NameServers = c.NameServers
		metaData.Retries = c.Retries
		// Seconds() returns a float. However, timeout is passed in as an integer
		// command line argument, so there should be no loss of data when casting
		// back to an integer here.
		metaData.Timeout = int(c.Timeout.Seconds())
		metaData.Conf = c
		// add global lookup-related metadata
		// write out metadata
		var f *os.File
		if c.MetadataFilePath == "-" {
			f = os.Stderr
		} else {
			var err error
			f, err = os.OpenFile(c.MetadataFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				log.Fatal("unable to open metadata file:", err.Error())
			}
			defer f.Close()
		}
		j, err := json.Marshal(metaData)
		if err != nil {
			log.Fatal("unable to JSON encode metadata:", err.Error())
		}
		f.WriteString(string(j))
	}
	return nil
}
