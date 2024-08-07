/*
* ZDNS Copyright 2024 Regents of the University of Michigan
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
package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
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

	"github.com/zmap/zdns/src/cli/iohandlers"
	blacklist "github.com/zmap/zdns/src/internal/safeblacklist"
	"github.com/zmap/zdns/src/internal/util"
	"github.com/zmap/zdns/src/zdns"
)

type routineMetadata struct {
	Names  int
	Status map[zdns.Status]int
}

type Metadata struct {
	Names       int            `json:"names"`
	Status      map[string]int `json:"statuses"`
	StartTime   string         `json:"start_time"`
	EndTime     string         `json:"end_time"`
	NameServers []string       `json:"name_servers"`
	Timeout     int            `json:"timeout"`
	Retries     int            `json:"retries"`
	Conf        *CLIConf       `json:"conf"`
	ZDNSVersion string         `json:"zdns_version"`
}

func populateCLIConfig(gc *CLIConf, flags *pflag.FlagSet) *CLIConf {
	if gc.LogFilePath != "" && gc.LogFilePath != "-" {
		f, err := os.OpenFile(gc.LogFilePath, os.O_WRONLY|os.O_CREATE, util.DefaultFilePermissions)
		if err != nil {
			log.Fatalf("Unable to open log file (%s): %s", gc.LogFilePath, err.Error())
		}
		log.SetOutput(f)
	}

	// Translate the assigned verbosity level to a logrus log level.
	logLevel := log.InfoLevel
	switch gc.Verbosity {
	case 1: // Fatal
		logLevel = log.FatalLevel
	case 2: // Error
		logLevel = log.ErrorLevel
	case 3: // Warnings  (default)
		logLevel = log.WarnLevel
	case 4: // Information
		logLevel = log.WarnLevel
	case 5: // Debugging
		logLevel = log.DebugLevel
	default:
		log.Fatal("Unknown verbosity level specified. Must be between 1 (lowest)--5 (highest)")
	}
	log.SetLevel(logLevel)

	// complete post facto global initialization based on command line arguments

	// class initialization
	switch strings.ToUpper(gc.ClassString) {
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

	err := populateNetworkingConfig(gc)
	if err != nil {
		log.Fatalf("could not populate networking config: %v", err)
	}

	if gc.UseNanoseconds {
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

	// the margin for limit of open files covers different build platforms (linux/darwin), metadata files, or
	// input and output files etc.
	// check ulimit if value is high enough and if not, try to fix it
	ulimitCheck(uint64(gc.Threads + 100))

	if gc.UDPOnly && gc.TCPOnly {
		log.Fatal("TCP Only and UDP Only are conflicting")
	}
	if gc.NameServerMode && gc.AlexaFormat {
		log.Fatal("Alexa mode is incompatible with name server mode")
	}
	if gc.NameServerMode && gc.MetadataFormat {
		log.Fatal("Metadata mode is incompatible with name server mode")
	}
	if gc.NameServerMode && gc.NameOverride == "" && gc.Module != BINDVERSION {
		log.Fatal("Static Name must be defined with --override-name in --name-server-mode unless DNS module does not expect names (e.g., BINDVERSION).")
	}
	// Output Groups are defined by a base + any additional fields that the user wants
	groups := strings.Split(gc.IncludeInOutput, ",")
	if gc.ResultVerbosity != "short" && gc.ResultVerbosity != "normal" && gc.ResultVerbosity != "long" && gc.ResultVerbosity != "trace" {
		log.Fatal("Invalid result verbosity. Options: short, normal, long, trace")
	}

	gc.OutputGroups = append(gc.OutputGroups, gc.ResultVerbosity)
	gc.OutputGroups = append(gc.OutputGroups, groups...)

	// setup i/o if not specified
	if gc.InputHandler == nil {
		gc.InputHandler = iohandlers.NewFileInputHandler(gc.InputFilePath)
	}
	if gc.OutputHandler == nil {
		gc.OutputHandler = iohandlers.NewFileOutputHandler(gc.OutputFilePath)
	}
	return gc
}

func populateResolverConfig(gc *CLIConf) *zdns.ResolverConfig {
	config := zdns.NewResolverConfig()

	config.IPVersionMode = zdns.GetIPVersionMode(gc.IPv4Transport, gc.IPv6Transport)
	// if we're in IPv4 or IPv6 only mode, set the iteration preference to match
	// This is used in extractAuthorities where we need to know whether to request A or AAAA records to continue iteration
	if config.IPVersionMode == zdns.IPv4Only {
		config.IterationIPPreference = zdns.PreferIPv4
	} else if config.IPVersionMode == zdns.IPv6Only {
		config.IterationIPPreference = zdns.PreferIPv6
	} else if config.IPVersionMode == zdns.IPv4OrIPv6 && !gc.PreferIPv4Iteration && !gc.PreferIPv6Iteration {
		// need to specify some type of preference, we'll default to IPv4 and inform the user
		log.Info("No iteration IP preference specified, defaulting to IPv4 preferred. See --prefer-ipv4-iteration and --prefer-ipv6-iteration for more info")
		config.IterationIPPreference = zdns.PreferIPv4
	} else {
		config.IterationIPPreference = zdns.GetIterationIPPreference(gc.PreferIPv4Iteration, gc.PreferIPv6Iteration)
	}
	config.TransportMode = zdns.GetTransportMode(gc.UDPOnly, gc.TCPOnly)

	config.Timeout = time.Second * time.Duration(gc.Timeout)
	config.IterativeTimeout = time.Second * time.Duration(gc.IterationTimeout)
	// copy nameservers to resolver config
	if len(gc.NameServers) != 0 {
		ipv4NSs, ipv6NSs, err := util.SplitIPv4AndIPv6Addrs(gc.NameServers)
		if err != nil {
			log.Fatalf("unable to split IPv4 and IPv6 name-server addresses (%s): %v", gc.NameServers, err)
		}
		// While this is a bit of a hack to set both the root and external name servers to the same values, the CLI
		// can only be used in either recursive or iterative mode. If we don't do this and leave one or the other empty,
		// the resolver will attempt to auto-populate with the OS/ZDNS defaults. If these defaults and the user-provided
		// values have a loopback mismatch (some are loopback, others aren't), this causes issues.
		// By setting them both here, we prevent that auto-populate.
		config.RootNameServersV4 = ipv4NSs
		config.RootNameServersV6 = ipv6NSs
		config.ExternalNameServersV4 = ipv4NSs
		config.ExternalNameServersV6 = ipv6NSs
	} else if gc.IterativeResolution {
		config.RootNameServersV4 = zdns.RootServersV4[:]
		config.RootNameServersV6 = zdns.RootServersV6[:]
		config.ExternalNameServersV4 = zdns.RootServersV4[:]
		config.ExternalNameServersV6 = zdns.RootServersV6[:]
	}
	// Else: resolver will populate the external name servers with either the OS default or the ZDNS default if none exist
	config.LookupAllNameServers = gc.LookupAllNameServers
	config.FollowCNAMEs = gc.FollowCNAMEs

	// Local Addresses
	for _, ip := range gc.LocalAddrs {
		if ip.To4() != nil {
			config.LocalAddrsV4 = append(config.LocalAddrsV4, ip)
		} else if util.IsIPv6(&ip) {
			config.LocalAddrsV6 = append(config.LocalAddrsV6, ip)
		} else {
			log.Fatalf("invalid local address: %s", ip.String())
		}
	}

	if gc.UseNSID {
		config.EdnsOptions = append(config.EdnsOptions, new(dns.EDNS0_NSID))
	}
	if gc.ClientSubnet != nil {
		config.EdnsOptions = append(config.EdnsOptions, gc.ClientSubnet)
	}
	config.Cache = new(zdns.Cache)
	config.Cache.Init(gc.CacheSize)
	config.Retries = gc.Retries
	config.MaxDepth = gc.MaxDepth
	config.CheckingDisabledBit = gc.CheckingDisabled
	config.ShouldRecycleSockets = gc.RecycleSockets
	config.DNSSecEnabled = gc.Dnssec
	config.DNSConfigFilePath = gc.ConfigFilePath

	config.LogLevel = log.Level(gc.Verbosity)

	if gc.BlacklistFilePath != "" {
		config.Blacklist = blacklist.New()
		if err := config.Blacklist.ParseFromFile(gc.BlacklistFilePath); err != nil {
			log.Fatal("unable to parse blacklist file: ", err)
		}
	}
	return config
}

func Run(gc CLIConf, flags *pflag.FlagSet) {
	gc = *populateCLIConfig(&gc, flags)
	resolverConfig := populateResolverConfig(&gc)
	err := resolverConfig.PopulateAndValidate()
	if err != nil {
		log.Fatal("could not populate defaults and validate resolver config: ", err)
	}
	// Log any information about the resolver configuration, according to log level
	resolverConfig.PrintInfo()
	lookupModule, err := GetLookupModule(gc.Module)
	if err != nil {
		log.Fatal("could not get lookup module: ", err)
	}
	err = lookupModule.CLIInit(&gc, resolverConfig, flags)
	if err != nil {
		log.Fatalf("could not initialize lookup module (type: %s): %v", gc.Module, err)
	}
	// DoLookup:
	//	- n threads that do processing from in and place results in out
	//	- process until inChan closes, then wg.done()
	// Once we processing threads have all finished, wait until the
	// output and metadata threads have completed
	inChan := make(chan string)
	outChan := make(chan string)
	metaChan := make(chan routineMetadata, gc.Threads)
	var routineWG sync.WaitGroup

	inHandler := gc.InputHandler
	if inHandler == nil {
		log.Fatal("Input handler is nil")
	}

	outHandler := gc.OutputHandler
	if outHandler == nil {
		log.Fatal("Output handler is nil")
	}

	// Use handlers to populate the input and output/results channel
	go func() {
		inErr := inHandler.FeedChannel(inChan, &routineWG)
		if inErr != nil {
			log.Fatal(fmt.Sprintf("could not feed input channel: %v", inErr))
		}
	}()
	go func() {
		outErr := outHandler.WriteResults(outChan, &routineWG)
		if outErr != nil {
			log.Fatal(fmt.Sprintf("could not write output results from output channel: %v", outErr))
		}
	}()
	routineWG.Add(2)

	// create pool of worker goroutines
	var lookupWG sync.WaitGroup
	lookupWG.Add(gc.Threads)
	startTime := time.Now().Format(gc.TimeFormat)
	// create shared cache for all threads to share
	for i := 0; i < gc.Threads; i++ {
		i := i
		go func(threadID int) {
			initWorkerErr := doLookupWorker(&gc, lookupModule, resolverConfig, inChan, outChan, metaChan, &lookupWG)
			if initWorkerErr != nil {
				log.Fatalf("could not start lookup worker #%d: %v", i, initWorkerErr)
			}
		}(i)
	}
	lookupWG.Wait()
	close(outChan)
	close(metaChan)
	routineWG.Wait()
	if gc.MetadataFilePath != "" {
		// we're done processing data. aggregate all the data from individual routines
		metaData := aggregateMetadata(metaChan)
		metaData.StartTime = startTime
		metaData.EndTime = time.Now().Format(gc.TimeFormat)
		metaData.NameServers = gc.NameServers
		metaData.Retries = gc.Retries
		// Seconds() returns a float. However, timeout is passed in as an integer
		// command line argument, so there should be no loss of data when casting
		// back to an integer here.
		metaData.Timeout = gc.Timeout
		metaData.Conf = &gc
		// add global lookup-related metadata
		// write out metadata
		var f *os.File
		if gc.MetadataFilePath == "-" {
			f = os.Stderr
		} else {
			f, err = os.OpenFile(gc.MetadataFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, util.DefaultFilePermissions)
			if err != nil {
				log.Fatal("unable to open metadata file:", err.Error())
			}
			defer func(f *os.File) {
				err = f.Close()
				if err != nil {
					log.Error("unable to close metadata file:", err.Error())
				}
			}(f)
		}
		j, err := json.Marshal(metaData)
		if err != nil {
			log.Fatal("unable to JSON encode metadata:", err.Error())
		}
		_, err = f.WriteString(string(j))
		if err != nil {
			log.Errorf("unable to write metadata with error: %v", err)
		}
	}
}

// doLookupWorker is a single worker thread that processes lookups from the input channel. It calls wg.Done when it is finished.
func doLookupWorker(gc *CLIConf, lookup LookupModule, rc *zdns.ResolverConfig, input <-chan string, output chan<- string, metaChan chan<- routineMetadata, wg *sync.WaitGroup) error {
	defer wg.Done()
	resolver, err := zdns.InitResolver(rc)
	if err != nil {
		return fmt.Errorf("could not init resolver: %w", err)
	}
	var metadata routineMetadata
	metadata.Status = make(map[zdns.Status]int)
	for line := range input {
		var res zdns.Result
		var innerRes interface{}
		var trace zdns.Trace
		var status zdns.Status
		var err error
		var changed bool
		var lookupName string
		rawName := ""
		nameServer := ""
		var rank int
		var entryMetadata string
		if gc.AlexaFormat {
			rawName, rank = parseAlexa(line)
			res.AlexaRank = rank
		} else if gc.MetadataFormat {
			rawName, entryMetadata = parseMetadataInputLine(line)
			res.Metadata = entryMetadata
		} else if gc.NameServerMode {
			nameServer, err = util.AddDefaultPortToDNSServerName(line)
			if err != nil {
				log.Fatal("unable to parse name server: ", line)
			}
		} else {
			rawName, nameServer = parseNormalInputLine(line)
		}
		lookupName, changed = makeName(rawName, gc.NamePrefix, gc.NameOverride)
		if changed {
			res.AlteredName = lookupName
		}
		res.Name = rawName
		res.Class = dns.Class(gc.Class).String()

		startTime := time.Now()
		innerRes, trace, status, err = lookup.Lookup(resolver, lookupName, nameServer)

		res.Timestamp = time.Now().Format(gc.TimeFormat)
		res.Duration = time.Since(startTime).Seconds()
		if status != zdns.StatusNoOutput {
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
			if err != nil {
				log.Fatalf("unable to marshal result to JSON: %v", err)
			}
			jsonRes, err := json.Marshal(data)
			if err != nil {
				log.Fatalf("unable to marshal JSON result: %v", err)
			}
			output <- string(jsonRes)
		}
		metadata.Names++
		metadata.Status[status]++
	}
	metaChan <- metadata
	return nil
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
	r := csv.NewReader(strings.NewReader(line))
	s, err := r.Read()
	if err != nil || len(s) == 0 {
		return line, ""
	}
	if len(s) == 1 {
		return s[0], ""
	} else {
		ns, err := util.AddDefaultPortToDNSServerName(s[1])
		if err != nil {
			log.Fatal("unable to parse name server: ", s[1])
		}
		return s[0], ns
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

func aggregateMetadata(c <-chan routineMetadata) Metadata {
	var meta Metadata
	meta.ZDNSVersion = zdnsCLIVersion
	meta.Status = make(map[string]int)
	for m := range c {
		meta.Names += m.Names
		for k, v := range m.Status {
			meta.Status[string(k)] += v
		}
	}
	return meta
}
