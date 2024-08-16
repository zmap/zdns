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
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/liip/sheriff"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/cli/iohandlers"
	blacklist "github.com/zmap/zdns/src/internal/safeblacklist"
	"github.com/zmap/zdns/src/internal/util"
	"github.com/zmap/zdns/src/zdns"
)

const (
	googleDNSResolverAddr   = "8.8.8.8:53"
	googleDNSResolverAddrV6 = "[2001:4860:4860::8888]:53"
	loopbackIPv4Addr        = "127.0.0.1"
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

// populateCLIConfig populates the CLIConf struct with the values from the command line arguments or the defaults.
func populateCLIConfig(gc *CLIConf, domains []string) *CLIConf {
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
	if len(domains) > 0 {
		// using domains from command line
		gc.InputHandler = iohandlers.NewStringSliceInputHandler(domains)
	} else if gc.InputHandler == nil {
		gc.InputHandler = iohandlers.NewFileInputHandler(gc.InputFilePath)
	}
	if gc.OutputHandler == nil {
		gc.OutputHandler = iohandlers.NewFileOutputHandler(gc.OutputFilePath)
	}
	return gc
}

func populateResolverConfig(gc *CLIConf) *zdns.ResolverConfig {
	config := zdns.NewResolverConfig()
	config.TransportMode = zdns.GetTransportMode(gc.UDPOnly, gc.TCPOnly)
	config.Timeout = time.Second * time.Duration(gc.Timeout)
	config.IterativeTimeout = time.Second * time.Duration(gc.IterationTimeout)
	config.LookupAllNameServers = gc.LookupAllNameServers
	config.FollowCNAMEs = gc.FollowCNAMEs

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
	// This must occur after setting the DNSConfigFilePath above, so that ZDNS knows where to fetch the DNS Config
	config, err := populateIPTransportMode(gc, config)
	if err != nil {
		log.Fatal("could not populate IP transport mode: ", err)
	}
	// This is used in extractAuthorities where we need to know whether to request A or AAAA records to continue iteration
	// Must be set after populating IPTransportMode
	if config.IPVersionMode == zdns.IPv4Only {
		config.IterationIPPreference = zdns.PreferIPv4
	} else if config.IPVersionMode == zdns.IPv6Only {
		config.IterationIPPreference = zdns.PreferIPv6
	} else if config.IPVersionMode == zdns.IPv4OrIPv6 && !gc.PreferIPv4Iteration && !gc.PreferIPv6Iteration {
		// need to specify some type of preference, we'll default to IPv4 and inform the user
		log.Info("No iteration IP preference specified, defaulting to IPv4 preferred. See --prefer-ipv4-iteration and --prefer-ipv6-iteration for more info")
		config.IterationIPPreference = zdns.PreferIPv4
	} else if config.IPVersionMode == zdns.IPv4OrIPv6 && gc.PreferIPv4Iteration && gc.PreferIPv6Iteration {
		log.Fatal("Cannot specify both --prefer-ipv4-iteration and --prefer-ipv6-iteration")
	} else {
		config.IterationIPPreference = zdns.GetIterationIPPreference(gc.PreferIPv4Iteration, gc.PreferIPv6Iteration)
	}
	// This must occur after setting the DNSConfigFilePath above, so that ZDNS knows where to fetch the DNS Config
	config, err = populateNameServers(gc, config)
	if err != nil {
		log.Fatal("could not populate name servers: ", err)
	}
	// User/OS defaults could contain duplicates, remove
	config.ExternalNameServersV4 = util.RemoveDuplicates(config.ExternalNameServersV4)
	config.RootNameServersV4 = util.RemoveDuplicates(config.RootNameServersV4)
	config.ExternalNameServersV6 = util.RemoveDuplicates(config.ExternalNameServersV6)
	config.RootNameServersV6 = util.RemoveDuplicates(config.RootNameServersV6)

	if config.IPVersionMode == zdns.IPv4Only {
		// Drop any IPv6 nameservers
		config.ExternalNameServersV6 = []string{}
		config.RootNameServersV6 = []string{}
	}
	if config.IPVersionMode == zdns.IPv6Only {
		// Drop any IPv4 nameservers
		config.ExternalNameServersV4 = []string{}
		config.RootNameServersV4 = []string{}
	}

	config, err = populateLocalAddresses(gc, config)
	if err != nil {
		log.Fatal("could not populate local addresses: ", err)
	}
	return config
}

// populateIPTransportMode populates the IPTransportMode field of the ResolverConfig
// If user sets --4 (IPv4 Only) or --6 (IPv6 Only), we'll set the IPVersionMode to IPv4Only or IPv6Only, respectively.
// Otherwise, we need to determine the IPVersionMode based on either the OS' default resolver(s) or the user's provided name servers.
// Note: populateNameServers must be called before this function to ensure the nameservers are populated.
func populateIPTransportMode(gc *CLIConf, config *zdns.ResolverConfig) (*zdns.ResolverConfig, error) {
	if gc.IPv4TransportOnly && gc.IPv6TransportOnly {
		return nil, errors.New("only one of --4 and --6 allowed")
	}
	if gc.IPv4TransportOnly {
		config.IPVersionMode = zdns.IPv4Only
		return config, nil
	}
	if gc.IPv6TransportOnly {
		config.IPVersionMode = zdns.IPv6Only
		return config, nil
	}
	nameServersSupportIPv4 := false
	nameServersSupportIPv6 := false
	// Check if user provided nameservers
	if len(gc.NameServers) != 0 {
		// Check that the nameservers have a port and append one if necessary
		portValidatedNSs := make([]string, 0, len(gc.NameServers))
		// check that the nameservers have a port and append one if necessary
		for _, ns := range gc.NameServers {
			portNS, err := util.AddDefaultPortToDNSServerName(ns)
			if err != nil {
				return nil, fmt.Errorf("could not parse name server: %s. Correct IPv4 format: 1.1.1.1:53 or IPv6 format: [::1]:53", ns)
			}
			portValidatedNSs = append(portValidatedNSs, portNS)
		}
		v4NameServers, v6NameServers, err := util.SplitIPv4AndIPv6Addrs(portValidatedNSs)
		if err != nil {
			return nil, errors.Wrap(err, "could not split IPv4 and IPv6 addresses for nameservers")
		}
		if len(v4NameServers) != 0 {
			nameServersSupportIPv4 = true
		}
		if len(v6NameServers) != 0 {
			nameServersSupportIPv6 = true
		}
	} else {
		// User did not provide nameservers, check the OS' default resolver(s)
		v4NameServers, v6NameServers, err := zdns.GetDNSServers(config.DNSConfigFilePath)
		if err != nil {
			log.Warn("Unable to parse resolvers file to determine if IPv4 or IPv6 is supported. Defaulting to IPv4")
			config.IPVersionMode = zdns.IPv4Only
			return config, nil
		}
		if len(v4NameServers) != 0 {
			nameServersSupportIPv4 = true
		}
		if len(v6NameServers) != 0 {
			nameServersSupportIPv6 = true
		}
	}
	if nameServersSupportIPv4 && nameServersSupportIPv6 {
		config.IPVersionMode = zdns.IPv4OrIPv6
		return config, nil
	} else if nameServersSupportIPv4 {
		config.IPVersionMode = zdns.IPv4Only
		return config, nil
	} else if nameServersSupportIPv6 {
		config.IPVersionMode = zdns.IPv6Only
		return config, nil
	} else {
		return nil, errors.New("no nameservers found with OS defaults. Please specify desired nameservers with --name-servers")
	}
}

func populateNameServers(gc *CLIConf, config *zdns.ResolverConfig) (*zdns.ResolverConfig, error) {
	// Nameservers are populated in this order:
	// 1. If user provided nameservers, use those
	// 2. (External Only) If we can get the OS' default recursive resolver nameservers, use those
	// 3. Use ZDNS defaults

	// Additionally, both Root and External nameservers must be populated, since the Resolver doesn't know we'll only
	// be performing either iterative or recursive lookups, not both.
	// IPv4 Name Servers/Local Address only needs to be populated if we're doing IPv4 lookups, same for IPv6
	if len(gc.NameServers) != 0 {
		// User provided name servers, use them.
		// Check that the nameservers have a port and append one if necessary
		portValidatedNSs := make([]string, 0, len(gc.NameServers))
		// check that the nameservers have a port and append one if necessary
		for _, ns := range gc.NameServers {
			portNS, err := util.AddDefaultPortToDNSServerName(ns)
			if err != nil {
				return nil, fmt.Errorf("could not parse name server: %s. Correct IPv4 format: 1.1.1.1:53 or IPv6 format: [::1]:53", ns)
			}
			portValidatedNSs = append(portValidatedNSs, portNS)
		}
		v4NameServers, v6NameServers, err := util.SplitIPv4AndIPv6Addrs(portValidatedNSs)
		if err != nil {
			return nil, errors.Wrap(err, "could not split IPv4 and IPv6 addresses for nameservers")
		}
		// The resolver will ignore IPv6 nameservers if we're doing IPv4 only lookups, and vice versa so this is fine
		config.ExternalNameServersV4 = v4NameServers
		config.RootNameServersV4 = v4NameServers
		config.ExternalNameServersV6 = v6NameServers
		config.RootNameServersV6 = v6NameServers
		return config, nil
	}
	// User did not provide nameservers
	if !gc.IterativeResolution {
		// Try to get the OS' default recursive resolver nameservers
		v4NameServers, v6NameServers, err := zdns.GetDNSServers(config.DNSConfigFilePath)
		if err != nil {
			v4NameServers, v6NameServers = zdns.DefaultExternalResolversV4, zdns.DefaultExternalResolversV6
			log.Warn("Unable to parse resolvers file. Using ZDNS defaults: ", strings.Join(util.Concat(v4NameServers, v6NameServers), ", "))
		}
		if config.IPVersionMode != zdns.IPv6Only {
			if len(v4NameServers) == 0 {
				return nil, errors.New("no IPv4 nameservers found. Please specify desired nameservers with --name-servers")
			}
			config.ExternalNameServersV4 = v4NameServers
			config.RootNameServersV4 = v4NameServers
		}
		if config.IPVersionMode != zdns.IPv4Only {
			if len(v6NameServers) == 0 {
				return nil, errors.New("no IPv6 nameservers found. Please specify desired nameservers with --name-servers")
			}
			config.ExternalNameServersV6 = v6NameServers
			config.RootNameServersV6 = v6NameServers
		}
		return config, nil
	}
	// User did not provide nameservers and we're doing iterative resolution, use ZDNS defaults
	config.ExternalNameServersV4 = zdns.RootServersV4[:]
	config.RootNameServersV4 = zdns.RootServersV4[:]
	config.ExternalNameServersV6 = zdns.RootServersV6[:]
	config.RootNameServersV6 = zdns.RootServersV6[:]
	return config, nil
}

func populateLocalAddresses(gc *CLIConf, config *zdns.ResolverConfig) (*zdns.ResolverConfig, error) {
	// Local Addresses are populated in this order:
	// 1. If user provided local addresses, use those
	// 2. If the config's nameservers are loopback, use the local loopback address
	// 3. Otherwise, try to connect to Google's recursive resolver and take the IP address we use for the connection

	// IPv4 local addresses are required for IPv4 lookups, same for IPv6
	if len(gc.LocalAddrs) != 0 {
		// if user provided a local address(es), that takes precedent
		config.LocalAddrsV4, config.LocalAddrsV6 = []net.IP{}, []net.IP{}
		for _, addr := range gc.LocalAddrs {
			if addr == nil {
				return nil, errors.New("invalid nil local address")
			}
			if addr.To4() != nil {
				config.LocalAddrsV4 = append(config.LocalAddrsV4, addr)
			} else if util.IsIPv6(&addr) {
				config.LocalAddrsV6 = append(config.LocalAddrsV6, addr)
			} else {
				return nil, fmt.Errorf("invalid local address: %s", addr.String())
			}
		}
		return config, nil
	}
	// if the nameservers are loopback, use the loopback address
	allNameServers := util.Concat(config.ExternalNameServersV4, config.ExternalNameServersV6, config.RootNameServersV4, config.RootNameServersV6)
	if len(allNameServers) == 0 {
		// this shouldn't happen
		return nil, errors.New("name servers must be set before populating local addresses")
	}
	anyNameServersLoopack := false
	for _, ns := range allNameServers {
		ip, _, err := util.SplitHostPort(ns)
		if err != nil {
			return nil, errors.Wrapf(err, "could not split host and port for nameserver: %s", ns)
		}
		if ip.IsLoopback() {
			anyNameServersLoopack = true
			break
		}
	}

	if anyNameServersLoopack {
		// set local address so name servers are reachable
		config.LocalAddrsV4 = []net.IP{net.ParseIP(loopbackIPv4Addr)}
		// loopback nameservers not supported for IPv6, we'll let Resolver validation take care of this
	} else {
		// localAddr not set, so we need to find the default IP address
		if config.IPVersionMode != zdns.IPv6Only {
			conn, err := net.Dial("udp", googleDNSResolverAddr)
			if err != nil {
				return nil, fmt.Errorf("unable to find default IP address to open socket: %w", err)
			}
			config.LocalAddrsV4 = []net.IP{conn.LocalAddr().(*net.UDPAddr).IP}
			// cleanup socket
			if err = conn.Close(); err != nil {
				log.Error("unable to close test connection to Google public DNS: ", err)
			}
		}
		if config.IPVersionMode != zdns.IPv4Only {
			conn, err := net.Dial("udp", googleDNSResolverAddrV6)
			if err != nil {
				return nil, fmt.Errorf("unable to find default IP address to open socket: %w", err)
			}
			config.LocalAddrsV6 = []net.IP{conn.LocalAddr().(*net.UDPAddr).IP}
			// cleanup socket
			if err = conn.Close(); err != nil {
				log.Error("unable to close test connection to Google public IPv6 DNS: ", err)
			}
		}
	}
	return config, nil
}

func Run(gc CLIConf, flags *pflag.FlagSet, args []string) {
	// User can provide both a module and a list of domains to query as inputs, similar to dig
	module, domains, err := parseArgs(args, gc.ModuleString)
	if err != nil {
		log.Fatal("could not parse arguments: ", err)
	}
	if len(gc.Module) == 0 && len(module) == 0 {
		// no module specified by either user or command, we cannot continue
		log.Fatal("No valid DNS lookup module specified. Please provide a module to run.")
	} else if len(gc.Module) == 0 {
		// Some commands set gc.Module, but most don't. If it's not set, set with module from parsing args
		gc.Module = strings.ToUpper(module)
	}

	gc = *populateCLIConfig(&gc, domains)
	resolverConfig := populateResolverConfig(&gc)
	// Log any information about the resolver configuration, according to log level
	resolverConfig.PrintInfo()
	err = resolverConfig.Validate()
	if err != nil {
		log.Fatalf("resolver config did not pass validation: %v", err)
	}
	lookupModule, err := GetLookupModule(gc.Module)
	if err != nil {
		log.Fatalf("could not get lookup module %s: %v", gc.Module, err)
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
				log.Fatalf("unable to open metadata file: %v", err)
			}
			defer func(f *os.File) {
				err = f.Close()
				if err != nil {
					log.Errorf("unable to close metadata file: %v", err)
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

// parseArgs parses and validates the command line arguments to ZDNS
// Valid usages of ZDNS are:
// Single arg as module/query type, input is taken from std. in: zdns <module>
// 1+ args as domains, module/query type must be passed in with --module: zdns --module=<module> <domain1> <domain2> ...
func parseArgs(args []string, moduleString string) (module string, domains []string, err error) {
	if len(args) == 0 && len(moduleString) == 0 {
		// some commands (nslookup) don't require a module, let the caller error check
		return "", nil, nil
	}
	if len(args) > 1 {
		// pre-alloc the domains slice, we know it will be at most the length of args - 1 for the mandatory module name
		domains = make([]string, 0, len(args)-1)
	}

	// --module takes precedence
	validLookupModulesMap := GetValidLookups()
	if len(moduleString) != 0 {
		module = strings.ToUpper(moduleString)
		_, ok := validLookupModulesMap[module]
		if !ok {
			return "", nil, fmt.Errorf("invalid lookup module specified - %s. ex: zdns A or zdns --module=A. See 'zdns avail-modules' for more", moduleString)
		}
		// check if --module is one of the special commands which should be called directly.
		if _, ok = cmds[module]; ok {
			return "", nil, fmt.Errorf("the module specified (--module=%s) has its own arguements and must be called with 'zdns %s'. See 'zdns %s --help' for more", module, module, module)
		}
		// alright, found the module, all args are domains
		domains = append(domains, args...)
		return module, domains, nil
	}

	// no --module, so we must have a module name as the first arg
	if len(args) > 1 {
		return "", nil, errors.New("invalid args. Valid usages are 1) zdns <module> (where domains come from std. in) or 2) zdns --module=<module> <domain1> <domain2> ...")
	}

	// only one arg, must be a module name
	module = strings.ToUpper(args[0])
	if _, ok := validLookupModulesMap[module]; !ok {
		return "", nil, fmt.Errorf("invalid lookup module specified - %s. ex: zdns A or zdns --module=A. See 'zdns avail-modules' for more", args[0])
	}
	return module, nil, nil
}
