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
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"

	"github.com/zmap/zdns/src/cli/iohandlers"
	blacklist "github.com/zmap/zdns/src/internal/safeblacklist"
	"github.com/zmap/zdns/src/internal/util"
	"github.com/zmap/zdns/src/zdns"
)

type routineMetadata struct {
	Names   int // number of domain names processed
	Lookups int // number of lookups performed
	Status  map[zdns.Status]int
}

type Metadata struct {
	Names       int            `json:"names"`
	Lookups     int            `json:"lookups"`
	Status      map[string]int `json:"statuses"`
	StartTime   string         `json:"start_time"`
	EndTime     string         `json:"end_time"`
	NameServers []string       `json:"name_servers"`
	Timeout     int            `json:"timeout"`
	Retries     int            `json:"retries"`
	Conf        *CLIConf       `json:"conf"`
	ZDNSVersion string         `json:"zdns_version"`
}

func populateCLIConfig(gc *CLIConf) *CLIConf {
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
	if gc.NameServerMode && gc.NameOverride == "" && gc.CLIModule != BINDVERSION {
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
	if len(GC.Domains) > 0 {
		// using domains from command line
		gc.InputHandler = iohandlers.NewStringSliceInputHandler(GC.Domains)
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
	config.DNSOverHTTPS = gc.DNSOverHTTPS
	config.DNSOverTLS = gc.DNSOverTLS

	config.Timeout = time.Second * time.Duration(gc.Timeout)
	config.IterativeTimeout = time.Second * time.Duration(gc.IterationTimeout)
	config.LookupAllNameServers = gc.LookupAllNameServers
	config.FollowCNAMEs = !gc.DisableFollowCNAMEs // ZFlags only allows default-false bool flags. We'll invert here.

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
	config.ShouldRecycleSockets = !gc.DisableRecycleSockets
	config.DNSSecEnabled = gc.Dnssec
	config.DNSConfigFilePath = gc.DNSConfigFilePath

	config.LogLevel = log.Level(gc.Verbosity)

	if gc.BlacklistFilePath != "" {
		config.Blacklist = blacklist.New()
		if err := config.Blacklist.ParseFromFile(gc.BlacklistFilePath); err != nil {
			log.Fatal("unable to parse blacklist file: ", err)
		}
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
	config, err := populateIPTransportMode(gc, config)
	if err != nil {
		log.Fatal("could not populate IP transport mode: ", err)
	}
	// This must occur after setting IPTransportMode, so that ZDNS knows whether to use IPv4 or IPv6 nameservers
	config, err = populateNameServers(gc, config)
	if err != nil {
		log.Fatal("could not populate name servers: ", err)
	}
	if config.IPVersionMode == zdns.IPv4Only {
		// Drop any IPv6 nameservers
		config.ExternalNameServersV6 = []zdns.NameServer{}
		config.RootNameServersV6 = []zdns.NameServer{}
	}
	if config.IPVersionMode == zdns.IPv6Only {
		// Drop any IPv4 nameservers
		config.ExternalNameServersV4 = []zdns.NameServer{}
		config.RootNameServersV4 = []zdns.NameServer{}
	}
	noV4NameServers := len(config.ExternalNameServersV4) == 0 && len(config.RootNameServersV4) == 0
	if gc.IPv4TransportOnly && noV4NameServers {
		log.Fatal("cannot use --4 since no IPv4 nameservers found, ensure you have IPv4 connectivity and provide --name-servers")
	}
	noV6NameServers := len(config.ExternalNameServersV6) == 0 && len(config.RootNameServersV6) == 0
	if gc.IPv6TransportOnly && noV6NameServers {
		log.Fatal("cannot use --6 since no IPv6 nameservers found, ensure you have IPv6 connectivity and provide --name-servers")
	}

	config, err = populateLocalAddresses(gc, config)
	if err != nil {
		log.Fatal("could not populate local addresses: ", err)
	}
	return config
}

// populateIPTransportMode populates the IPTransportMode field of the ResolverConfig
// If user sets --4 (IPv4 Only) or --6 (IPv6 Only), we'll set the IPVersionMode to IPv4Only or IPv6Only, respectively.
// If user does not set --4 or --6, we'll determine the IPVersionMode based on:
//  1. the provided name-servers (if any)
//  2. the OS' default resolvers (if no name-servers provided)
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
	// User did not specify IPv4 or IPv6 only transport, so we need to determine the IPVersionMode based on the nameservers
	var nses []zdns.NameServer
	var err error
	var ipv4NSStrings, ipv6NSStrings []string
	var nameServersSupportIPv4, nameServersSupportIPv6 bool
	ipOnlyNSes := removeDomainsFromNameServersString(gc.NameServersString)
	// User can provide name servers as either IPs, IP+Port, or domain name
	// For the purposes of determining what IP mode the user's host supports, we'll only consider IPs or IP+Port
	// Domains could have either A or AAAA and that tells us nothing about the host's IPv4/6 capabilities
	if gc.NameServersString != "" && len(ipOnlyNSes) > 0 {
		// User provided name servers, so we can determine the IPVersionMode based on the provided name servers
		nses, err = convertNameServerStringSliceToNameServers(ipOnlyNSes, zdns.IPv4OrIPv6, config.DNSOverTLS, config.DNSOverHTTPS)
		if err != nil {
			return nil, fmt.Errorf("could not parse name servers from --name-server: %v", err)
		}
		for _, ns := range nses {
			if ns.IP.To4() != nil {
				nameServersSupportIPv4 = true
			} else if util.IsIPv6(&ns.IP) {
				nameServersSupportIPv6 = true
			} else {
				log.Fatal("invalid name server: ", ns.String())
			}
		}
		if !nameServersSupportIPv4 && !nameServersSupportIPv6 {
			return nil, errors.New("no nameservers found. Please specify desired nameservers with --name-servers")
		}
		config.IPVersionMode = zdns.GetIPVersionMode(nameServersSupportIPv4, nameServersSupportIPv6)
		return config, nil
	}
	// check OS' default resolver(s) to determine if we support IPv4 or IPv6
	ipv4NSStrings, ipv6NSStrings, err = zdns.GetDNSServers(config.DNSConfigFilePath)
	if err != nil {
		log.Fatal("unable to parse resolvers file, please use '--name-servers': ", err)
	}
	if len(ipv4NSStrings) == 0 && len(ipv6NSStrings) == 0 {
		return nil, errors.New("no nameservers found with OS defaults. Please specify desired nameservers with --name-servers")
	}
	if len(ipv4NSStrings) > 0 {
		nameServersSupportIPv4 = true
	}
	if len(ipv6NSStrings) > 0 {
		nameServersSupportIPv6 = true
	}
	config.IPVersionMode = zdns.GetIPVersionMode(nameServersSupportIPv4, nameServersSupportIPv6)
	return config, nil
}

func populateNameServers(gc *CLIConf, config *zdns.ResolverConfig) (*zdns.ResolverConfig, error) {
	// Nameservers are populated in this order:
	// 1. If user provided nameservers, use those
	// 2. (External Only and NOT --name-server-mode) If we can get the OS' default recursive resolver nameservers, use those
	// 3. Use ZDNS defaults

	// Additionally, both Root and External nameservers must be populated, since the Resolver doesn't know we'll only
	// be performing either iterative or recursive lookups, not both.

	// IPv4 Name Servers/Local Address only needs to be populated if we're doing IPv4 lookups, same for IPv6
	if len(gc.NameServers) != 0 {
		// User provided name servers, use them.
		var err error
		config, err = useNameServerStringToPopulateNameServers(gc.NameServers, config)
		if err != nil {
			return nil, fmt.Errorf("could not populate name servers: %v", err)
		}
		if config.DNSOverHTTPS {
			// double-check all external nameservers have domains, necessary for DoH
			for _, ns := range util.Concat(config.ExternalNameServersV4, config.ExternalNameServersV6) {
				if len(ns.DomainName) == 0 {
					log.Fatal("DoH requires domain names for all name servers, ex. --name-servers=cloudflare-dns.com,dns.google")
				}
			}
		}
		return config, nil
	}
	// User did not provide nameservers
	if gc.DNSOverTLS {
		config.RootNameServersV4 = zdns.DefaultExternalDoTResolversV4
		config.ExternalNameServersV4 = zdns.DefaultExternalDoTResolversV4
		config.RootNameServersV6 = zdns.DefaultExternalDoTResolversV6
		config.ExternalNameServersV6 = zdns.DefaultExternalDoTResolversV6
		return config, nil
	}
	if gc.DNSOverHTTPS {
		defaultDoHNameServers := []string{zdns.CloudflareDoHDomainName, zdns.GoogleDoHDomainName}
		return useNameServerStringToPopulateNameServers(defaultDoHNameServers, config)
	}
	if !gc.IterativeResolution && !gc.NameServerMode {
		// Try to get the OS' default recursive resolver nameservers
		var v4NameServers, v6NameServers []zdns.NameServer
		v4NameServerStrings, v6NameServersStrings, err := zdns.GetDNSServers(config.DNSConfigFilePath)
		if err != nil {
			v4NameServers, v6NameServers = zdns.DefaultExternalResolversV4, zdns.DefaultExternalResolversV6
			log.Warn("Unable to parse resolvers file. Using ZDNS defaults")
		} else {
			// convert string slices to NameServers
			v4NameServers, err = convertNameServerStringSliceToNameServers(v4NameServerStrings, config.IPVersionMode, config.DNSOverTLS, config.DNSOverHTTPS)
			if err != nil {
				return nil, fmt.Errorf("could not convert IPv4 nameservers %s to NameServers: %v", strings.Join(v4NameServerStrings, ", "), err)
			}
			v6NameServers, err = convertNameServerStringSliceToNameServers(v6NameServersStrings, config.IPVersionMode, config.DNSOverTLS, config.DNSOverHTTPS)
			if err != nil {
				return nil, fmt.Errorf("could not convert IPv6 nameservers %s to NameServers: %v", strings.Join(v6NameServersStrings, ", "), err)
			}
		}
		// The resolver will ignore IPv6 nameservers if we're doing IPv4 only lookups, and vice versa so this is fine
		config.ExternalNameServersV4 = v4NameServers
		config.RootNameServersV4 = v4NameServers
		config.ExternalNameServersV6 = v6NameServers
		config.RootNameServersV6 = v6NameServers

		return config, nil
	}
	// User did not provide nameservers and we're doing iterative resolution, use ZDNS defaults
	config.ExternalNameServersV4 = zdns.RootServersV4[:]
	config.RootNameServersV4 = zdns.RootServersV4[:]
	config.ExternalNameServersV6 = zdns.RootServersV6[:]
	config.RootNameServersV6 = zdns.RootServersV6[:]
	return config, nil
}

func useNameServerStringToPopulateNameServers(nameServers []string, config *zdns.ResolverConfig) (*zdns.ResolverConfig, error) {
	var v4NameServers, v6NameServers []zdns.NameServer
	nses, err := convertNameServerStringSliceToNameServers(nameServers, config.IPVersionMode, config.DNSOverTLS, config.DNSOverHTTPS)
	if err != nil {
		return nil, fmt.Errorf("could not parse name server: %v. Correct IPv4 format: 1.1.1.1:53 or IPv6 format: [::1]:53\"", err)
	}
	for _, ns := range nses {
		if ns.IP.To4() != nil {
			v4NameServers = append(v4NameServers, ns)
		} else if util.IsIPv6(&ns.IP) {
			v6NameServers = append(v6NameServers, ns)
		} else {
			log.Fatal("Invalid name server: ", ns.String())
		}
	}
	// The resolver will ignore IPv6 nameservers if we're doing IPv4 only lookups, and vice versa so this is fine
	config.ExternalNameServersV4 = v4NameServers
	config.RootNameServersV4 = v4NameServers
	config.ExternalNameServersV6 = v6NameServers
	config.RootNameServersV6 = v6NameServers
	return config, nil
}

func populateLocalAddresses(gc *CLIConf, config *zdns.ResolverConfig) (*zdns.ResolverConfig, error) {
	// Local Addresses are populated in this order:
	// 1. If user provided local addresses, use those
	// 2. If user does not provide local addresses, one will be used on-demand by Resolver. See resolver.go:getConnectionInfo for more info

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
	}
	return config, nil
}

// WorkerPools are a collection of channels that workers can read from
// 1+ threads will read from a pooled channel, and the inputDeMultiplexer will send input to the appropriate channel
type WorkerPools struct {
	WorkerPools []chan *InputLineWithNameServer
}

func NewWorkerPools(numPools int) *WorkerPools {
	workerPools := make([]chan *InputLineWithNameServer, numPools)
	for i := 0; i < numPools; i++ {
		workerPools[i] = make(chan *InputLineWithNameServer)
	}
	return &WorkerPools{WorkerPools: workerPools}
}

// InputLineWithNameServer is a struct that contains a line of input and the name server to use for the lookup
// This name server is a "suggestion", --iterative lookups will ignore it as well as AXFR lookups
// The goal is to attempt to send all queries for a single name server to the same worker pool
type InputLineWithNameServer struct {
	Line       string
	NameServer *zdns.NameServer
}

// inputDeMultiplxer is a single goroutine that reads from the input channel and sends the input to the appropriate worker pool channel
// The goal is that a query for a single name server will consistently go to the same worker pool which 1+ threads will read from
// This is especially useful for TLS/TCP/HTTPS based lookups where repeating the initial handshakes would be wasteful
func inputDeMultiplexer(nameServers []zdns.NameServer, inChan <-chan string, workerPools *WorkerPools, wg *sync.WaitGroup) error {
	wg.Add(1)
	defer wg.Done()
	// defer closing the worker pool chans
	defer func() {
		for _, pool := range workerPools.WorkerPools {
			close(pool)
		}
	}()
	for line := range inChan {
		nsIndex := rand.Intn(len(nameServers))
		randomNS := nameServers[nsIndex]
		chanID := nsIndex % len(workerPools.WorkerPools)
		workerPools.WorkerPools[chanID] <- &InputLineWithNameServer{Line: line, NameServer: &randomNS}
	}
	return nil
}

func Run(gc CLIConf) {
	gc = *populateCLIConfig(&gc)
	resolverConfig := populateResolverConfig(&gc)
	// Log any information about the resolver configuration, according to log level
	resolverConfig.PrintInfo()
	err := resolverConfig.Validate()
	if err != nil {
		log.Fatalf("resolver config did not pass validation: %v", err)
	}
	for _, module := range gc.ActiveModules {
		// init all modules
		err = module.CLIInit(&gc, resolverConfig)
		if err != nil {
			log.Fatalf("could not initialize lookup module (type: %s): %v", gc.CLIModule, err)
		}
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

	nameServers := util.Concat(resolverConfig.ExternalNameServersV4, resolverConfig.ExternalNameServersV6, resolverConfig.RootNameServersV4, resolverConfig.RootNameServersV6)
	// de-dupe
	nsLookupMap := make(map[uint32]struct{})
	uniqNameServers := make([]zdns.NameServer, 0, len(nameServers))
	var hash uint32
	for _, ns := range nameServers {
		hash, err = ns.Hash()
		if err != nil {
			log.Fatalf("could not hash name server %s: %v", ns.String(), err)
		}
		if _, ok := nsLookupMap[hash]; !ok {
			nsLookupMap[hash] = struct{}{}
			uniqNameServers = append(uniqNameServers, ns)
		}
	}
	// DoH lookups only depend on domain name, remove nameservers with duplicate domains
	// We don't want the deMultiplexer to send the same domain (with different IPs) to different worker pools
	if gc.DNSOverHTTPS {
		nsDomainLookupMap := make(map[string]struct{})
		uniqueDomainNSes := make([]zdns.NameServer, 0, len(uniqNameServers))
		for _, ns := range uniqNameServers {
			if _, ok := nsDomainLookupMap[ns.DomainName]; !ok {
				nsDomainLookupMap[ns.DomainName] = struct{}{}
				uniqueDomainNSes = append(uniqueDomainNSes, ns)
			}
		}
		uniqNameServers = uniqueDomainNSes
	}
	numberOfWorkerPools := len(uniqNameServers)
	if gc.Threads < numberOfWorkerPools {
		// multiple threads can share a channel, but we can't have more channels than threads
		numberOfWorkerPools = gc.Threads
	}
	workerPools := NewWorkerPools(numberOfWorkerPools)

	// Use handlers to populate the input and output/results channel
	go func() {
		inErr := inHandler.FeedChannel(inChan, &routineWG)
		if inErr != nil {
			log.Fatal(fmt.Sprintf("could not feed input channel: %v", inErr))
		}
	}()
	go func() {
		plexErr := inputDeMultiplexer(uniqNameServers, inChan, workerPools, &routineWG)
		if plexErr != nil {
			log.Fatal(fmt.Sprintf("could not de-multiplex input channel: %v", plexErr))
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
		// assign each worker to a worker pool, we'll loop around if we have more workers than pools
		channelID := i % len(workerPools.WorkerPools)
		go func(threadID int) {
			initWorkerErr := doLookupWorker(&gc, resolverConfig, workerPools.WorkerPools[channelID], outChan, metaChan, &lookupWG)
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
func doLookupWorker(gc *CLIConf, rc *zdns.ResolverConfig, input <-chan *InputLineWithNameServer, output chan<- string, metaChan chan<- routineMetadata, wg *sync.WaitGroup) error {
	defer wg.Done()
	resolver, err := zdns.InitResolver(rc)
	if err != nil {
		return fmt.Errorf("could not init resolver: %w", err)
	}
	var metadata routineMetadata
	metadata.Status = make(map[zdns.Status]int)
	for line := range input {
		// we'll process each module sequentially, parallelism is per-domain
		res, rawName, nameServer := parseInputLine(gc, rc, line)
		res.Name = rawName
		// handle per-module lookups
		for moduleName, module := range gc.ActiveModules {
			if moduleName == "AXFR" {
				// special case, AXFR has its own nameserver handling. We'll only take nameservers if the user provides it
				// not the "suggestion" from the de-multiplexor
				if nameServer.String() == line.NameServer.String() {
					// this name server is the suggested one from the de-multiplexor, we'll remove it
					nameServer = nil
				}
			}
			var innerRes interface{}
			var trace zdns.Trace
			var status zdns.Status
			var err error
			var changed bool
			var lookupName string
			lookupName, changed = makeName(rawName, gc.NamePrefix, gc.NameOverride)
			if changed {
				res.AlteredName = lookupName
			}
			res.Class = dns.Class(gc.Class).String()

			startTime := time.Now()
			innerRes, trace, status, err = module.Lookup(resolver, lookupName, nameServer)

			lookupRes := zdns.SingleModuleResult{
				Timestamp: time.Now().Format(gc.TimeFormat),
				Duration:  time.Since(startTime).Seconds(),
			}
			if status != zdns.StatusNoOutput {
				lookupRes.Status = string(status)
				lookupRes.Data = innerRes
				lookupRes.Trace = trace
				if err != nil {
					lookupRes.Error = err.Error()
				}
				res.Results[moduleName] = lookupRes
			}
			metadata.Status[status]++
			metadata.Lookups++
		}
		if len(res.Results) > 0 {
			v, _ := version.NewVersion("0.0.0")
			o := &sheriff.Options{
				Groups:          gc.OutputGroups,
				ApiVersion:      v,
				IncludeEmptyTag: true,
			}
			data, err := sheriff.Marshal(o, res)
			if err != nil {
				log.Fatalf("unable to marshal result to JSON: %v", err)
			}
			cleansedData := replaceIntSliceInterface(data)
			jsonRes, err := json.Marshal(cleansedData)
			if err != nil {
				log.Fatalf("unable to marshal JSON result: %v", err)
			}
			output <- string(jsonRes)
		}
		metadata.Names++
	}
	// close the resolver, freeing up resources
	resolver.Close()
	metaChan <- metadata
	return nil
}

func parseInputLine(gc *CLIConf, rc *zdns.ResolverConfig, line *InputLineWithNameServer) (*zdns.Result, string, *zdns.NameServer) {
	res := zdns.Result{Results: make(map[string]zdns.SingleModuleResult, len(gc.ActiveModules))}
	// get the fields that won't change for each lookup module
	rawName := ""
	// this is the name server "suggested" by the de-multiplexor. The goal is that if
	// 1) the user doesn't provide a nameserver
	// 2) we're in external lookup mode
	// then we'll use the suggestion. This is to avoid the overhead of re-handshaking for each lookup
	// it's overwritten if the user provides a nameserver as part of the input line below
	nameServer := line.NameServer
	nameServerString := ""
	var rank int
	var entryMetadata string
	if gc.AlexaFormat {
		rawName, rank = parseAlexa(line.Line)
		res.AlexaRank = rank
	} else if gc.MetadataFormat {
		rawName, entryMetadata = parseMetadataInputLine(line.Line)
		res.Metadata = entryMetadata
	} else if gc.NameServerMode {
		nameServers, err := convertNameServerStringToNameServer(line.Line, rc.IPVersionMode, rc.DNSOverTLS, rc.DNSOverHTTPS)
		if err != nil {
			log.Fatal("unable to parse name server: ", line.Line)
		}
		if len(nameServers) == 0 {
			log.Fatal("no name servers found in line: ", line.Line)
		}
		// if user provides a domain name for the name server (one.one.one.one) we'll pick one of the IPs at random
		nameServer = &nameServers[rand.Intn(len(nameServers))]
	} else {
		rawName, nameServerString = parseNormalInputLine(line.Line)
		if len(nameServerString) != 0 {
			nameServers, err := convertNameServerStringToNameServer(nameServerString, rc.IPVersionMode, rc.DNSOverTLS, rc.DNSOverHTTPS)
			if err != nil {
				log.Fatal("unable to parse name server: ", line.Line)
			}
			if len(nameServers) == 0 {
				log.Fatal("no name servers found in line: ", line.Line)
			}
			// if user provides a domain name for the name server (one.one.one.one) we'll pick one of the IPs at random
			nameServer = &nameServers[rand.Intn(len(nameServers))]
		}
	}
	return &res, rawName, nameServer
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
		return s[0], s[1]
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
	meta.ZDNSVersion = zdns.ZDNSVersion
	meta.Status = make(map[string]int)
	for m := range c {
		meta.Names += m.Names
		meta.Lookups += m.Lookups
		for k, v := range m.Status {
			meta.Status[string(k)] += v
		}
	}
	return meta
}

func convertNameServerStringSliceToNameServers(nameServerStrings []string, mode zdns.IPVersionMode, usingDoT, usingDoH bool) ([]zdns.NameServer, error) {
	nameServers := make([]zdns.NameServer, 0, len(nameServerStrings))
	for _, ns := range nameServerStrings {
		parsedNSes, err := convertNameServerStringToNameServer(ns, mode, usingDoT, usingDoH)
		if err != nil {
			return nil, fmt.Errorf("could not parse name server %s: %v", ns, err)
		}
		nameServers = append(nameServers, parsedNSes...)
	}
	return nameServers, nil
}

func convertNameServerStringToNameServer(inaddr string, mode zdns.IPVersionMode, usingDoT, usingDoH bool) ([]zdns.NameServer, error) {
	host, port, err := util.SplitHostPort(inaddr)
	if err == nil && host != nil {
		return []zdns.NameServer{{IP: host, Port: uint16(port)}}, nil
	}

	// may be a port-less IP
	ip := net.ParseIP(inaddr)
	if ip != nil {
		ns := zdns.NameServer{IP: ip}
		ns.PopulateDefaultPort(usingDoT, usingDoH)
		return []zdns.NameServer{ns}, nil
	}

	// may be the domain name of a name server (one.one.one.one)
	// we'll add these prefixes back on later, stripping so we can detect ports
	inaddr = strings.TrimPrefix(inaddr, "https://")
	inaddr = strings.TrimPrefix(inaddr, "http://")
	domainAndPort := strings.Split(inaddr, ":")
	port = 0
	if len(domainAndPort) == 2 {
		// domain name with port (one.one.one.one:53)
		port, err = strconv.Atoi(domainAndPort[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", inaddr)
		}
	}
	ips, err := net.LookupIP(domainAndPort[0])
	if err != nil {
		return nil, fmt.Errorf("could not resolve name server: %s", inaddr)
	}
	nses := make([]zdns.NameServer, 0, len(ips))
	for _, resolvedIP := range ips {
		isIPv6AndCanUseIPv6 := util.IsIPv6(&resolvedIP) && mode != zdns.IPv4Only
		isIPv4AndCanUseIPv4 := resolvedIP.To4() != nil && mode != zdns.IPv6Only
		if isIPv4AndCanUseIPv4 || isIPv6AndCanUseIPv6 {
			ns := zdns.NameServer{IP: resolvedIP, Port: uint16(port), DomainName: domainAndPort[0]}
			ns.PopulateDefaultPort(usingDoT, usingDoH)
			nses = append(nses, ns)
		}
	}
	return nses, nil
}

func removeDomainsFromNameServersString(nameServersString string) []string {
	// User can provide name servers as either IPs, IP+Port, or domain name
	// For the purposes of determining what IP mode the user's host supports, we'll only consider IPs or IP+Port
	// Domains could have either A or AAAA and that tells us nothing about the host's IPv4/6 capabilities
	// We'll remove any domains from the name servers string
	nses := strings.Split(nameServersString, ",")
	ipOnlyNSes := make([]string, 0, len(nses))
	for _, ns := range nses {
		if net.ParseIP(ns) != nil {
			ipOnlyNSes = append(ipOnlyNSes, ns)
		} else if ip, _, err := net.SplitHostPort(ns); err == nil && net.ParseIP(ip) != nil {
			ipOnlyNSes = append(ipOnlyNSes, ns)
		}
		// else this must be a domain name
	}
	return ipOnlyNSes
}
