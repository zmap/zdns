package mxlookup

import (
	"github.com/spf13/pflag"
	"github.com/zmap/zdns/pkg/cmd"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/cachehash"
	"github.com/zmap/zdns/pkg/modules/alookup"
	"github.com/zmap/zdns/pkg/zdns"
)

type CachedAddresses struct {
	IPv4Addresses []string
	IPv6Addresses []string
}

func init() {
	mx := new(MXLookupModule)
	cmd.RegisterLookupModule("MXLOOKUP", mx)
}

type MXRecord struct {
	Name          string   `json:"name" groups:"short,normal,long,trace"`
	Type          string   `json:"type" groups:"short,normal,long,trace"`
	Class         string   `json:"class" groups:"normal,long,trace"`
	Preference    uint16   `json:"preference" groups:"short,normal,long,trace"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty" groups:"short,normal,long,trace"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty" groups:"short,normal,long,trace"`
	TTL           uint32   `json:"ttl" groups:"ttl,normal,long,trace"`
}

type MXResult struct {
	Servers []MXRecord `json:"exchanges" groups:"short,normal,long,trace"`
}

type MXLookupModule struct {
	IPv4Lookup  bool
	IPv6Lookup  bool
	MXCacheSize int
	CacheHash   *cachehash.CacheHash
	CHmu        sync.Mutex
}

// CLIInit initializes the MXLookupModule with the given parameters, used to call MXLookup from the command line
func (mx *MXLookupModule) CLIInit(gc *cmd.CLIConf, rc *zdns.ResolverConfig, f *pflag.FlagSet) {
	ipv4Lookup, err := f.GetBool("ipv4-lookup")
	if err != nil {
		panic(err)
	}
	ipv6Lookup, err := f.GetBool("ipv6-lookup")
	if err != nil {
		panic(err)
	}
	mxCacheSize, err := f.GetInt("mx-cache-size")
	if err != nil {
		panic(err)
	}
	if !ipv4Lookup && !ipv6Lookup {
		// need to use one of the two
		ipv4Lookup = true
	}
	mx.Init(ipv4Lookup, ipv6Lookup, mxCacheSize)
}

// Init initializes the MXLookupModule with the given parameters, used to call MXLookup programmatically
func (mx *MXLookupModule) Init(ipv4Lookup, ipv6Lookup bool, mxCacheSize int) {
	if !ipv4Lookup && !ipv6Lookup {
		log.Fatal("At least one of ipv4-lookup or ipv6-lookup must be true")
	}
	if mxCacheSize <= 0 {
		log.Fatal("mxCacheSize must be greater than 0, got ", mxCacheSize)
	}
	mx.IPv4Lookup = ipv4Lookup
	mx.IPv6Lookup = ipv6Lookup
	mx.MXCacheSize = mxCacheSize
	mx.CacheHash = new(cachehash.CacheHash)
	mx.CacheHash.Init(mxCacheSize)
}

func (mxLookup *MXLookupModule) lookupIPs(r *zdns.Resolver, name, nameServer string, ipMode zdns.IPVersionMode) (CachedAddresses, zdns.Trace) {
	if mxLookup == nil {
		log.Fatal("mxLookup is not initialized")
	}
	mxLookup.CHmu.Lock()
	// TODO this comment V is present in the original code and has been there since 2017 IIRC, so ask Zakir what to do
	// XXX this should be changed to a miekglookup
	res, found := mxLookup.CacheHash.Get(name)
	mxLookup.CHmu.Unlock()
	if found {
		return res.(CachedAddresses), zdns.Trace{}
	}
	retv := CachedAddresses{}
	result, trace, status, _ := alookup.DoTargetedLookup(r, name, nameServer, ipMode)
	if status == zdns.STATUS_NOERROR && result != nil {
		retv.IPv4Addresses = result.IPv4Addresses
		retv.IPv6Addresses = result.IPv6Addresses
	}
	mxLookup.CHmu.Lock()
	mxLookup.CacheHash.Add(name, retv)
	mxLookup.CHmu.Unlock()
	return retv, trace
}

func (mxLookup *MXLookupModule) Lookup(r *zdns.Resolver, lookupName, nameServer string) (interface{}, zdns.Trace, zdns.Status, error) {
	ipMode := zdns.GetIPVersionMode(mxLookup.IPv4Lookup, mxLookup.IPv6Lookup)
	retv := MXResult{Servers: []MXRecord{}}
	res, trace, status, err := r.ExternalLookup(&zdns.Question{Name: lookupName, Type: dns.TypeMX, Class: dns.ClassINET}, nameServer)
	if status != zdns.STATUS_NOERROR || err != nil {
		return nil, trace, status, err
	}

	for _, ans := range res.Answers {
		if mxAns, ok := ans.(zdns.PrefAnswer); ok {
			lookupName = strings.TrimSuffix(mxAns.Answer.Answer, ".")
			rec := MXRecord{TTL: mxAns.Ttl, Type: mxAns.Type, Class: mxAns.Class, Name: lookupName, Preference: mxAns.Preference}
			ips, secondTrace := mxLookup.lookupIPs(r, lookupName, nameServer, ipMode)
			rec.IPv4Addresses = ips.IPv4Addresses
			rec.IPv6Addresses = ips.IPv6Addresses
			retv.Servers = append(retv.Servers, rec)
			trace = append(trace, secondTrace...)
		}
	}
	return &retv, trace, zdns.STATUS_NOERROR, nil
}

// Help returns the module's help string
func (mxLookup *MXLookupModule) Help() string {
	return ""
}
