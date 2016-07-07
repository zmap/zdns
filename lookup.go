package zdns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	_ "io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

func parseAlexa(line string) (string, int) {
	s := strings.SplitN(line, ",", 1)
	rank, err := strconv.Atoi(s[0])
	if err != nil {
		log.Fatal("Malformed Alexa Top Million file")
	}
	return s[1], rank
}

func makeName(name string, prefix string) (string, bool) {
	if prefix == "" {
		return name, false
	} else {
		return strings.Join([]string{prefix, name}, ""), true
	}
}

func doLookup(g *GlobalLookupFactory, gc *GlobalConf, input <-chan string, output chan<- string, wg *sync.WaitGroup) error {
	f, err := (*g).MakeRoutineFactory()
	if err != nil {
		log.Fatal("Unable to create new routine factory", err.Error())
	}
	for line := range input {
		var res Result
		var rawName string
		var rank int
		if gc.AlexaFormat == true {
			rawName, rank = parseAlexa(line)
			res.AlexaRank = rank
		} else {
			rawName = line
		}
		lookupName, changed := makeName(rawName, gc.NamePrefix)
		res.Domain = lookupName
		if changed {
			res.OriginalDomain = rawName
		}
		l, err := f.MakeLookup()
		if err != nil {
			log.Fatal("Unable to build lookup instance", err)
		}
		innerRes, status, err := l.DoLookup(lookupName)
		res.Status = string(status)
		res.Data = innerRes
		if err != nil {
			res.Error = err.Error()
		}
		jsonRes, err := json.Marshal(res)
		if err != nil {
			log.Fatal("Unable to marshal JSON result", err)
		}
		output <- string(jsonRes)
		fmt.Print(string(jsonRes))
	}
	(*wg).Done()
	return nil
}

// write results from lookup to output file
func doOutput(out <-chan string, path string) error {
	var f *os.File
	if path == "" || path == "-" {
		f = os.Stdout
	} else {
		f, err := os.Open(path)
		if err != nil {
			log.Fatal("unable to open output file:", err.Error())
		}
		defer f.Close()
	}
	for n := range out {
		f.WriteString(n)
		f.WriteString("\n")
	}
	return nil
}

// read input file and put results into channel
func doInput(in chan<- string, path string) error {
	var f *os.File
	if path == "" || path == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(path)
		if err != nil {
			log.Fatal("unable to open output file:", err.Error())
		}
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		in <- s.Text()
	}
	if err := s.Err(); err != nil {
		log.Fatal("input unable to read file", err)
	}
	close(in)
	return nil
}

func DoLookups(g *GlobalLookupFactory, c *GlobalConf) error {
	// doInput: take lines from input -> inChan
	//	- closes channel when done processing
	// doOutput: take serialized JSON from outChan and write
	// DoLookup:
	//	- n threads that do processing from in and place results in out
	//	- process until inChan closes, then wg.done()
	// Once we processing threads have all finished, wait until the
	// output and metadata threads have completed
	inChan := make(chan string)
	outChan := make(chan string)
	go doOutput(outChan, c.OutputFilePath)
	go doInput(inChan, c.InputFilePath)
	var wg sync.WaitGroup
	wg.Add(c.Threads)
	for i := 0; i < c.Threads; i++ {
		go doLookup(g, c, inChan, outChan, &wg)
	}
	wg.Wait()
	close(outChan)
	return nil
}

func GetDNSServers(path string) ([]string, error) {
	c, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return []string{}, err
	}
	var servers []string
	for _, s := range c.Servers {
		full := strings.Join([]string{s, c.Port}, ":")
		servers = append(servers, full)
	}
	return servers, nil
}
