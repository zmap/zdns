/*
 * ZDNS Copyright 2016 Regents of the University of Michigan
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
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type routineMetadata struct {
	Names  int
	Status map[Status]int
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

func makeName(name string, prefix string) (string, bool) {
	if prefix == "" {
		return name, false
	} else {
		return strings.Join([]string{prefix, name}, ""), true
	}
}

func doLookup(g *GlobalLookupFactory, gc *GlobalConf, input <-chan interface{}, output chan<- string, metaChan chan<- routineMetadata, wg *sync.WaitGroup, threadID int) error {
	f, err := (*g).MakeRoutineFactory(threadID)
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
		if (*g).ZonefileInput() {
			length := len(genericInput.(*dns.Token).RR.Header().Name)
			if length == 0 {
				continue
			}
			res.Name = genericInput.(*dns.Token).RR.Header().Name[0 : length-1]
			res.Class = dns.Class(gc.Class).String()
			switch typ := genericInput.(*dns.Token).RR.(type) {
			case *dns.NS:
				ns := strings.ToLower(typ.Ns)
				res.Nameserver = ns[:len(ns)-1]
			}
			innerRes, status, err = l.DoZonefileLookup(genericInput.(*dns.Token))
		} else {
			line := genericInput.(string)
			var changed bool
			var rawName string
			var rank int
			if gc.AlexaFormat == true {
				rawName, rank = parseAlexa(line)
				res.AlexaRank = rank
			} else {
				rawName = line
			}
			lookupName, changed := makeName(rawName, gc.NamePrefix)
			if changed {
				res.AlteredName = lookupName
			}
			res.Name = rawName
			res.Class = dns.Class(gc.Class).String()
			innerRes, trace, status, err = l.DoLookup(lookupName)
		}
		res.Timestamp = time.Now().Format(gc.TimeFormat)
		if status != STATUS_NO_OUTPUT {
			res.Status = string(status)
			res.Data = innerRes
			res.Trace = trace
			if err != nil {
				res.Error = err.Error()
			}
			jsonRes, err := json.Marshal(res)
			if err != nil {
				log.Fatal("Unable to marshal JSON result", err)
			}
			output <- string(jsonRes)
		}
		metadata.Names++
		metadata.Status[status]++
	}
	metaChan <- metadata
	(*wg).Done()
	return nil
}

// write results from lookup to output file
func doOutput(out <-chan string, path string, wg *sync.WaitGroup) error {
	var f *os.File
	if path == "" || path == "-" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatal("unable to open output file:", err.Error())
		}
		defer f.Close()
	}
	for n := range out {
		f.WriteString(n + "\n")
	}
	(*wg).Done()
	return nil
}

// read input file and put results into channel
func doInput(in chan<- interface{}, path string, wg *sync.WaitGroup, zonefileInput bool, passedName string) error {

	defer func() {
		close(in)
		(*wg).Done()
	}()

	if len(passedName) > 0 {
		in <- passedName
		return nil
	}

	var f *os.File
	if path == "" || path == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(path)
		if err != nil {
			log.Fatal("unable to open input file:", err.Error())
		}
	}
	if zonefileInput {
		tokens := dns.ParseZone(f, ".", path)
		for t := range tokens {
			in <- t
		}
	} else {
		s := bufio.NewScanner(f)
		for s.Scan() {
			in <- s.Text()
		}
		if err := s.Err(); err != nil {
			log.Fatal("input unable to read file", err)
		}
	}

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

func DoLookups(g *GlobalLookupFactory, c *GlobalConf) error {
	// doInput: take lines from input -> inChan
	//	- closes channel when done processing
	// doOutput: take serialized JSON from outChan and write
	// DoLookup:
	//	- n threads that do processing from in and place results in out
	//	- process until inChan closes, then wg.done()
	// Once we processing threads have all finished, wait until the
	// output and metadata threads have completed
	inChan := make(chan interface{})
	outChan := make(chan string)
	metaChan := make(chan routineMetadata, c.Threads)
	var routineWG sync.WaitGroup
	go doOutput(outChan, c.OutputFilePath, &routineWG)
	go doInput(inChan, c.InputFilePath, &routineWG, (*g).ZonefileInput(), c.PassedName)
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
