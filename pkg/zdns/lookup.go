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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/liip/sheriff"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/internal/util"
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
