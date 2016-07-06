package zdns

import (
	"bufio"
	"encoding/json"
	_ "io"
	"log"
	"os"
	"strconv"
	"strings"
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

func doLookup(f LookupFactory, gc GlobalConf, input <-chan string, output chan<- string) error {

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
	}
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
		f, err := os.Open(path)
		if err != nil {
			log.Fatal("unable to open output file:", err.Error())
		}
		defer f.Close()
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		in <- s.Text()
	}
	if err := s.Err(); err != nil {
		log.Fatal("input unable to read file", err)
	}
	return nil
}

func DoLookups(f *LookupFactory, c *GlobalConf) error {

	inChan := make(chan string)
	outChan := make(chan string)

	go doOutput(outChan, c.OutputFilePath)
	go doInput(inChan, c.InputFilePath)
	return nil

}
