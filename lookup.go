package zdns

import (
	"bufio"
	_ "io"
	"log"
	"os"
	"strings"
)

func makeName(name string, prefix string) string {

	if prefix == "" {
		return name
	} else {
		return strings.Join([]string{prefix, name}, "")
	}

}

func doLookup(f LookupFactory, gc GlobalConf, input <-chan string, output chan<- string) error {

	for rawName := range input {
		lookupName := makeName(rawName, gc.NamePrefix)
		l, err := f.MakeLookup()
		if err != nil {

		}
		res, err := l.DoLookup(lookupName)
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
