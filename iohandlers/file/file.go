package file

import (
	"bufio"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	dns "github.com/zmap/miekg-dns"
	"github.com/zmap/zdns"
)

type InputHandler struct {
	filepath string
}

func (h *InputHandler) Initialize(conf *zdns.GlobalConf) {
	h.filepath = conf.InputFilePath
}

func (h *InputHandler) FeedChannel(in chan<- interface{}, wg *sync.WaitGroup, zonefileInput bool) error {
	defer close(in)
	defer (*wg).Done()

	var f *os.File
	if h.filepath == "" || h.filepath == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(h.filepath)
		if err != nil {
			log.Fatal("unable to open input file:", err.Error())
		}
	}
	if zonefileInput {
		tokens := dns.ParseZone(f, ".", h.filepath)
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

type OutputHandler struct {
	filepath string
}

func (h *OutputHandler) Initialize(conf *zdns.GlobalConf) {
	h.filepath = conf.OutputFilePath
}

func (h *OutputHandler) WriteResults(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()

	var f *os.File
	if h.filepath == "" || h.filepath == "-" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(h.filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatal("unable to open output file:", err.Error())
		}
		defer f.Close()
	}
	for n := range results {
		f.WriteString(n + "\n")
	}
	return nil
}

// register handlers
func init() {
	in := new(InputHandler)
	zdns.RegisterInputHandler("file", in)

	out := new(OutputHandler)
	zdns.RegisterOutputHandler("file", out)
}
