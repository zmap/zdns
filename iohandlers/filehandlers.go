package iohandlers

import (
	"bufio"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

type FileInputHandler struct {
	filepath string
}

func NewFileInputHandler(filepath string) *FileInputHandler {
	return &FileInputHandler{
		filepath: filepath,
	}
}

func (h *FileInputHandler) FeedChannel(in chan<- interface{}, wg *sync.WaitGroup) error {
	defer close(in)
	defer (*wg).Done()

	var f *os.File
	if h.filepath == "" || h.filepath == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(h.filepath)
		if err != nil {
			log.Fatalf("unable to open input file: %v", err)
		}
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		in <- s.Text()
	}
	if err := s.Err(); err != nil {
		log.Fatalf("input unable to read file: %v", err)
	}
	return nil
}

type FileOutputHandler struct {
	filepath string
}

func NewFileOutputHandler(filepath string) *FileOutputHandler {
	return &FileOutputHandler{
		filepath: filepath,
	}
}

func (h *FileOutputHandler) WriteResults(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()

	var f *os.File
	if h.filepath == "" || h.filepath == "-" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(h.filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("unable to open output file: %v", err)
		}
		defer f.Close()
	}
	for n := range results {
		f.WriteString(n + "\n")
	}
	return nil
}
