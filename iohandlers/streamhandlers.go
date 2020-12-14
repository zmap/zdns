package iohandlers

import (
	"bufio"
	"io"
	"sync"

	log "github.com/sirupsen/logrus"
)

type StreamInputHandler struct {
	reader io.Reader
}

func NewStreamInputHandler(r io.Reader) *StreamInputHandler {
	return &StreamInputHandler{
		reader: r,
	}
}

func (h *StreamInputHandler) FeedChannel(in chan<- interface{}, wg *sync.WaitGroup) error {
	defer close(in)
	defer (*wg).Done()

	s := bufio.NewScanner(h.reader)
	for s.Scan() {
		in <- s.Text()
	}
	if err := s.Err(); err != nil {
		log.Fatalf("unable to read input stream: %v", err)
	}
	return nil
}

type StreamOutputHandler struct {
	writer io.Writer
}

func NewStreamOutputHandler(w io.Writer) *StreamOutputHandler {
	return &StreamOutputHandler{
		writer: w,
	}
}

func (h *StreamOutputHandler) WriteResults(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()
	for n := range results {
		io.WriteString(h.writer, n+"\n")
	}
	return nil
}
