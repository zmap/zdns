package iohandlers

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

type ArgsInputHandler struct {
	input []string
}

func NewArgsInputHandler(input []string) *ArgsInputHandler {
	return &ArgsInputHandler{
		input: input,
	}
}

func (h *ArgsInputHandler) FeedChannel(in chan<- interface{}, wg *sync.WaitGroup) error {
	defer close(in)
	defer (*wg).Done()

	if len(h.input) == 0 {
		log.Fatal("empty array of input args passed to argshandler")
	}

	for _, name := range h.input {
		in <- name
	}

	return nil
}
