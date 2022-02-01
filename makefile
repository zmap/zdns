all: zdns

zdns:
	go build

clean:
	rm -f zdns

install: zdns
	go install

.PHONY: zdns clean

