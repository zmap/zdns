all: zdns

zdns:
	go build -o zdns-cli

clean:
	rm -f zdns

install: zdns
	go install

.PHONY: zdns clean
