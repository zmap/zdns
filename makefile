all: zdns/zdns

zdns/zdns:
	cd zdns && go build

clean:
	rm -f zdns/zdns

install: zdns/zdns
	cd zdns && go install

.PHONY: zdns/zdns clean

