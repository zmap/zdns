all: zdns/zdns

zdns/zdns:
	cd zdns && go build

clean:
	rm -f zdns/zdns

.PHONY: zdns/zdns clean

