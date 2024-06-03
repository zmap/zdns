all: zdns

zdns:
	go build -o zdns

clean:
	rm -f zdns

install: zdns
	go install

.PHONY: zdns clean
