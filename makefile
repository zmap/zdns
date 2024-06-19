all: zdns

zdns:
	go build -o zdns

clean:
	rm -f zdns

install: zdns
	go install

test: zdns
	go test -v ./...

integration-tests: zdns
	pip3 install -r testing/requirements.txt
	python3 testing/integration_tests.py
	python3 testing/large_scan_integration/large_scan_integration_tests.py

lint:
	goimports -w -local "github.com/zmap/zdns" ./
	gofmt -s -w ./
	golangci-lint run

license-check:
	./.github/workflows/check_license.sh

ci: zdns lint test integration-tests license-check

.PHONY: zdns clean test integration-tests lint ci license-check

