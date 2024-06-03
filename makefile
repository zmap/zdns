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
	python3 testing/integration_tests.py
	python3 testing/large_scan_integration/large_scan_integration_tests.py

lint:
	goimports -d ./
	golangci-lint run

license-check:
	./.github/workflows/check_license.sh

ci: zdns lint test integration-tests license-check

.PHONY: zdns clean test integration-tests lint ci license-check

