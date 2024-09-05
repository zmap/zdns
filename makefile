all: zdns

zdns:
	go build -o zdns

clean:
	rm -f zdns

install: zdns
	go install

test: zdns
	go test -v ./...
	pip3 install -r testing/requirements.txt
	pytest -n 4 testing/integration_tests.py

integration-tests: zdns
	pip3 install -r testing/requirements.txt
	pytest -n auto testing/integration_tests.py
	python3 testing/large_scan_integration/large_scan_integration_tests.py

# Not all hosts support this, so this will be a custom make target
ipv6-tests: zdns
	pip3 install -r testing/requirements.txt
	python3 testing/ipv6_tests.py

lint:
	goimports -w -local "github.com/zmap/zdns" ./
	gofmt -s -w ./
	golangci-lint run

license-check:
	./.github/workflows/check_license.sh

benchmark: zdns
	cd ./benchmark && go run main.go stats.go

ci: zdns lint test integration-tests license-check

.PHONY: zdns clean test integration-tests lint ci license-check benchmark

