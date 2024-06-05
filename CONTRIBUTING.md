# Contributing to ZDNS

We welcome any contributions to ZDNS. Please feel free to open an issue or a pull request, and we will review it as soon as possible.

## Development Pre-requisites
 - Python3 
 - Go v1.20 or later
 - make
 - [golangci-lint](https://golangci-lint.run/welcome/install/#local-installation)
 - [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports)

## PR Guidelines
Please ensure:
1. The PR is up-to-date with the latest changes in the `main` branch.
1. The PR passes all the CI checks. See [Local CI](#local-ci) for more information.
1. The PR has a clear description of the changes made.
1. PR's should be as small as possible. If you are making a large change, please consider breaking it down into smaller PR's.

## Local CI

To aid in reducing the testing cycle time, we have a number of make targets to enable running these checks locally. These targets include:
- `make ci`
  - runs all the below make targets
  - Keep in mind that `integration-tests` can take a minute or 2 to run. Please consider running the other targets individually if you are working on a specific area.
- `make test`
  - runs the unit tests
- `make integration-tests` 
  - runs the integration tests
- `make lint` 
  - runs the linters
- `make license-check` 
  - checks the license compliance