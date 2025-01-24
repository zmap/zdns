# Releasing a New Version of ZDNS
We use [goreleaser](https://goreleaser.com) to release new versions of ZDNS. To release a new version, follow these steps:

0. Install `goreleaser`:
```shell
brew install goreleaser/tap/goreleaser
```
1. Build the binaries:
```shell
goreleaser build --clean
```
