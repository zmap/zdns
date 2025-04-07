# Releasing a New Version of ZDNS

## Pre-Release Checklist
- [ ] Major Version Release Example: `v2.X.Y` -> `v3.0.0`
     - [ ] Bump the module name in `go.mod`
     - [ ] Update the import paths in all non-`src/zdns` packages to use the new module name.

Updating `go.mod` assuming releasing a new major version (v3):
```
    module github.com/zmap/zdns/v2 // Update v2 -> v3
```
Update import paths in all non-`src/zdns` packages to use the new module name:
```go
	"github.com/zmap/zdns/v2/src/zdns" // Update v2 -> v3
```
- [ ] All Releases
  - [ ] Ensure all dependencies are up to date `go get -u ./...`
  - [ ] Ensure that the ZDNS version [src/zdns/version.go](https://github.com/zmap/zdns/blob/main/src/zdns/version.go) is updated to the new version
  - [ ] Ensure the version of `miekg/dns` matches the version of `zmap/dns` in the replace directive in `go.mod`
  - [ ] Ensure any of the above changes have been merged into `main`


## Release Process
Once the above checklist is complete, you can proceed with the release process. We use `goreleaser` to automate the release process.

0. Install `goreleaser`:
```shell  
brew install goreleaser/tap/goreleaser
```  

1. Create a new tag and push to GH:
```shell  
git tag -a vA.B.C -m "Release A.B.C"
```  

2. Test the release:
```shell  
goreleaser release --skip=publish --clean
```

3. Set GitHub Token (at least configured with `write:packages`)
```shell
export GITHUB_TOKEN="YOUR_GH_TOKEN"
```
4. Push Tag to Github
   Be sure that this tagged commit is what you want to tag. Once you push you shouldn't delete the tagged version.
```shell
git push origin vA.B.C
```
5. Release!
```shell
goreleaser release --clean
```
6. Update the [Release Notes](https://github.com/zmap/zdns/releases) with a description of your changes