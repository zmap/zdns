# Releasing a New Version of ZDNS
We use [goreleaser](https://goreleaser.com) to release new versions of ZDNS. To release a new version, follow these steps:

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
goreleaser release --skip-publish --clean
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