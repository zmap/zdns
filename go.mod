module github.com/zmap/zdns

go 1.23.0

require (
	github.com/hashicorp/go-version v1.7.0
	github.com/liip/sheriff v0.12.0
	github.com/miekg/dns v1.1.64
	github.com/pkg/errors v0.9.1
	github.com/schollz/progressbar/v3 v3.18.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	github.com/zmap/go-dns-root-anchors v0.0.0-20241218192521-63aee68224b6
	github.com/zmap/go-iptree v0.0.0-20210731043055-d4e632617837
	github.com/zmap/zcrypto v0.0.0-20250324021606-4f0ea0eaccac
	github.com/zmap/zflags v1.4.0-beta.1.0.20200204220219-9d95409821b6
	github.com/zmap/zgrab2 v0.1.9-0.20250324024219-c80b95ff127a
	gotest.tools/v3 v3.5.2
)

replace github.com/miekg/dns => github.com/zmap/dns v1.1.64

require (
	github.com/asergeyev/nradix v0.0.0-20220715161825-e451993e425c // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.21.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/weppos/publicsuffix-go v0.40.3-0.20250311103038-7794c8c0723b // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/term v0.30.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/tools v0.31.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
