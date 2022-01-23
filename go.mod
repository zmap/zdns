module github.com/zmap/zdns

go 1.13

require (
	github.com/asergeyev/nradix v0.0.0-20170505151046-3872ab85bb56 // indirect
	github.com/hashicorp/go-version v1.2.0
	github.com/liip/sheriff v0.0.0-20190308094614-91aa83a45a3d
	github.com/miekg/dns v1.1.27
	github.com/sirupsen/logrus v1.4.2
	github.com/zmap/go-iptree v0.0.0-20170831022036-1948b1097e25
	golang.org/x/crypto v0.0.0-20200117160349-530e935923ad // indirect
	golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa // indirect
)

replace github.com/miekg/dns => github.com/zmap/dns v1.1.35-zdns-2
