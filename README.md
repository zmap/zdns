# ZDNS

ZDNS is a command-line utility that provides high-speed DNS lookups. For
example, the following will perform MX lookups and a secondary A lookup for the
IPs of MX servers for the domains in the Alexa Top Million:

	cat top-1m.csv | zdns MX --lookup-ipv4 --alexa

ZDNS is written in golang and is primarily based on https://github.com/miekg/dns.

### Install

ZDNS can be installed by running:

	go get github.com/zmap/zdns/zdns


### Usage

ZDNS provides several modules: A, AAAA, MX, TXT, SPF, and SPF. For additional
information about each, you can run:

	zdns CMD --help

For example:

	zdns AAAA --help


### License

ZGrab is licensed under the Apache 2.0 License. See LICENSE for more information.
