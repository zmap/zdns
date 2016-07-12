# ZDNS

[![Build Status](https://travis-ci.org/zmap/zdns.svg?branch=master)](https://travis-ci.org/zmap/zdns)


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

ZDNS Copyright 2016 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
