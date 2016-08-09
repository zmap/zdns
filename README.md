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

ZDNS provides several types of modules. The first provides raw JSON output for
the response to a single DNS query. These include A, AAAA, AXFR, CNAME, DMARC,
MX, NS, PTR, TXT, and SPF. For example, running

For example, the command:

	echo "cesys.io" | zdns AAAA

Will give you back the entire DNS response---similar to what you would expect
from running dig:

	{
	  "name": "censys.io",
	  "status": "success",
	  "data": {
	    "answers": [
	      {
	        "ttl": 300,
	        "type": "A",
	        "name": "censys.io",
	        "data": "216.239.38.21"
	      }
	    ],
	    "additionals": [
	      {
	        "ttl": 34563,
	        "type": "A",
	        "name": "ns-cloud-e1.googledomains.com",
	        "data": "216.239.32.110"
	      },
	    ],
	    "authorities": [
	      {
	        "ttl": 53110,
	        "type": "NS",
	        "name": "censys.io",
	        "data": "ns-cloud-e1.googledomains.com."
	      },
	    ],
	    "protocol": "udp"
	  }
	}

However, these modules will not help you if the server does not automatically
what you return. For example, an MX query may or may not include the the IPs
for the MX records in the additionals section. To address this gap and provide
a friendlier interface, we also provide several "lookup" modules, which operate
similar to nslookup. There are two of these modules: `alookup` and `mxlookup`.

`mxlookup` will additionally do an A lookup for the IP addresses that
correspond with an exchange record. `alookup` will do the same for A records
(and will follow CNAME records.)

For example,

	echo "censys.io" | ./zdns mxlookup --ipv4-lookup

will return:

	{
	  "name": "censys.io",
	  "status": "success",
	  "data": {
	    "exchanges": [
	      {
	        "name": "aspmx.l.google.com",
	        "type": "MX",
	        "preference": 1,
	        "ipv4_addresses": [
	          "74.125.28.26"
	        ],
	        "ttl": 288
	      },
	      {
	        "name": "alt1.aspmx.l.google.com",
	        "type": "MX",
	        "preference": 5,
	        "ipv4_addresses": [
	          "64.233.182.26"
	        ],
	        "ttl": 288
	      }
	    ]
	  }
	}

Please note the --threads and --go-processes flags, which will dictate ZDNS's
performance.



### License

ZDNS Copyright 2016 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
