ZDNS
====

[![Build Status](https://travis-ci.org/zmap/zdns.svg?branch=master)](https://travis-ci.org/zmap/zdns)


ZDNS is a command-line utility that provides high-speed DNS lookups. For
example, the following will perform MX lookups and a secondary A lookup for the
IPs of MX servers for the domains in the Alexa Top Million:

	cat top-1m.csv | zdns MX --lookup-ipv4 --alexa

ZDNS is written in golang and is primarily based on https://github.com/miekg/dns.

Install
=======

ZDNS can be installed by running:

	go get github.com/zmap/zdns/zdns


Usage
=====

ZDNS provides several types of modules.

Raw DNS Modules
---------------

The `A`, `AAAA`, `ANY`, `AXFR`, `CNAME`, `DMARC`, `MX`, `NS`, `PTR`, `TXT`,
`SOA`, and `SPF` modules provide the raw DNS response in JSON form, similar to dig.

For example, the command:

	echo "censys.io" | zdns A

returns:
```json
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
```

Lookup Modules
--------------

Raw DNS responses frequently do not provide the data you _want_. For example,
an MX response may not include the associated A records in the additionals
section requiring an additional lookup. To address this gap and provide a
friendlier interface, we also provide several _lookup_ modules: `alookup` and
`mxlookup`.

`mxlookup` will additionally do an A lookup for the IP addresses that
correspond with an exchange record. `alookup` acts similar to nslookup and will
follow CNAME records.

For example,

	echo "censys.io" | ./zdns mxlookup --ipv4-lookup

returns:
```json
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
```

Please note the --threads and --go-processes flags, which will dictate ZDNS's
performance.


Zone File Modules
-----------------

The above modules are useful when we only have a list of domain names to perform queries
for. However, in some instances we have a root zone file that indicates all domains in a 
zone, and their nameservers. For this instance, we have the `zone` module.

The `zone` module performs an `alookup` for each domain in the specified zone file, 
skipping as much of the recursive lookup as is possible. This entails utilization of the
glue records in the zone file to go directly to the domain's authoritative nameserver,
as well as caching nameserver locations when lookups must be performed.

For example, if the following two records are in a zonefile,

	foo.com. NS ns.foo.com.
	ns.foo.com. A XXX.XXX.XXX.XXX

then the resulting lookup for foo.com will utilize the nameserver at XXX.XXX.XXX.XXX

This is useful for performing many `alookup` calls without hammering the local and root
nameservers. 

Note: the `zone` module requires the --input-file flag be set, in order to allow it to 
make two passes over the input.


License
=======

ZDNS Copyright 2016 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
