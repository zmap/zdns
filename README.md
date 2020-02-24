ZDNS
====

[![Build Status](https://travis-ci.org/zmap/zdns.svg?branch=master)](https://travis-ci.org/zmap/zdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/zmap/zdns)](https://goreportcard.com/report/github.com/zmap/zdns)

ZDNS is a command-line utility that provides high-speed DNS lookups. For
example, the following will perform MX lookups and a secondary A lookup for the
IPs of MX servers for the domains in the Alexa Top Million:

	cat top-1m.csv | zdns MX --ipv4-lookup --alexa

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

The `A`, `AAAA`, `ANY`, `AXFR`, `CAA`, `CDS`, `CDNSKEY`, `CNAME`, `DMARC`, `DS`, `DNSKEY`,
`MX`, `NAPTR`, `NS`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `PTR`,  `RRSIG`, `SOA`, `SPF`,
`SRV`, `TLSA`, and `TXT` modules provide the raw DNS response in JSON form, similar to dig.

For example, the command:

	echo "censys.io" | zdns A

returns:
```json
{
  "name": "censys.io",
  "class": "IN",
  "status": "NOERROR",
  "data": {
    "answers": [
      {
        "ttl": 300,
        "type": "A",
        "class": "IN",
        "name": "censys.io",
        "data": "216.239.38.21"
      }
    ],
    "additionals": [
      {
        "ttl": 34563,
        "type": "A",
        "class": "IN",
        "name": "ns-cloud-e1.googledomains.com",
        "data": "216.239.32.110"
      },
    ],
    "authorities": [
      {
        "ttl": 53110,
        "type": "NS",
        "class": "IN",
        "name": "censys.io",
        "data": "ns-cloud-e1.googledomains.com."
      },
    ],
    "protocol": "udp",
    "resolver": "30.128.52.190:53"
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
  "status": "NOERROR",
  "data": {
    "exchanges": [
      {
        "name": "aspmx.l.google.com",
        "type": "MX",
        "class": "IN",
        "preference": 1,
        "ipv4_addresses": [
          "74.125.28.26"
        ],
        "ttl": 288
      },
      {
        "name": "alt1.aspmx.l.google.com",
        "type": "MX",
        "class": "IN",
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

Local Recursion
---------------

ZDNS can either operate against a recursive resolver (e.g., an organizational
DNS server) [default behavior] or can perform its own recursion internally. To
perform local recursion, run zdns with the `--iterative` flag. When this flag
is used, ZDNS will round-robin between the published root servers (e.g.,
198.41.0.4). In iterative mode, you can control the size of the local cache by
specifying `--cache-size` and the timeout for individual iterations by setting
`--iteration-timeout`. The `--timeout` flag controls the timeout of the entire
resolution for a given input (i.e., the sum of all iterative steps).

Output Verbosity
----------------

DNS includes a lot of extraneous data that is not always useful. There are four
result verbosity levels: `short`, `normal` (default), `long`, and `trace`:

 * `short`: Short is the most terse result output. It contains only information about the responses
 * `normal`: Normal provides everything included in short as well as data about the responding server
 * `long`: Long outputs everything the server included in the DNS packet, including flags.
 * `trace`: Trace outputs everything from every step of the recursion process

Users can also include specific additional fields using the `--include-fields`
flag and specifying a list of fields, e.g., `--include-fields=flags,resolver`.
Additional fields are: class, protocol, ttl, resolver, flags.


Name Server Mode
----------------

By default ZDNS expects to receive a list of names to lookup on a small number
of name servers. For example:

```echo "google.com" | ./zdns A --name-servers=8.8.8.8,8.8.4.4```

However, there are times where you instead want to lookup the same name across
a large number of servers. This can be accomplished using _name server mode_.
For example:

```echo "8.8.8.8" | ./zdns A --name-server-mode --override-name="google.com"```

Here, every line piped in ZDNS is sent an A query for `google.com`. ZDNS also
supports mixing and matching both modes by piping in a comma-delimited list of
`name,nameServer`. For example:

```echo "google.com,8.8.8.8" | ./zdns A``` will send an `A` query for
`google.com` to `8.8.8.8` regardless of what name servers are specified by
`--name-servers=` flag. Lines that do not explicitly specify a name server will
use the servers specified by the OS or `--name-servers` flag as would normally
happen.


Running ZDNS
------------

By default, ZDNS will operate with 1,000 light-weight go routines. If you're
not careful, this will overwhelm many upstream DNS providers. We suggest that
users coordinate with local network administrators before performing any scans.
You can control the number of concurrent connections with the `--threads` and
`--go-processes` command line arguments. Alternate name servers can be
specified with `--name-servers`. ZDNS will rotate through these servers when
making requests.

While the number of go routines you use will depend on both hardware and the
type of request, we've rarely seen performance increase with more than 5,000 go
routines. In most cases, either performance will decrease and/or timeouts will
increase beyond that point. We've seen good ZDNS performance by running multiple
processes. Running 4 instances of ZDNS each with 2,500 threads is a great place
to start testing if you're performing large studies.

Unsupported Types
-----------------

If zdns encounters a record type it does not support it will generate an output
record with the `type` field set correctly and a representation of the
underlying data structure in the `unparsed_rr` field. Do not rely on the
presence or structure of this field. This field (and its existence) may change
at any time as we expand support for additional record types. If you find
yourself using this field, please consider submitting a pull-request adding
parser support.

License
=======

ZDNS Copyright 2020 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
