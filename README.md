ZDNS
====

[![Build Status](https://travis-ci.org/zmap/zdns.svg?branch=master)](https://travis-ci.org/zmap/zdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/zmap/zdns)](https://goreportcard.com/report/github.com/zmap/zdns)

ZDNS is a command-line utility that provides high-speed DNS lookups. ZDNS is
written in Go and contains its own recursive resolution code and a cache
optimized for performing lookups of a diverse set of names. We use
https://github.com/miekg/dns to construct and parse raw DNS packets.

As an example, the following will perform MX lookups and a secondary A lookup
for the IPs of MX servers for the domains in the Alexa Top Million:

	cat top-1m.csv | ./zdns MX --ipv4-lookup --alexa


Install
=======

ZDNS can be installed by checking out the repository and running `go build`.

	git clone https://github.com/zmap/zdns.git
	cd zdns/zdns
	go build

You _cannot_ just run `go get` because we use a forked version of miekg's DNS
library that has additional performance fixes.


Usage
=====

ZDNS provides several types of modules:

- *Raw DNS modules* provide the raw DNS reponse from the server similar to dig, but in JSON. There is a module for (nearly) every type of DNS record
- *Lookup modules* provide more helpful responses when multiple queries are required (e.g., completing additional `A` lookup if a `CNAME` is received)
- *Misc modules* provide other additional means of querying servers (e.g., `bind.version`)

We detail the modules below:

Raw DNS Modules
---------------
The A, AAAA, AFSDB, ANY, ATMA, AVC, AXFR, BINDVERSION, CAA, CDNSKEY, CDS, CERT,
CNAME, CSYNC, DHCID, DMARC, DNSKEY, DS, EID, EUI48, EUI64, GID, GPOS, HINFO,
HIP, HTTPS, ISDN, KEY, KX, L32, L64, LOC, LP, MB, MD, MF, MG, MR, MX, NAPTR, NID,
NINFO, NS, NSAPPTR, NSEC, NSEC3, NSEC3PARAM, NSLOOKUP, NULL, NXT, OPENPGPKEY,
PTR, PX, RP, RRSIG, RT, SVCBS, MIMEA, SOA, SPF, SRV, SSHFP, TALINK, TKEY, TLSA, TXT,
UID, UINFO, UNSPEC, and URI modules provide the raw DNS response in JSON form,
similar to dig.

For example, the command:

	echo "censys.io" | ./zdns A

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

Other DNS Modules
-----------------

ZDNS also supports special "debug" DNS queries. Modules include: `BINDVERSION`.

Local Recursion
---------------

ZDNS can either operate against a recursive resolver (e.g., an organizational
DNS server) [default behavior] or can perform its own recursion internally. If
you are performing a small number of lookups (i.e., millions) and using a less
than 10,000 go routines, it is typically fastest to use one of the common
recursive resolvers like Cloudflare or Google. Cloudflare is nearly always
faster than Google. This is particularly true if you're looking up popular
names because they're cached and can be answered in a single round trip.
Otherwise, performing iteration internally is much faster, because you can run
with tens of thousands of concurrent threads without DOS'ing and/or rate
limiting your recursive resolver.

To perform local recursion, run zdns with the `--iterative` flag. When this
flag is used, ZDNS will round-robin between the published root servers (e.g.,
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
making requests. We have successfully run ZDNS with tens of thousands of
light-weight routines.

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
