ZDNS
====

[![Build Status](https://travis-ci.org/zmap/zdns.svg?branch=master)](https://travis-ci.org/zmap/zdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/zmap/zdns)](https://goreportcard.com/report/github.com/zmap/zdns)

ZDNS is a command-line utility that provides high-speed DNS lookups. ZDNS is
written in Go and contains its own recursive resolution code and a cache
optimized for performing lookups of a diverse set of names. We use
https://github.com/zmap/dns to construct and parse raw DNS packets.
For more information about ZDNS's architecture and performance, check out the following [paper](https://lizizhikevich.github.io/assets/papers/ZDNS.pdf) appearing at ACM's Internet Measurement Conference '22. 

As an example, the following will perform MX lookups and a secondary A lookup
for the IPs of MX servers for the domains in the Alexa Top Million:

	cat top-1m.csv | ./zdns MX --ipv4-lookup --alexa


Install
=======

ZDNS can be installed by checking out the repository and running `go build`.

```bash
git clone https://github.com/zmap/zdns.git
cd zdns
go build
```

Usage
=====

ZDNS was originally built as a CLI tool only. Work has been done to convert
this into a library with a CLI that calls this library. Currently, the library
has been separated out and a new, separate CLI has been added. Work is ongoing
to clean up the interface between the CLI (or any other client program of the
ZDNS library) and the ZDNS library itself.

The ZDNS library lives in `github.com/zmap/zdns/pkg/zdns`. A function there,
`zdns.Run()`, is used to start the ZDNS tool and do the requested lookups.
Currently, this tool is intended to accept a `zdns.GlobalConf` object, `plfag`
flags, and other information, but this interface is undergoing revisions to be
more generally usable and continue to decouple the CLI from the library.

The CLI for this library lives in `github.com/zmap/zdns` under the main
package. Its functionality is described below.

ZDNS provides several types of modules:

- *Raw DNS modules* provide the raw DNS reponse from the server similar to dig,
  but in JSON. There is a module for (nearly) every type of DNS record

- *Lookup modules* provide more helpful responses when multiple queries are
  required (e.g., completing additional `A` lookup if a `CNAME` is received)

- *Misc modules* provide other additional means of querying servers (e.g.,
  `bind.version`)

We detail the modules below:

Raw DNS Modules
---------------

The A, AAAA, AFSDB, ANY, ATMA, AVC, AXFR, BINDVERSION, CAA, CDNSKEY, CDS, CERT,
CNAME, CSYNC, DHCID, DMARC, DNSKEY, DS, EID, EUI48, EUI64, GID, GPOS, HINFO,
HIP, HTTPS, ISDN, KEY, KX, L32, L64, LOC, LP, MB, MD, MF, MG, MR, MX, NAPTR,
NID, NINFO, NS, NSAPPTR, NSEC, NSEC3, NSEC3PARAM, NSLOOKUP, NULL, NXT,
OPENPGPKEY, PTR, PX, RP, RRSIG, RT, SVCBS, MIMEA, SOA, SPF, SRV, SSHFP, TALINK,
TKEY, TLSA, TXT, UID, UINFO, UNSPEC, and URI modules provide the raw DNS
response in JSON form, similar to dig.

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

Threads, Sockets, and Performance
---------------------------------

ZDNS performance stems from massive parallelization using light-weight Go
routines. This architecture has several cavaets:

 * Every Go routine uses its own dedicated network socket. Thus, you need to be
   able to open as many sockets (in terms of both max file descriptors and
   ephemeral ports) as you have threads specified (via `--threads`). By default,
   ZDNS uses 1,000 threads, which is less than Linux's default max number of 1024
   open FDs. However, it is greater than Mac OS's default of 256. You can view
   the maximum number of open FDs (and thus sockets) permitted by running `unlimit -n`. If
   you want to run with a greater number of threads than this number, you need to
   increase the number of open files at the OS level. If you fail to do this,
   you'll encounter a fatal error similar to `FATA[0000] unable to create
   socketlisten udp <client IP address>:0: socket: too many open files`. If you
   want to run more threads than you have ephemeral ports available, you will need
   to use multiple client IP addresses: `--local-addr=A,B,C`.

 * By default, ZDNS "reuses" UDP sockets by creating an unbound UDP socket for
   each light-weight routine at launch and using it for all queries (regardless
   of destination IP). This dramatically improves performance because ZDNS and the
   host OS don't need to setup and tear down a socket to send each individual
   packet (since DNS queries/responses tend to be one packet each).  However, this
   means that ZDNS will preallocate a socket for each thread at launch. This may not
   be optimal if you're only looking up a small number of names.  For example, if
   you only need to lookup 100 names, but use the default 1,000 threads, you'll
   bind but never use 900 UDP sockets. Instead, of worrying about recycling
   sockets, we recommend that you specify a reasonable number of threads for your
   use case (since this also foregoes any work to start those threads in the first place).
   This is why, though, you can get an error about being unable to open a large
   number of sockets even though you're only looking up a single name. If it's important
   to create a fresh socket for each query, you can disable this reuse by specifying
   `--recycle-sockets=false`.

 * Go is happy to use all CPU cores that are available to it, and can use a
   tremendous amount of CPU if you specify a large number of threads. CPU is
   primarily used for parsing and JSON encoding. If you want to limit the number
   of CPU cores, you can do so by including the `--go-processes=n` flag or setting
   the `GOMAXPROCS` environment variable.

 * Typically we recommend using around 1000-5000 threads. Unless you're on an
   underesourced system, you'll likely be throwing away free performance with
   only tens or hundreds of threads (since you'll be waiting on network
   communication). We typically don't see significant improvement in performance
   with over 5,000 threads, and don't have any cases where more than 10,000
   threads improved performance.


Local Recursion
---------------

ZDNS can either operate against a recursive resolver (e.g., an organizational
DNS server) [default behavior] or can perform its own recursion internally. If
you are performing a small number of lookups (i.e., millions) and using a less
than 10,000 go routines, it is typically fastest to use one of the common
recursive resolvers like Cloudflare or Google. Cloudflare is nearly always
faster than Google. This is particularly true if you're looking up popular
names because they're cached and can be answered in a single round trip.
When using tens of thousands of concurrent threads, consider performing 
iteration internally in order to avoid  DOS'ing and/or rate limiting your
recursive resolver.

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

Querying all Nameservers
----------------
There is a feature available to perform a certain DNS query against all nameservers. For example, you might want to get the A records from all nameservers of a certain domain. To do so, you can do:

```echo "google.com" | ./zdns A --all-nameservers```

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
