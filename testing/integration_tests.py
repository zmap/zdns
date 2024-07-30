#!/usr/bin/env python3

import copy
import subprocess
import json
import unittest
import tempfile
import datetime
from dateutil import parser
from ipaddress import ip_address


def recursiveSort(obj):
    def listSort(l):
        assert (type(l) == type(list()))
        new_list = []
        for item in l:
            item = recursiveSort(item)
            new_list.append(item)
        if len(new_list) > 0 and type(new_list[0]) == dict:
            return sorted(new_list, key=lambda x: x["name"])
        else:
            return sorted(new_list)

    def dictSort(d):
        assert (type(d) == type(dict()))
        for key in d:
            d[key] = recursiveSort(d[key])
        return d

    if type(obj) == list:
        return listSort(obj)

    elif type(obj) == dict:
        return dictSort(obj)
    else:
        return obj


class Tests(unittest.TestCase):
    maxDiff = None
    ZDNS_EXECUTABLE = "../zdns"

    def run_zdns_check_failure(self, flags, name, expected_err, executable=ZDNS_EXECUTABLE):
        flags = flags + " --threads=10"
        c = f"echo '{name}' | {executable} {flags}; exit 0"
        o = subprocess.check_output(c, shell=True, stderr=subprocess.STDOUT)
        self.assertEqual(expected_err in o.decode(), True)

    def run_zdns(self, flags, name, executable=ZDNS_EXECUTABLE):
        flags = flags + " --threads=10"
        c = f"echo '{name}' | {executable} {flags}"
        o = subprocess.check_output(c, shell=True)
        return c, json.loads(o.rstrip())

    def run_zdns_multiline(self, flags, names, executable=ZDNS_EXECUTABLE):
        d = tempfile.mkdtemp
        f = "/".join([d, "temp"])
        with open(f) as fd:
            for name in names:
                fd.writeline(name)
        flags = flags + " --threads=10"
        c = f"cat '{f}' | {executable} {flags}"
        o = subprocess.check_output(c, shell=True)
        os.rm(f)
        return c, [json.loads(l.rstrip()) for l in o]

    ROOT_A = {"1.2.3.4", "2.3.4.5", "3.4.5.6"}

    ROOT_A_ANSWERS = [{"type": "A", "class": "IN", "answer": x,
                       "name": "zdns-testing.com"} for x in ROOT_A]

    ROOT_AAAA = {"fd5a:3bce:8713::1", "fde6:9bb3:dbd6::2", "fdb3:ac76:a577::3"}

    ROOT_AAAA_ANSWERS = [{"type": "AAAA", "class": "IN", "answer": x,
                          "name": "zdns-testing.com"} for x in ROOT_AAAA]

    MX_SERVERS = [
        {"answer": "mx1.zdns-testing.com.", "preference": 1, "type": "MX", "class": "IN", 'name': 'zdns-testing.com'},
        {"answer": "mx2.zdns-testing.com.", "preference": 5, "type": "MX", "class": "IN", 'name': 'zdns-testing.com'},
        {"answer": "mx1.censys.io.", "preference": 10, "type": "MX", "class": "IN", 'name': 'zdns-testing.com'},
    ]

    NS_SERVERS = [
        {"type": "NS", "class": "IN", "name": "zdns-testing.com",
         "answer": "ns-cloud-c2.googledomains.com."},
        {"type": "NS", "class": "IN", "name": "zdns-testing.com",
         "answer": "ns-cloud-c3.googledomains.com."},
        {"type": "NS", "class": "IN", "name": "zdns-testing.com",
         "answer": "ns-cloud-c1.googledomains.com."},
        {"type": "NS", "class": "IN", "name": "zdns-testing.com",
         "answer": "ns-cloud-c4.googledomains.com."},
    ]

    NXDOMAIN_ANSWER = {
        "name": "zdns-testing-nxdomain.com",
        "class": "IN",
        "status": "NXDOMAIN"
    }

    MX_LOOKUP_ANSWER = {
        "name": "zdns-testing.com",
        "class": "IN",
        "status": "NOERROR",
        "data": {
            "exchanges": [
                {
                    "name": "mx1.zdns-testing.com",
                    "type": "MX",
                    "class": "IN",
                    "preference": 1,
                    "ipv4_addresses": [
                        "1.2.3.4",
                        "2.3.4.5"
                    ],
                    "ipv6_addresses": [
                        "fdb3:ac76:a577::4",
                        "fdb3:ac76:a577::5"
                    ],

                },
                {
                    "name": "mx2.zdns-testing.com",
                    "type": "MX",
                    "class": "IN",
                    "preference": 5,
                    "ipv4_addresses": [
                        "5.6.7.8"
                    ],
                },
                {
                    "name": "mx1.censys.io",
                    "type": "MX",
                    "class": "IN",
                    "preference": 10,
                }
            ]
        }
    }

    MX_LOOKUP_ANSWER_IPV4 = copy.deepcopy(MX_LOOKUP_ANSWER)
    del MX_LOOKUP_ANSWER_IPV4["data"]["exchanges"][0]["ipv6_addresses"]
    MX_LOOKUP_ANSWER_IPV6 = copy.deepcopy(MX_LOOKUP_ANSWER)
    del MX_LOOKUP_ANSWER_IPV6["data"]["exchanges"][0]["ipv4_addresses"]
    del MX_LOOKUP_ANSWER_IPV6["data"]["exchanges"][1]["ipv4_addresses"]

    A_LOOKUP_WWW_ZDNS_TESTING = {
        "name": "www.zdns-testing.com",
        "class": "IN",
        "status": "NOERROR",
        "data": {
            "ipv4_addresses": [
                "1.2.3.4",
                "2.3.4.5",
                "3.4.5.6"
            ],
            "ipv6_addresses": [
                "fde6:9bb3:dbd6::2",
                "fd5a:3bce:8713::1",
                "fdb3:ac76:a577::3"
            ]
        }
    }

    A_LOOKUP_IPV4_WWW_ZDNS_TESTING = copy.deepcopy(A_LOOKUP_WWW_ZDNS_TESTING)
    del A_LOOKUP_IPV4_WWW_ZDNS_TESTING["data"]["ipv6_addresses"]
    A_LOOKUP_IPV6_WWW_ZDNS_TESTING = copy.deepcopy(A_LOOKUP_WWW_ZDNS_TESTING)
    del A_LOOKUP_IPV6_WWW_ZDNS_TESTING["data"]["ipv4_addresses"]

    NS_LOOKUP_WWW_ZDNS_TESTING = {
        "name": "www.zdns-testing.com",
        "status": "NOERROR",
        "data": {
            "servers": [
                {
                    "ipv4_addresses": [
                        "216.239.34.108"
                    ],
                    "ipv6_addresses": [
                        "2001:4860:4802:34::6c"
                    ],
                    "name": "ns-cloud-c2.googledomains.com",
                    "type": "NS"
                },
                {
                    "ipv4_addresses": [
                        "216.239.32.108"
                    ],
                    "ipv6_addresses": [
                        "2001:4860:4802:32::6c"
                    ],
                    "name": "ns-cloud-c1.googledomains.com",
                    "type": "NS"
                },
                {
                    "ipv4_addresses": [
                        "216.239.38.108"
                    ],
                    "ipv6_addresses": [
                        "2001:4860:4802:38::6c"
                    ],
                    "name": "ns-cloud-c4.googledomains.com",
                    "type": "NS"
                },
                {
                    "ipv4_addresses": [
                        "216.239.36.108"
                    ],
                    "ipv6_addresses": [
                        "2001:4860:4802:36::6c"
                    ],
                    "name": "ns-cloud-c3.googledomains.com",
                    "type": "NS"
                }
            ]
        }
    }

    NS_LOOKUP_IPV4_WWW_ZDNS_TESTING = copy.deepcopy(NS_LOOKUP_WWW_ZDNS_TESTING)
    for server in NS_LOOKUP_IPV4_WWW_ZDNS_TESTING["data"]["servers"]:
        del server["ipv6_addresses"]
    NS_LOOKUP_IPV6_WWW_ZDNS_TESTING = copy.deepcopy(NS_LOOKUP_WWW_ZDNS_TESTING)
    for server in NS_LOOKUP_IPV6_WWW_ZDNS_TESTING["data"]["servers"]:
        del server["ipv4_addresses"]

    PTR_LOOKUP_GOOGLE_PUB = [
        {
            "type": "PTR",
            "class": "IN",
            "name": "8.8.8.8.in-addr.arpa",
            "answer": "dns.google."
        }
    ]

    CAA_RECORD = [
        {
            "type": "CAA",
            "class": "IN",
            "name": "zdns-testing.com",
            "tag": "issue",
            "value": "letsencrypt.org",
            "flag": 0
        }
    ]

    TXT_RECORD = [
        {
            "type": "TXT",
            "class": "IN",
            "name": "test_txt.zdns-testing.com",
            "answer": "Hello World!"
        }
    ]

    UDP_TRUNCATED_LARGE_TXT = {
        "name": "large-text.zdns-testing.com",
        "class": "IN",
        "status": "TRUNCATED",
        "timestamp": "2019-12-18T14:41:23-05:00",
        "data": {
            "answers": [],
            "additionals": [],
            "authorities": [],
            "protocol": "udp",
            "flags": {
                "response": False,
                "opcode": 0,
                "authoritative": False,
                "truncated": False,
                "recursion_desired": False,
                "recursion_available": False,
                "authenticated": False,
                "checking_disabled": False,
                "error_code": 0
            }
        }
    }

    TCP_LARGE_TXT_ANSWERS = [
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "surveys, informed by our own experiences conducting a long-term research survey over the past year."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "and explore the security implications of high speed Internet-scale network surveys, both offensive and defensive. "
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "in under 45 minutes from user space on a single machine, approaching the theoretical maximum speed of gigabit Ethernet."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "We introduce ZMap, a modular, open-source network scanner specifically architected to perform Internet-wide scans and capable of surveying the entire IPv4 address space"
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Internet-wide network scanning has numerous security applications, including exposing new vulnerabilities and tracking the adoption of defensive mechanisms, but probing the entire public address space with existing tools is both difficult and slow."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "We also discuss best practices for good Internet citizenship when performing Internet-wide"
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "We present the scanner architecture, experimentally characterize its performance and accuracy, "
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur."
        },
        {
            "type": "TXT",
            "class": "IN",
            "name": "large-text.zdns-testing.com",
            "answer": "Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem."
        },
    ]

    WWW_CNAME_ANSWERS = [
        {
            "type": "CNAME",
            "class": "IN",
            "name": "www.zdns-testing.com",
            "answer": "zdns-testing.com."
        }
    ]

    DMARC_ANSWER = {
        "data": {
            "dmarc": "v=DMARC1; p=none; rua=mailto:postmaster@censys.io"
        }
    }

    SPF_ANSWER = {
        "data": {
            "spf": "v=spf1 mx include:_spf.google.com -all"
        }
    }

    SOA_ANSWERS = [
        {
            "type": "SOA",
            "class": "IN",
            "name": "zdns-testing.com",
            "ns": "ns-cloud-c1.googledomains.com",
            "mbox": "cloud-dns-hostmaster.google.com",
            "serial": 2,
            "refresh": 21600,
            "retry": 3600,
            "expire": 259200,
            "min_ttl": 300

        }
    ]

    SRV_ANSWERS = [
        {
            "type": "SRV",
            "class": "IN",
            "name": "_sip._udp.sip.voice.google.com",
            "port": 5060,
            "priority": 10,
            "target": "sip-anycast-1.voice.google.com.",
            "weight": 1
        },
        {
            "type": "SRV",
            "class": "IN",
            "name": "_sip._udp.sip.voice.google.com",
            "port": 5060,
            "priority": 20,
            "target": "sip-anycast-2.voice.google.com.",
            "weight": 1
        }
    ]

    TLSA_ANSWERS = [
        {
            "type": "TLSA",
            "class": "IN",
            "name": "_25._tcp.mail.ietf.org",
            "cert_usage": 3,
            "selector": 1,
            "matching_type": 1,
            "certificate": "c1e715b41a893a35c8310e746552a6cd51ebaeadb2bf01d6e38e773f7adebe90"
        }
    ]

    ECS_MAPPINGS = {
        "171.67.68.0/24": "2.3.4.5",
        "131.159.92.0/24": "3.4.5.6",
        "129.127.149.0/24": "1.2.3.4"
    }

    def assertSuccess(self, res, cmd):
        self.assertEqual(res["status"], "NOERROR", cmd)

    def assertServFail(self, res, cmd):
        self.assertEqual(res["status"], "SERVFAIL", cmd)

    def assertEqualAnswers(self, res, correct, cmd, key="answer"):
        self.assertIn("answers", res["data"])
        for answer in res["data"]["answers"]:
            del answer["ttl"]
        a = sorted(res["data"]["answers"], key=lambda x: x[key])
        b = sorted(correct, key=lambda x: x[key])
        helptext = "%s\nExpected:\n%s\n\nActual:\n%s" % (cmd,
                                                         json.dumps(b, indent=4), json.dumps(a, indent=4))

        def _lowercase(obj):
            """ Make dictionary lowercase """
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "name":
                        obj[k] = v.lower()
                    else:
                        _lowercase(v)

        _lowercase(a)
        _lowercase(b)
        self.assertEqual(a, b, helptext)

    def assertEqualNXDOMAIN(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["status"], correct["status"])

    def assertEqualMXLookup(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["status"], correct["status"])
        for exchange in res["data"]["exchanges"]:
            del exchange["ttl"]
        self.assertEqual(recursiveSort(res["data"]["exchanges"]), recursiveSort(correct["data"]["exchanges"]))

    def assertEqualALookup(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["status"], correct["status"])
        if "ipv4_addresses" in correct["data"]:
            self.assertIn("ipv4_addresses", res["data"])
            self.assertEqual(sorted(res["data"]["ipv4_addresses"]), sorted(correct["data"]["ipv4_addresses"]))
        else:
            self.assertNotIn("ipv4_addresses", res["data"])
        if "ipv6_addresses" in correct["data"]:
            self.assertIn("ipv6_addresses", res["data"])
            self.assertEqual(sorted(res["data"]["ipv6_addresses"]), sorted(correct["data"]["ipv6_addresses"]))
        else:
            self.assertNotIn("ipv6_addresses", res["data"])

    def assertEqualNSLookup(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["status"], correct["status"])
        for server in res["data"]["servers"]:
            del server["ttl"]
        self.assertEqual(recursiveSort(res["data"]["servers"]), recursiveSort(correct["data"]["servers"]))

    def assertEqualTypes(self, res, list):
        res_types = set()
        for rr in res["data"]["answers"]:
            res_types.add(rr["type"])
        self.assertEqual(sorted(res_types), sorted(list))

    def check_json_in_list(self, json_obj, list):
        for obj in list:
            if json_obj == obj:
                return True
        return False

    def assertEqualAxfrLookup(self, records, correct_records):
        for record in list(records):
            try:
                del record["ttl"]
            except:
                pass
            try:
                del record["min_ttl"]
            except:
                pass
            try:
                del record["expire"]
            except:
                pass
            try:
                del record["refresh"]
            except:
                pass
            try:
                del record["retry"]
            except:
                pass
            # Delete records without the "name" field
            if not "name" in record:
                records.remove(record)
        for expected_record in correct_records:
            self.assertEqual(self.check_json_in_list(expected_record, records), True)

    def test_a(self):
        c = "A"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_a_ipv6(self):
        c = "A --name-servers=2001:4860:4860::8888:53"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_cname(self):
        c = "CNAME"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.WWW_CNAME_ANSWERS, cmd)

    def test_caa(self):
        c = "CAA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.CAA_RECORD, cmd, key="name")

    def test_txt(self):
        c = "TXT"
        name = "test_txt.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.TXT_RECORD, cmd)

    def test_a_iterative(self):
        c = "A --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_a_iterative_nxdomain(self):
        c = "A --iterative"
        name = "zdns-testing-nxdomain.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualNXDOMAIN(res, self.NXDOMAIN_ANSWER)

    def test_aaaa(self):
        c = "AAAA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd)

    def test_aaaa_iterative(self):
        c = "AAAA --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd)

    def test_mx(self):
        c = "MX"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd)

    def test_mx_iterative(self):
        c = "MX --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd)

    def test_ns(self):
        c = "NS"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd)

    def test_ns_iterative(self):
        c = "NS --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd)

    def test_mx_lookup(self):
        c = "mxlookup --ipv4-lookup --ipv6-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_iterative(self):
        c = "mxlookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_ipv4(self):
        c = "mxlookup --ipv4-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_mx_lookup_ipv6(self):
        c = "mxlookup --ipv6-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV6)

    def test_mx_lookup_default(self):
        c = "mxlookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_a_lookup(self):
        c = "alookup --ipv4-lookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING)

    def test_a_lookup_iterative(self):
        c = "alookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING)

    def test_a_lookup_ipv4(self):
        c = "alookup --ipv4-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_a_lookup_ipv6(self):
        c = "alookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV6_WWW_ZDNS_TESTING)

    def test_a_lookup_default(self):
        c = "alookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_ns_lookup(self):
        c = "nslookup --ipv4-lookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualNSLookup(res, self.NS_LOOKUP_WWW_ZDNS_TESTING)

    def test_ns_lookup_iterative(self):
        c = "nslookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.NS_LOOKUP_WWW_ZDNS_TESTING)

    def test_ns_lookup_default(self):
        c = "nslookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualNSLookup(res, self.NS_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_ns_lookup_ipv4(self):
        c = "nslookup --ipv4-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualNSLookup(res, self.NS_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_ns_lookup_ipv6(self):
        c = "nslookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualNSLookup(res, self.NS_LOOKUP_IPV6_WWW_ZDNS_TESTING)

    def test_spf_lookup(self):
        c = "spf"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.SPF_ANSWER["data"])

    def test_spf_lookup_iterative(self):
        c = "spf --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.SPF_ANSWER["data"])

    def test_dmarc_lookup(self):
        c = "dmarc"
        name = "_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.DMARC_ANSWER["data"])

    def test_dmarc_lookup_iterative(self):
        c = "dmarc --iterative"
        name = "_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.DMARC_ANSWER["data"])

    def test_ptr(self):
        c = "PTR"
        name = "8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd)

    def test_ptr_iterative(self):
        c = "PTR --iterative"
        name = "8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd)

    def test_spf(self):
        c = "SPF"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.SPF_ANSWER["data"])

    def test_spf_iterative(self):
        c = "SPF --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.SPF_ANSWER["data"])

    def test_dmarc(self):
        c = "DMARC"
        name = "_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.DMARC_ANSWER["data"])

    def test_dmarc_iterative(self):
        c = "DMARC --iterative"
        name = "_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.DMARC_ANSWER["data"])

    def test_axfr(self):
        # In this test, we just check for few specific records
        # in the AXFR fetch for zonetransfer.me because the
        # records can change over time and we want to minimise
        # having to update ./axfr.json
        c = "axfr"
        name = "zonetransfer.me"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        f = open("testing/axfr.json")
        axfr_answer = json.load(f)
        self.assertEqualAxfrLookup(res["data"]["servers"][0]["records"], axfr_answer["data"]["servers"][0]["records"])
        f.close()

    def test_soa(self):
        c = "SOA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.SOA_ANSWERS, cmd, key="serial")

    def test_srv(self):
        c = "SRV"
        name = "_sip._udp.sip.voice.google.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.SRV_ANSWERS, cmd, key="target")

    def test_tlsa(self):
        c = "TLSA"
        name = "_25._tcp.mail.ietf.org"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.TLSA_ANSWERS, cmd, key="certificate")

    def test_too_big_txt_udp(self):
        c = "TXT --udp-only --name-servers=8.8.8.8:53"
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["status"], "TRUNCATED")
        self.assertEqual(res["data"]["protocol"], "udp")

    def test_too_big_txt_tcp(self):
        c = "TXT --tcp-only --name-servers=8.8.8.8:53"  # Azure DNS does not provide results.
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd, key="answer")

    def test_too_big_txt_all(self):
        c = "TXT --name-servers=8.8.8.8:53"
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["protocol"], "tcp")
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd, key="answer")

    def test_override_name(self):
        c = "A --override-name=zdns-testing.com"
        name = "notrealname.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_server_mode_a_lookup_ipv4(self):
        c = "A --override-name=zdns-testing.com --name-server-mode"
        name = "8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_mixed_mode_a_lookup_ipv4(self):
        c = "A --name-servers=0.0.0.0"
        name = "zdns-testing.com,8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_local_addr_interface_warning(self):
        c = "A --local-addr 192.168.1.5 --local-interface en0"
        name = "zdns-testing.com"
        self.run_zdns_check_failure(c, name, "--local-addr and --local-interface cannot both be specified")

    def test_edns0_client_subnet(self):
        name = "ecs-geo.zdns-testing.com"
        for subnet, ip_addr in self.ECS_MAPPINGS.items():
            # Hardcoding a name server that supports ECS; Github's default recursive does not.
            c = f"A --client-subnet {subnet} --name-servers=8.8.8.8:53"
            cmd, res = self.run_zdns(c, name)
            self.assertSuccess(res, cmd)
            address, netmask = tuple(subnet.split("/"))
            family = 1 if ip_address(address).version == 4 else 2
            self.assertEqual(address, res["data"]['additionals'][0]['csubnet']['address'])
            self.assertEqual(int(netmask), res["data"]['additionals'][0]['csubnet']["source_netmask"])
            self.assertEqual(family, res["data"]['additionals'][0]['csubnet']['family'])
            self.assertTrue("source_scope" in res["data"]['additionals'][0]['csubnet'])
            correct = [{"type": "A", "class": "IN", "answer": ip_addr, "name": "ecs-geo.zdns-testing.com"}]
            self.assertEqualAnswers(res, correct, cmd)

    def test_edns0_nsid(self):
        name = "google.com"
        # using Google Public DNS for testing as its NSID always follows format 'gpdns-<airport code>'
        c = f"A --nsid --name-servers=8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertTrue("nsid" in res["data"]['additionals'][0])
        self.assertTrue(res["data"]['additionals'][0]['nsid']['nsid'].startswith("gpdns-"))

    def test_edns0_ede_1(self):
        name = "dnssec.fail"
        # using Cloudflare Public DNS (1.1.1.1) that implements EDE
        c = f"A --name-servers=1.1.1.1:53"
        cmd, res = self.run_zdns(c, name)
        self.assertServFail(res, cmd)
        self.assertTrue("ede" in res["data"]['additionals'][0])
        ede_obj = res["data"]['additionals'][0]["ede"][0]
        self.assertEqual("DNSKEY Missing", ede_obj["error_text"])
        self.assertEqual("no SEP matching the DS found for dnssec.fail.", ede_obj["extra_text"])
        self.assertEqual(9, ede_obj["info_code"])

    def test_edns0_ede_2_cd(self):
        name = "dnssec.fail"
        # using Cloudflare Public DNS (1.1.1.1) that implements EDE, checking disabled resulting in NOERROR
        c = f"A --name-servers=1.1.1.1:53 --checking-disabled"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertTrue("ede" in res["data"]['additionals'][0])
        ede_obj = res["data"]['additionals'][0]["ede"][0]
        self.assertEqual("DNSKEY Missing", ede_obj["error_text"])
        self.assertEqual("no SEP matching the DS found for dnssec.fail.", ede_obj["extra_text"])
        self.assertEqual(9, ede_obj["info_code"])

    def test_dnssec_response(self):
        # checks if dnssec records are returned
        c = f"SOA --dnssec --name-servers=8.8.8.8:53"
        name = "."
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual('do', res["data"]['additionals'][0]['flags'])
        self.assertEqualTypes(res, ["SOA", "RRSIG"])

    def test_cd_bit_not_set(self):
        c = "A --name-servers=8.8.8.8:53"
        name = "dnssec-failed.org"
        cmd, res = self.run_zdns(c, name)
        self.assertServFail(res, cmd)

    def test_cd_bit_set(self):
        c = "A --name-servers=8.8.8.8:53 --checking-disabled"
        name = "dnssec-failed.org"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)

    def test_timetamps(self):
        c = "A"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        assert "timestamp" in res
        date = datetime.datetime.strptime(res["timestamp"], "%Y-%m-%dT%H:%M:%S%z")
        self.assertTrue(date.microsecond == 0)  # microseconds should be 0 since we didn't call with --nanoseconds

    def test_timetamps_nanoseconds(self):
        c = "A --nanoseconds"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        assert "timestamp" in res
        date = parser.parse(res["timestamp"])
        self.assertTrue(date.microsecond != 0)
        # microseconds should be non-zero since we called with --nanoseconds. There is a chance it happens to be 0,
        # but it is very unlikely. (1 in 1,000,000). Python's datetime.date's smallest unit of time is microseconds,
        # so that's why we're using this in place of nanoseconds. It should not affect the test's validity.

# Test Cases for IPv6
    def test_ipv6_unreachable(self):
        c = "A --iterative --ipv6-lookup=true --ipv4-lookup=false"
        name = "esrg.stanford.edu"
        cmd, res = self.run_zdns(c, name)
        # esrg.stanford.edu is hosted on NS's that do not have an IPv6 address. Therefore, this will fail.
        self.assertServFail(res, cmd)

    def test_ipv6_external_lookup_unreachable_nameserver(self):
        c = "A --ipv6-lookup=true --ipv4-lookup=false --name-servers=1.1.1.1"
        name = "zdns-testing.com"
        try:
            cmd, res = self.run_zdns(c, name)
        except Exception as e:
            return True
        self.fail("Should have thrown an exception, shouldn't be able to reach any IPv4 servers while in IPv6 mode")

    def test_ipv4_external_lookup_unreachable_nameserver(self):
        c = "A --ipv6-lookup=false --ipv4-lookup=true --name-servers=2606:4700:4700::1111"
        name = "zdns-testing.com"
        try:
            cmd, res = self.run_zdns(c, name)
        except Exception as e:
            return True
        self.fail("Should have thrown an exception, shouldn't be able to reach any IPv6 servers while in IPv4 mode")

    def test_ipv6_happy_path_external(self):
        c = "A --ipv6-lookup=true"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_ipv6_happy_path_iterative(self):
        c = "A --ipv6-lookup=true --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_ipv6_happy_path_no_ipv4_iterative(self):
        c = "A --ipv6-lookup=true --ipv4-lookup=false --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)




if __name__ == "__main__":
    unittest.main()
