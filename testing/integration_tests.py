#!/usr/bin/env python3

import copy
import os
import subprocess
import json
import unittest
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
    ZDNS_EXECUTABLE = "./zdns"
    ADDITIONAL_FLAGS = " --threads=10 --quiet"  # flags used with every test

    def run_zdns_check_failure(self, flags, name, expected_err, executable=ZDNS_EXECUTABLE):
        flags = flags + self.ADDITIONAL_FLAGS
        c = f"echo '{name}' | {executable} {flags}; exit 0"
        o = subprocess.check_output(c, shell=True, stderr=subprocess.STDOUT)
        self.assertEqual(expected_err in o.decode(), True)

    def run_zdns(self, flags, name, executable=ZDNS_EXECUTABLE):
        flags = flags + self.ADDITIONAL_FLAGS
        c = f"echo '{name}' | {executable} {flags}"
        o = subprocess.check_output(c, shell=True)
        return c, json.loads(o.rstrip())

    # Runs zdns with a given name(s) input and flags, returns the command and JSON objects from the piped JSON-Lines output
    # Used when running a ZDNS command that should return multiple lines of output, and you want those in a list
    def run_zdns_multiline_output(self, flags, name, executable=ZDNS_EXECUTABLE, append_flags=True):
        if append_flags:
            flags = flags + self.ADDITIONAL_FLAGS
        c = f"echo '{name}' | {executable} {flags}"
        o = subprocess.check_output(c, shell=True)
        output_lines = o.decode('utf-8').strip().splitlines()
        json_objects = [json.loads(line.rstrip()) for line in output_lines]
        return c, json_objects

    ROOT_A_ZDNS_TESTING_COM = {"1.2.3.4", "2.3.4.5", "3.4.5.6"}  # zdns-testing.com

    ROOT_A_A_ZDNS_TESTING_COM = {"21.9.87.65"}  # a.zdns-testing.com

    ROOT_A_ANSWERS = [{"type": "A", "class": "IN", "answer": x,
                       "name": "zdns-testing.com"} for x in ROOT_A_ZDNS_TESTING_COM]

    ROOT_A_A_ZDNS_TESTING_COM_ANSWERS = [{"type": "A", "class": "IN", "answer": x,
                                          "name": "a.zdns-testing.com"} for x in ROOT_A_A_ZDNS_TESTING_COM]

    ROOT_AAAA = {"fd5a:3bce:8713::1", "fde6:9bb3:dbd6::2", "fdb3:ac76:a577::3"}

    ROOT_AAAA_ANSWERS = [{"type": "AAAA", "class": "IN", "answer": x,
                          "name": "zdns-testing.com"} for x in ROOT_AAAA]

    MX_SERVERS = [
        {"answer": "mx1.zdns-testing.com.", "preference": 1, "type": "MX", "class": "IN", 'name': 'zdns-testing.com'},
        {"answer": "mx2.zdns-testing.com.", "preference": 5, "type": "MX", "class": "IN", 'name': 'zdns-testing.com'},
        {"answer": "mx1.censys.io.", "preference": 10, "type": "MX", "class": "IN", 'name': 'zdns-testing.com'},
    ]

    A_MX1_ZDNS_TESTING_COM = {"1.2.3.4", "2.3.4.5"}

    AAAA_MX1_ZDNS_TESTING_COM = {"fdb3:ac76:a577::4", "fdb3:ac76:a577::5"}

    A_MX1_ZDNS_TESTING_COM_ANSWERS = [{"type": "A", "class": "IN", "answer": x, "name": "mx1.zdns-testing.com"}
                                      for x in A_MX1_ZDNS_TESTING_COM]
    AAAA_MX1_ZDNS_TESTING_COM_ANSWERS = [{"type": "AAAA", "class": "IN", "answer": x, "name": "mx1.zdns-testing.com"}
                                         for x in AAAA_MX1_ZDNS_TESTING_COM]

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
        "results": {
            "MXLOOKUP": {
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
        }
    }

    MX_LOOKUP_ANSWER_IPV4 = copy.deepcopy(MX_LOOKUP_ANSWER)
    del MX_LOOKUP_ANSWER_IPV4["results"]["MXLOOKUP"]["data"]["exchanges"][0]["ipv6_addresses"]
    MX_LOOKUP_ANSWER_IPV6 = copy.deepcopy(MX_LOOKUP_ANSWER)
    del MX_LOOKUP_ANSWER_IPV6["results"]["MXLOOKUP"]["data"]["exchanges"][0]["ipv4_addresses"]
    del MX_LOOKUP_ANSWER_IPV6["results"]["MXLOOKUP"]["data"]["exchanges"][1]["ipv4_addresses"]

    A_LOOKUP_WWW_ZDNS_TESTING = {
        "name": "www.zdns-testing.com",
        "results": {
            "ALOOKUP": {
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
        }
    }

    A_LOOKUP_WWW_ZDNS_TESTING_IPv6 = {
        "name": "www.zdns-testing.com",
        "results": {
            "ALOOKUP": {
                "status": "NOERROR",
                "class": "IN",
                "data": {
                    "ipv6_addresses": [
                        "fde6:9bb3:dbd6::2",
                        "fd5a:3bce:8713::1",
                        "fdb3:ac76:a577::3"
                    ]
                }
            }
        }
    }

    A_LOOKUP_CNAME_CHAIN_03 = {
        "name": "cname-chain-03.esrg.stanford.edu",
        "results": {
            "ALOOKUP": {
                "status": "NOERROR",
                "class": "IN",
                "data": {
                    "ipv4_addresses": [
                        "1.2.3.4",
                    ]
                }
            }
        }
    }

    A_LOOKUP_IPV4_WWW_ZDNS_TESTING = copy.deepcopy(A_LOOKUP_WWW_ZDNS_TESTING)
    del A_LOOKUP_IPV4_WWW_ZDNS_TESTING["results"]["ALOOKUP"]["data"]["ipv6_addresses"]
    A_LOOKUP_IPV6_WWW_ZDNS_TESTING = copy.deepcopy(A_LOOKUP_WWW_ZDNS_TESTING)
    del A_LOOKUP_IPV6_WWW_ZDNS_TESTING["results"]["ALOOKUP"]["data"]["ipv4_addresses"]

    NS_LOOKUP_WWW_ZDNS_TESTING = {
        "name": "www.zdns-testing.com",
        "results": {
            "NSLOOKUP": {
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
        }
    }

    NS_LOOKUP_IPV4_WWW_ZDNS_TESTING = copy.deepcopy(NS_LOOKUP_WWW_ZDNS_TESTING)
    for server in NS_LOOKUP_IPV4_WWW_ZDNS_TESTING["results"]["NSLOOKUP"]["data"]["servers"]:
        del server["ipv6_addresses"]
    NS_LOOKUP_IPV6_WWW_ZDNS_TESTING = copy.deepcopy(NS_LOOKUP_WWW_ZDNS_TESTING)
    for server in NS_LOOKUP_IPV6_WWW_ZDNS_TESTING["results"]["NSLOOKUP"]["data"]["servers"]:
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

    WWW_CNAME_AND_A_ANSWERS = [
        {
            "type": "CNAME",
            "class": "IN",
            "name": "www.zdns-testing.com",
            "answer": "zdns-testing.com."
        }, {
            "type": "A",
            "class": "IN",
            "name": "zdns-testing.com",
            "answer": "1.2.3.4"
        }, {
            "type": "A",
            "class": "IN",
            "name": "zdns-testing.com",
            "answer": "2.3.4.5"
        }, {
            "type": "A",
            "class": "IN",
            "name": "zdns-testing.com",
            "answer": "3.4.5.6"
        }
    ]

    WWW_CNAME_AND_AAAA_ANSWERS = [
        {
            "type": "CNAME",
            "class": "IN",
            "name": "www.zdns-testing.com",
            "answer": "zdns-testing.com."
        }, {
            "type": "AAAA",
            "class": "IN",
            "name": "zdns-testing.com",
            "answer": "fd5a:3bce:8713::1"
        }, {
            "type": "AAAA",
            "class": "IN",
            "name": "zdns-testing.com",
            "answer": "fde6:9bb3:dbd6::2"
        }, {
            "type": "AAAA",
            "class": "IN",
            "name": "zdns-testing.com",
            "answer": "fdb3:ac76:a577::3"
        }
    ]

    CNAME_LOOP_ANSWERS = [
        {
            "type": "CNAME",
            "class": "IN",
            "name": "cname-loop.zdns-testing.com",
            "answer": "cname-loop.esrg.stanford.edu.",
        }, {
            "type": "CNAME",
            "class": "IN",
            "name": "cname-loop.esrg.stanford.edu",
            "answer": "cname-loop.zdns-testing.com.",
        }
    ]

    # an A record behind a DNAME record
    DNAME_A_RECORD_ANSWERS = [
        {
            "type": "DNAME",
            "class": "IN",
            "name": "zdns-dname.esrg.stanford.edu",
            "answer": "zdns-testing.com.",
        },
        {
            "type": "CNAME",
            "class": "IN",
            "name": "a.zdns-dname.esrg.stanford.edu",
            "answer": "a.zdns-testing.com.",
        }, {
            "type": "A",
            "class": "IN",
            "name": "a.zdns-testing.com",
            "answer": "21.9.87.65",
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
            "certificate": "b05d5a0b10095ab7d38710aa70b85c5227cfb9cae23c93ee2bf8fdbedfffdb39"
        }, {
            "type": "TLSA",
            "class": "IN",
            "name": "_25._tcp.mail.ietf.org",
            "cert_usage": 3,
            "selector": 1,
            "matching_type": 1,
            "certificate": "1f9afe824b213ab18bd59312c58c9282d2047875324cc7e0d4259d67cf42c5fa"
        }
    ]

    ECS_MAPPINGS = {
        "171.67.68.0/24": "2.3.4.5",
        "131.159.92.0/24": "3.4.5.6",
        "129.127.149.0/24": "1.2.3.4"
    }

    def assertSuccess(self, res, cmd, query_type):
        self.assertEqual(res["results"][query_type]["status"], "NOERROR", cmd)

    def assertServFail(self, res, cmd, query_type):
        self.assertEqual(res["results"][query_type]["status"], "SERVFAIL", cmd)

    def assertEqualAnswers(self, res, correct, cmd, query_type, key="answer"):
        self.assertIn("answers", res["results"][query_type]["data"])
        for answer in res["results"][query_type]["data"]["answers"]:
            del answer["ttl"]
        a = sorted(res["results"][query_type]["data"]["answers"], key=lambda x: x[key])
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

    def assertEqualNXDOMAIN(self, res, correct, query_type):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["results"][query_type]["status"], correct["status"])

    def assertEqualMXLookup(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["results"]["MXLOOKUP"]["status"], correct["results"]["MXLOOKUP"]["status"])
        for exchange in res["results"]["MXLOOKUP"]["data"]["exchanges"]:
            del exchange["ttl"]
        self.assertEqual(recursiveSort(res["results"]["MXLOOKUP"]["data"]["exchanges"]),
                         recursiveSort(correct["results"]["MXLOOKUP"]["data"]["exchanges"]))

    def assertEqualALookup(self, res, correct, query_type):
        self.assertEqual(res["name"], correct["name"])
        res = res["results"][query_type]
        correct_A_lookup = correct["results"][query_type]
        self.assertEqual(res["status"], correct_A_lookup["status"])
        if "ipv4_addresses" in correct_A_lookup["data"]:
            self.assertIn("ipv4_addresses", res["data"])
            self.assertEqual(sorted(res["data"]["ipv4_addresses"]), sorted(correct_A_lookup["data"]["ipv4_addresses"]))
        else:
            self.assertNotIn("ipv4_addresses", res["data"])
        if "ipv6_addresses" in correct_A_lookup["data"]:
            self.assertIn("ipv6_addresses", res["data"])
            self.assertEqual(sorted(res["data"]["ipv6_addresses"]), sorted(correct_A_lookup["data"]["ipv6_addresses"]))
        else:
            self.assertNotIn("ipv6_addresses", res["data"])

    def assertEqualNSLookup(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["results"]["NSLOOKUP"]["status"], correct["results"]["NSLOOKUP"]["status"])
        for server in res["results"]["NSLOOKUP"]["data"]["servers"]:
            del server["ttl"]
        self.assertEqual(recursiveSort(res["results"]["NSLOOKUP"]["data"]["servers"]),
                         recursiveSort(correct["results"]["NSLOOKUP"]["data"]["servers"]))

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
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_a_dig_style_args(self):
        c = "A zdns-testing.com"
        name = ""
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_a_multiple_domains_dig_style(self):
        c = "A zdns-testing.com a.zdns-testing.com --iterative"
        name = ""
        cmd, res = self.run_zdns_multiline_output(c, name)
        self.assertSuccess(res[0], cmd, "A")
        self.assertSuccess(res[1], cmd, "A")
        if res[0]["name"] == "zdns-testing.com":
            self.assertEqualAnswers(res[0], self.ROOT_A_ANSWERS, cmd, "A")
            self.assertEqualAnswers(res[1], self.ROOT_A_A_ZDNS_TESTING_COM_ANSWERS, cmd, "A")
        else:
            self.assertEqualAnswers(res[0], self.ROOT_A_A_ZDNS_TESTING_COM_ANSWERS, cmd, "A")
            self.assertEqualAnswers(res[1], self.ROOT_A_ANSWERS, cmd, "A")

    def test_multiple_modules(self):
        ini_file_contents = """
        [Application Options]
        name-servers = "1.1.1.1"
        [A]
        [AAAA]
        """
        file_name = "./test_multiple_modules.ini"
        with open(file_name, "w") as f:
            f.write(ini_file_contents)
        c = "MULTIPLE -c " + file_name
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertSuccess(res, cmd, "AAAA")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd, "AAAA")
        # delete file
        os.remove(file_name)

    def test_multiple_modules_multiple_domains(self):
        ini_file_contents = """
        [Application Options]
        name-servers = "1.1.1.1"
        [A]
        [AAAA]
        """
        file_name = "./test_multiple_modules_multiple_domains.ini"
        with open(file_name, "w") as f:
            f.write(ini_file_contents)
        c = "MULTIPLE -c " + file_name + " zdns-testing.com mx1.zdns-testing.com"
        name = ""

        cmd, res = self.run_zdns_multiline_output(c, name)
        self.assertSuccess(res[0], cmd, "A")
        self.assertSuccess(res[0], cmd, "AAAA")
        self.assertSuccess(res[1], cmd, "A")
        self.assertSuccess(res[1], cmd, "AAAA")
        for r in res:
            for query_type, query_res in r["results"].items():
                if query_res["data"]["resolver"] != "1.1.1.1:53":
                    self.fail("Unexpected resolver")
                if r["name"] == "zdns-testing.com" and query_type == "A":
                    self.assertEqualAnswers(r, self.ROOT_A_ANSWERS, cmd, "A")
                elif r["name"] == "zdns-testing.com" and query_type == "AAAA":
                    self.assertEqualAnswers(r, self.ROOT_AAAA_ANSWERS, cmd, "AAAA")
                elif r["name"] == "mx1.zdns-testing.com" and query_type == "A":
                    self.assertEqualAnswers(r, self.A_MX1_ZDNS_TESTING_COM_ANSWERS, cmd, "A")
                elif r["name"] == "mx1.zdns-testing.com" and query_type == "AAAA":
                    self.assertEqualAnswers(r, self.AAAA_MX1_ZDNS_TESTING_COM_ANSWERS, cmd, "AAAA")
                else:
                    self.fail("Unexpected response")
        # delete file
        cmd = f"rm {file_name}"
        subprocess.check_output(cmd, shell=True)

    def test_multiple_modules_with_special_modules(self):
        ini_file_contents = """
        [Application Options]
        name-servers = "1.1.1.1"
        [ALOOKUP]
        ipv4-lookup=false
        ipv6-lookup = true
        """
        file_name = "./test_multiple_modules_special_modules.ini"
        with open(file_name, "w") as f:
            f.write(ini_file_contents)
        c = "MULTIPLE -c " + file_name
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns_multiline_output(c, name)
        self.assertSuccess(res[0], cmd, "ALOOKUP")
        self.assertEqualALookup(res[0], self.A_LOOKUP_WWW_ZDNS_TESTING_IPv6, "ALOOKUP")
        # delete file
        cmd = f"rm {file_name}"
        subprocess.check_output(cmd, shell=True)

    def test_cname(self):
        c = "CNAME"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "CNAME")
        self.assertEqualAnswers(res, self.WWW_CNAME_ANSWERS, cmd, "CNAME")

    def test_cname_loop_iterative(self):
        c = "A --iterative"
        name = "cname-loop.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.CNAME_LOOP_ANSWERS, cmd, "A")

    def test_a_behind_cname(self):
        c = "A"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.WWW_CNAME_AND_A_ANSWERS, cmd, "A")

    def test_aaaa_behind_cname(self):
        c = "AAAA"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "AAAA")
        self.assertEqualAnswers(res, self.WWW_CNAME_AND_AAAA_ANSWERS, cmd, "AAAA")

    def test_caa(self):
        c = "CAA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "CAA")
        self.assertEqualAnswers(res, self.CAA_RECORD, cmd, key="name", query_type="CAA")

    def test_txt(self):
        c = "TXT"
        name = "test_txt.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "TXT")
        self.assertEqualAnswers(res, self.TXT_RECORD, cmd, "TXT")

    def test_a_iterative(self):
        c = "A --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_a_iterative_nxdomain(self):
        c = "A --iterative"
        name = "zdns-testing-nxdomain.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualNXDOMAIN(res, self.NXDOMAIN_ANSWER, "A")

    def test_aaaa(self):
        c = "AAAA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "AAAA")
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd, "AAAA")

    def test_aaaa_iterative(self):
        c = "AAAA --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "AAAA")
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd, "AAAA")

    def test_mx(self):
        c = "MX"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "MX")
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd, "MX")

    def test_mx_iterative(self):
        c = "MX --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "MX")
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd, "MX")

    def test_ns(self):
        c = "NS"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "NS")
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd, "NS")

    def test_ns_iterative(self):
        c = "NS --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "NS")
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd, "NS")

    def test_mx_lookup(self):
        c = "mxlookup --ipv4-lookup --ipv6-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "MXLOOKUP")
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_iterative(self):
        c = "mxlookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "MXLOOKUP")
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_ipv4(self):
        c = "mxlookup --ipv4-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "MXLOOKUP")
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_mx_lookup_ipv6(self):
        c = "mxlookup --ipv6-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "MXLOOKUP")
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV6)

    def test_mx_lookup_default(self):
        c = "mxlookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "MXLOOKUP")
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_a_lookup(self):
        c = "alookup --ipv4-lookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "ALOOKUP")
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING, "ALOOKUP")

    def test_a_lookup_iterative(self):
        c = "alookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "ALOOKUP")
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING, "ALOOKUP")

    def test_a_lookup_ipv4(self):
        c = "alookup --ipv4-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "ALOOKUP")
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING, "ALOOKUP")

    def test_a_lookup_ipv6(self):
        c = "alookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "ALOOKUP")
        self.assertEqualALookup(res, self.A_LOOKUP_IPV6_WWW_ZDNS_TESTING, "ALOOKUP")

    def test_a_lookup_default(self):
        c = "alookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "ALOOKUP")
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING, "ALOOKUP")

    def test_a_lookup_iterative_cname_loop(self):
        c = "alookup --iterative"
        name = "cname-loop.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "ALOOKUP")
        assert len(res["results"]["ALOOKUP"]["data"]) == 0

    # There exists DNS records in esrg.stanford.edu and zdns-testing.com of the form:
    # cname-chain-01.esrg.stanford.edu CNAME cname-chain-02.zdns-testing.com.
    # cname-chain-02.zdns-testing.com CNAME cname-chain-03.esrg.stanford.edu.
    # ...
    # cname-chain-11.esrg.stanford.edu CNAME cname-chain-12.zdns-testing.com.
    # cname-chain-12.zdns-testing.com A 1.2.3.4
    # We only follow 10 CNAMEs in a chain, so we should not be able to resolve the A record using cname-chain-01
    def test_a_lookup_cname_chain_too_long(self):
        c = "alookup --iterative --ipv4-lookup"
        name = "cname-chain-01.esrg.stanford.edu"
        cmd, res = self.run_zdns(c, name)
        self.assertServFail(res, cmd, "ALOOKUP")

    def test_a_lookup_cname_chain(self):
        c = "alookup --iterative --ipv4-lookup"
        name = "cname-chain-03.esrg.stanford.edu"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "ALOOKUP")
        self.assertEqualALookup(res, self.A_LOOKUP_CNAME_CHAIN_03, "ALOOKUP")

    def test_type_option_server_mode_a_lookup_ipv4(self):
        c = "A --override-name=www.zdns-testing.com --name-server-mode"
        name = "8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["results"]["A"]["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.WWW_CNAME_AND_A_ANSWERS, cmd, "A")

    def test_dig_style_type_option_server_mode_a_lookup_ipv4(self):
        c = "A 8.8.8.8 --override-name=www.zdns-testing.com --name-server-mode"
        name = ""
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["results"]["A"]["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.WWW_CNAME_AND_A_ANSWERS, cmd, "A")

    def test_name_server_mode_with_tls(self):
        c = "A 1.1.1.1 8.8.8.8 --override-name=www.zdns-testing.com --name-server-mode --tls --threads=1"
        name = ""
        cmd, res = self.run_zdns_multiline_output(c, name, append_flags=False)
        usedCloudflare = False
        usedGoogle = False
        for r in res:
            self.assertEqualAnswers(r, self.WWW_CNAME_AND_A_ANSWERS, cmd, "A")
            if r["results"]["A"]["data"]["resolver"] == "1.1.1.1:853":
                usedCloudflare = True
            elif r["results"]["A"]["data"]["resolver"] == "8.8.8.8:853":
                usedGoogle = True
            else:
                self.fail("Unexpected resolver")
        # we should setup a new TLS connection with each nameserver. This tests that that happens correctly
        self.assertTrue(usedCloudflare)
        self.assertTrue(usedGoogle)


    def test_name_server_mode_with_doh(self):
        c = "A dns.google cloudflare-dns.com --override-name=www.zdns-testing.com --name-server-mode --https --threads=1"
        name = ""
        cmd, res = self.run_zdns_multiline_output(c, name, append_flags=False)
        usedCloudflare = False
        usedGoogle = False
        for r in res:
            self.assertEqualAnswers(r, self.WWW_CNAME_AND_A_ANSWERS, cmd, "A")
            if r["results"]["A"]["data"]["resolver"] == "cloudflare-dns.com":
                usedCloudflare = True
            elif r["results"]["A"]["data"]["resolver"] == "dns.google":
                usedGoogle = True
            else:
                self.fail("Unexpected resolver")
        # we should setup a new TLS connection with each nameserver. This tests that that happens correctly
        self.assertTrue(usedCloudflare)
        self.assertTrue(usedGoogle)

    def test_doh(self):
        c = "A --https"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_tls(self):
        c = "A --tls"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_ns_lookup(self):
        c = "nslookup --ipv4-lookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "NSLOOKUP")
        self.assertEqualNSLookup(res, self.NS_LOOKUP_WWW_ZDNS_TESTING)

    def test_ns_lookup_iterative(self):
        c = "nslookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "NSLOOKUP")
        self.assertEqualALookup(res, self.NS_LOOKUP_WWW_ZDNS_TESTING, "NSLOOKUP")

    def test_ns_lookup_default(self):
        c = "nslookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "NSLOOKUP")
        self.assertEqualNSLookup(res, self.NS_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_ns_lookup_ipv4(self):
        c = "nslookup --ipv4-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "NSLOOKUP")
        self.assertEqualNSLookup(res, self.NS_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_ns_lookup_ipv6(self):
        c = "nslookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "NSLOOKUP")
        self.assertEqualNSLookup(res, self.NS_LOOKUP_IPV6_WWW_ZDNS_TESTING)

    def test_spf_lookup(self):
        c = "spf"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "SPF")
        self.assertEqual(res["results"]["SPF"]["data"], self.SPF_ANSWER["data"])

    def test_spf_lookup_iterative(self):
        c = "spf --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "SPF")
        self.assertEqual(res["results"]["SPF"]["data"], self.SPF_ANSWER["data"])

    def test_dmarc_lookup(self):
        c = "dmarc"
        name = "_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "DMARC")
        self.assertEqual(res["results"]["DMARC"]["data"], self.DMARC_ANSWER["data"])

    def test_dmarc_lookup_iterative(self):
        c = "dmarc --iterative"
        name = "_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "DMARC")
        self.assertEqual(res["results"]["DMARC"]["data"], self.DMARC_ANSWER["data"])

    def test_ptr(self):
        c = "PTR"
        name = "8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "PTR")
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd, "PTR")

    def test_ptr_iterative(self):
        c = "PTR --iterative"
        name = "8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "PTR")
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd, "PTR")

    def test_axfr(self):
        # In this test, we just check for few specific records
        # in the AXFR fetch for zonetransfer.me because the
        # records can change over time and we want to minimise
        # having to update ./axfr.json
        c = "axfr"
        name = "zonetransfer.me"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "AXFR")
        f = open("testing/axfr.json")
        axfr_answer = json.load(f)
        self.assertEqualAxfrLookup(res["results"]["AXFR"]["data"]["servers"][0]["records"],
                                   axfr_answer["data"]["servers"][0]["records"])
        f.close()

    def test_soa(self):
        c = "SOA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, c)
        self.assertEqualAnswers(res, self.SOA_ANSWERS, cmd, c, key="serial")

    def test_srv(self):
        c = "SRV"
        name = "_sip._udp.sip.voice.google.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, c)
        self.assertEqualAnswers(res, self.SRV_ANSWERS, cmd, c, key="target")

    def test_tlsa(self):
        c = "TLSA"
        name = "_25._tcp.mail.ietf.org"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, c)
        self.assertEqualAnswers(res, self.TLSA_ANSWERS, cmd, c, key="certificate")

    def test_too_big_txt_udp(self):
        c = "TXT --udp-only --name-servers=8.8.8.8:53"
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["results"]["TXT"]["status"], "TRUNCATED")
        self.assertEqual(res["results"]["TXT"]["data"]["protocol"], "udp")

    def test_too_big_txt_tcp(self):
        c = "TXT --tcp-only --name-servers=8.8.8.8:53"  # Azure DNS does not provide results.
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd, "TXT", key="answer")

    def test_too_big_txt_all(self):
        c = "TXT --name-servers=8.8.8.8:53"
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["results"]["TXT"]["data"]["protocol"], "tcp")
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd, "TXT", key="answer")

    def test_override_name(self):
        c = "A --override-name=zdns-testing.com"
        name = "notrealname.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_server_mode_a_lookup_ipv4(self):
        c = "A --override-name=zdns-testing.com --name-server-mode"
        name = "8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["results"]["A"]["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_mixed_mode_a_lookup_ipv4(self):
        c = "A --name-servers=0.0.0.0"
        name = "zdns-testing.com,8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["results"]["A"]["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

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
            self.assertSuccess(res, cmd, "A")
            address, netmask = tuple(subnet.split("/"))
            family = 1 if ip_address(address).version == 4 else 2
            original_res = res
            res = res["results"]["A"]
            self.assertEqual(address, res["data"]['additionals'][0]['csubnet']['address'])
            self.assertEqual(int(netmask), res["data"]['additionals'][0]['csubnet']["source_netmask"])
            self.assertEqual(family, res["data"]['additionals'][0]['csubnet']['family'])
            self.assertTrue("source_scope" in res["data"]['additionals'][0]['csubnet'])
            correct = [{"type": "A", "class": "IN", "answer": ip_addr, "name": "ecs-geo.zdns-testing.com"}]
            self.assertEqualAnswers(original_res, correct, cmd, "A")

    def test_edns0_nsid(self):
        name = "google.com"
        # using Google Public DNS for testing as its NSID always follows format 'gpdns-<airport code>'
        c = f"A --nsid --name-servers=8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        res = res["results"]["A"]
        self.assertTrue("nsid" in res["data"]['additionals'][0])
        self.assertTrue(res["data"]['additionals'][0]['nsid']['nsid'].startswith("gpdns-"))

    def test_edns0_ede_1(self):
        name = "dnssec.fail"
        # using Cloudflare Public DNS (1.1.1.1) that implements EDE
        c = f"A --name-servers=1.1.1.1:53"
        cmd, res = self.run_zdns(c, name)
        self.assertServFail(res, cmd, 'A')
        res = res["results"]["A"]
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
        self.assertSuccess(res, cmd, "A")
        res = res["results"]["A"]
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
        self.assertSuccess(res, cmd, "SOA")
        res = res["results"]["SOA"]
        self.assertEqual('do', res["data"]['additionals'][0]['flags'])
        self.assertEqualTypes(res, ["SOA", "RRSIG"])

    def test_cd_bit_not_set(self):
        c = "A --name-servers=8.8.8.8:53"
        name = "dnssec-failed.org"
        cmd, res = self.run_zdns(c, name)
        self.assertServFail(res, cmd, "A")

    def test_cd_bit_set(self):
        c = "A --name-servers=8.8.8.8:53 --checking-disabled"
        name = "dnssec-failed.org"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")

    def test_dnssec_validation_secure(self):
        # checks if dnssec validation is performed
        DOMAINS = [
            "cloudflare.com",
            "internetsociety.org",
            "dnssec-tools.org",
            "dnssec-deployment.org",
        ]
        for domain in DOMAINS:
            c = f"A {domain} --iterative --validate-dnssec --result-verbosity=long"
            name = "."
            cmd, res = self.run_zdns(c, name)
            self.assertSuccess(res, cmd, "A")
            dnssec = res["results"]["A"]["data"]["dnssec"]
            self.assertEqual(dnssec["status"], "Secure")
            self.assertTrue(len(dnssec["dses"]) > 0)
            self.assertTrue(len(dnssec["dnskeys"]) > 0)

    def test_dnssec_validation_secure_circular(self):
        # checks if dnssec validation can handle circular NS dependencies
        c = "A example.com --iterative --validate-dnssec --result-verbosity=long"
        name = "."
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        dnssec = res["results"]["A"]["data"]["dnssec"]
        self.assertEqual(dnssec["status"], "Secure")

    def test_dnssec_validation_insecure(self):
        # checks if dnssec validation reports insecure (not signed) zones correctly
        c = "A outlook.com --iterative --validate-dnssec --result-verbosity=long"
        name = "."
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        dnssec = res["results"]["A"]["data"]["dnssec"]
        self.assertEqual(dnssec["status"], "Insecure")
        self.assertTrue(len(dnssec["dses"]) == 0)
        self.assertTrue(len(dnssec["dnskeys"]) == 0)

    def test_dnssec_validation_insecure_cname(self):
        # checks if dnssec validation reports insecure if a CNAME is not signed
        c = "A linkedin.com --iterative --validate-dnssec --result-verbosity=long"
        name = "."
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        dnssec = res["results"]["A"]["data"]["dnssec"]
        self.assertEqual(dnssec["status"], "Insecure")

    def test_dnssec_validation_secure_cname(self):
        # checks if dnssec validation reports secure if a CNAME is signed and the target is signed
        c = "A dining.umich.edu --iterative --validate-dnssec --result-verbosity=long"
        name = "."
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        dnssec = res["results"]["A"]["data"]["dnssec"]
        self.assertEqual(dnssec["status"], "Secure")

    def test_dnssec_validation_bogus(self):
        # checks if dnssec validation reports bogus zones correctly
        DOMAINS = ["dnssec-failed.org", "rhybar.cz"]
        for domain in DOMAINS:
            c = f"A {domain} --iterative --validate-dnssec --result-verbosity=long"
            name = "."
            cmd, res = self.run_zdns(c, name)
            self.assertSuccess(res, cmd, "A")
            dnssec = res["results"]["A"]["data"]["dnssec"]
            self.assertEqual(dnssec["status"], "Bogus")

    def test_timetamps(self):
        c = "A"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        res = res["results"]["A"]
        assert "timestamp" in res
        date = datetime.datetime.strptime(res["timestamp"], "%Y-%m-%dT%H:%M:%S%z")
        self.assertTrue(date.microsecond == 0)  # microseconds should be 0 since we didn't call with --nanoseconds

    def test_timetamps_nanoseconds(self):
        c = "A --nanoseconds"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        res = res["results"]["A"]
        assert "timestamp" in res
        date = parser.parse(res["timestamp"])
        self.assertTrue(date.microsecond != 0)
        # microseconds should be non-zero since we called with --nanoseconds. There is a chance it happens to be 0,
        # but it is very unlikely. (1 in 1,000,000). Python's datetime.date's smallest unit of time is microseconds,
        # so that's why we're using this in place of nanoseconds. It should not affect the test's validity.

    # test_metadata_file test the `--metadata-file` flag which saves a summary of a scan's metadata output to a file
    def test_metadata_file(self):
        f_name = "temp-metadata.json"
        c = "A google.com yahoo.com cloudflare.com zdns-testing.com --metadata-file=" + f_name
        name = ""
        cmd, res = self.run_zdns_multiline_output(c, name)
        for r in res:
            self.assertSuccess(r, cmd, "A")
        # Attempt to read the metadata file

        metadata = None
        with open(f_name) as f:
            metadata = json.load(f)
        self.assertEqual(metadata["names"], 4)
        self.assertEqual(metadata["lookups"], 4)
        self.assertEqual(metadata["statuses"]["NOERROR"], 4)
        self.assertEqual(metadata["conf"]["Threads"], 10)
        if metadata["start_time"] is None or metadata["end_time"] is None:
            self.fail("Start or end time not recorded")
        if metadata["zdns_version"] is None:
            self.fail("ZDNS version not recorded")
        os.remove(f_name)

    def test_metadata_file_multi_module(self):
        ini_file_contents = """
        [Application Options]
        name-servers = "1.1.1.1"
        [A]
        [AAAA]
        """
        metadata_file_name = "temp-metadata-multi.json"
        ini_file_name = "test_metadata_file_multiple_modules.ini"
        with open(ini_file_name, "w") as f:
            f.write(ini_file_contents)
        c = ("MULTIPLE -c " + ini_file_name + " google.com yahoo.com cloudflare.com zdns-testing.com --metadata-file="
             + metadata_file_name)
        name = ""
        cmd, res = self.run_zdns_multiline_output(c, name)
        for r in res:
            self.assertSuccess(r, cmd, "A")
            self.assertSuccess(r, cmd, "AAAA")
        # Attempt to read the metadata file
        metadata = None
        with open(metadata_file_name) as f:
            metadata = json.load(f)
        self.assertEqual(metadata["names"], 4)
        self.assertEqual(metadata["lookups"], 8)
        self.assertEqual(metadata["statuses"]["NOERROR"], 8)
        os.remove(metadata_file_name)
        os.remove(ini_file_name)

    def test_a_lookup_domain_as_name_server_string(self):
        c = "A --name-servers=one.one.one.one"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_a_lookup_domain_name_server_with_input(self):
        c = "A"
        name = "zdns-testing.com,one.one.one.one"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")


    def test_a_lookup_IP_name_server_with_input(self):
        c = "A"
        name = "zdns-testing.com,1.1.1.1"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")
        self.assertEqual(res["results"]["A"]["data"]["resolver"], "1.1.1.1:53")

    def test_a_lookup_IP_name_server_with_input_flag_mismatch(self):
        c = "A --name-servers=1.1.1.1"
        name = "zdns-testing.com,8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")
        self.assertEqual(res["results"]["A"]["data"]["resolver"], "8.8.8.8:53", "user-supplied name server with input "
                                                                                "should take precedence")

    def test_a_lookup_IP_name_server_with_input_flag_loopback_mismatch(self):
        c = "A --name-servers=127.0.0.1"
        name = "zdns-testing.com,8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")
        self.assertEqual(res["results"]["A"]["data"]["resolver"], "8.8.8.8:53", "user-supplied name server with input "
                                                                                "should take precedence")

    def test_dnssec_option(self):
        c = "A --dnssec --name-servers=1.0.0.1"
        name = "cloudflare.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        hasRRSIG = False
        for record in res["results"]["A"]["data"]["answers"]:
            if record["type"] == "RRSIG":
                hasRRSIG = True
                break
        self.assertTrue(hasRRSIG, "DNSSEC option should return an RRSIG record")

    def test_external_lookup_cache(self):
        c = "A google.com google.com --name-servers=8.8.8.8 --threads=1"
        name = ""
        cmd, res = self.run_zdns_multiline_output(c, name, append_flags=False)
        self.assertSuccess(res[0], cmd, "A")
        self.assertSuccess(res[1], cmd, "A")
        first_duration = res[0]["results"]["A"]["duration"]
        second_duration = res[1]["results"]["A"]["duration"]
        # a bit of a hacky test, but we're checking that if we query the same domain with the same nameserver,
        # the second query has a much smaller response time than the first to show it's being cached
        self.assertTrue(first_duration / 50 > second_duration, f"Second query {second_duration} should be faster than the first {first_duration}")

    def test_lookup_all_nameservers_single_zone_iterative(self):
        """
        Test that --all-nameservers --iterative lookups work with domains whose nameservers are all in the same zone
        zdns-testing.com has nameservers ns-cloud-c1/2/3/4.googledomains.com, which are all in the .com zone and so will have their IPs
        provided as additional in the .com response
        """
        # zdns-testing.com's nameservers are all in the .com zone, so we should only have to query the .com nameservers
        c = "A zdns-testing.com --all-nameservers --iterative --timeout=60"
        cmd,res = self.run_zdns(c, "")
        self.assertSuccess(res, cmd, "A")
        # Check for layers
        self.assertIn(".", res["results"]["A"]["data"]["per_layer_responses"], "Should have the root (.) layer")
        self.assertIn("com", res["results"]["A"]["data"]["per_layer_responses"], "Should have the .com layer")
        self.assertIn("zdns-testing.com", res["results"]["A"]["data"]["per_layer_responses"], "Should have the google.com layer")
        # check for a.root-servers.net, b.root-servers.net, ... m.root-servers.net
        self.check_for_existance_of_root_and_com_nses(res)
        # check for the google.com nameservers
        actual_zdns_testing_leaf_NS_answers = []
        actual_zdns_testing_leaf_A_answers = []
        for entry in res["results"]["A"]["data"]["per_layer_responses"]["zdns-testing.com"]:
            if entry["type"] == "NS":
                actual_zdns_testing_leaf_NS_answers.append(entry)
            elif entry["type"] == "A":
                actual_zdns_testing_leaf_A_answers.append(entry)
            else:
                self.fail(f"Unexpected record type {entry['type']}")



        # Check that we have "1.2.3.4", "2.3.4.5", and "3.4.5.6" as the A records and valid NS records for all expected Leaf NSes
        if len(actual_zdns_testing_leaf_A_answers) != 4 or len(actual_zdns_testing_leaf_NS_answers) != 4:
            self.fail("Should have 4 A  and 4 NS record sets")
        expectedAnswers = ["1.2.3.4", "2.3.4.5", "3.4.5.6"]
        for entry in actual_zdns_testing_leaf_A_answers:
            actualAnswers = []
            for answer in entry["result"]["answers"]:
                actualAnswers.append(answer["answer"])
            # sort
            actualAnswers.sort()
            expectedAnswers.sort()
            self.assertEqual(actualAnswers, expectedAnswers, "Should have the expected A records")

    def check_for_existance_of_root_and_com_nses(self, res):
        actual_root_ns = []
        for entry in res["results"]["A"]["data"]["per_layer_responses"]["."]:
            actual_root_ns.append(entry["nameserver"])
        for letter in "abcdefghijklm":
            self.assertIn(f"{letter}.root-servers.net", actual_root_ns, "Should have the root nameservers")
        # check for the .com nameservers
        actual_com_nses = []
        for entry in res["results"]["A"]["data"]["per_layer_responses"]["com"]:
            actual_com_nses.append(entry["nameserver"])
        for letter in "abcdefghijklm":
            self.assertIn(f"{letter}.gtld-servers.net", actual_com_nses, "Should have the .com nameservers")

    def test_lookup_all_nameservers_multi_zone_iterative(self):
        """
        Test that --all-nameservers lookups work with domains whose nameservers have their nameservers in different zones
        In this case, example.com has a/b.iana-servers.net as nameservers, which are in the .com zone, but whose nameservers
        are dig -t NS iana-servers.com -> ns.icann.org, a/b/c.iana-servers.net. This means the .com nameservers will not
        provide the IPs in the additional section.
        """
        # example.com has nameservers in .com, .org, and .net, we'll have to iteratively figure out their IP addresses too
        c = "A example.com --all-nameservers --iterative --timeout=60"
        cmd,res = self.run_zdns(c, "")
        self.assertSuccess(res, cmd, "A")
        # Check for layers
        self.assertIn(".", res["results"]["A"]["data"]["per_layer_responses"], "Should have the root (.) layer")
        self.assertIn("com", res["results"]["A"]["data"]["per_layer_responses"], "Should have the .com layer")
        self.assertIn("example.com", res["results"]["A"]["data"]["per_layer_responses"], "Should have the example.com layer")
        self.check_for_existance_of_root_and_com_nses(res)
        # check for the example.com nameservers
        actual_example_nses = []
        for entry in res["results"]["A"]["data"]["per_layer_responses"]["example.com"]:
            actual_example_nses.append(entry["nameserver"])
        expected_example_nses = ["a.iana-servers.net", "b.iana-servers.net"]
        for ns in expected_example_nses:
            self.assertIn(ns, actual_example_nses, "Should have the example.com nameservers")

    def test_lookup_all_nameservers_external_lookup(self):
        """
        Test that --all-nameservers lookups work with external resolvers: cloudflare.com and google.com
        """
        c = "A google.com --all-nameservers --name-servers='1.1.1.1,8.8.8.8'"
        cmd,res = self.run_zdns(c, "")
        self.assertSuccess(res, cmd, "A")
        actual_resolvers = []
        for entry in res["results"]["A"]["data"]:
            actual_resolvers.append(entry["resolver"])
        expected_resolvers = ["1.1.1.1:53", "8.8.8.8:53"]
        for resolver in expected_resolvers:
            self.assertIn(resolver, actual_resolvers, "Should have the expected resolvers")



if __name__ == "__main__":
    unittest.main()
