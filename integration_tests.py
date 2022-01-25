#!/usr/bin/env python3

import copy
import subprocess
import json
import unittest
import tempfile

def recursiveSort(obj):

    def listSort(l):
        assert(type(l) == type(list()))
        new_list = []
        for item in l:
            item = recursiveSort(item)
            new_list.append(item)
        if len(new_list) > 0 and type(new_list[0]) == dict:
            return sorted(new_list, key=lambda x: x["name"])
        else:
            return sorted(new_list)

    def dictSort(d):
        assert(type(d) == type(dict()))
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

    def run_zdns(self, command, name):
        command = command + " --threads=10"
        c = "echo '%s' | %s" % (name, command)
        o = subprocess.check_output(c, shell=True)
        return c, json.loads(o.rstrip())

    def run_zdns_multiline(self, command, names):
        d = tempfile.mkdtemp
        f = "/".join([d,"temp"])
        with open(f) as fd:
            for name in names:
                fd.writeline(name)
        command = command + " --threads=10"
        c = "cat '%s' | %s" % (f, command)
        o = subprocess.check_output(c, shell=True)
        os.rm(f)
        return c, [json.loads(l.rstrip()) for l in o]

    ROOT_A = set([
        "1.2.3.4",
        "2.3.4.5",
        "3.4.5.6",
    ])

    ROOT_A_ANSWERS = [{"type":"A", "class":"IN", "answer":x,
        "name":"zdns-testing.com"} for x in ROOT_A]

    ROOT_AAAA = set([
        "fd5a:3bce:8713::1",
        "fde6:9bb3:dbd6::2",
        "fdb3:ac76:a577::3"
    ])

    ROOT_AAAA_ANSWERS = [{"type":"AAAA", "class":"IN", "answer":x,
        "name":"zdns-testing.com"} for x in ROOT_AAAA]

    MX_SERVERS = [
            {"answer":"mx1.zdns-testing.com.", "preference":1, "type":"MX", "class":"IN", 'name':'zdns-testing.com'},
            {"answer":"mx2.zdns-testing.com.", "preference":5, "type":"MX", "class":"IN", 'name':'zdns-testing.com'},
            {"answer":"mx1.censys.io.", "preference":10, "type":"MX", "class":"IN", 'name':'zdns-testing.com'},
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
        "name":   "zdns-testing.com",
        "class":  "IN",
        "status": "NOERROR",
        "data": {
            "exchanges": [
                {
                    "name":  "mx1.zdns-testing.com",
                    "type":  "MX",
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
                    "name":  "mx2.zdns-testing.com",
                    "type":  "MX",
                    "class": "IN",
                    "preference": 5,
                    "ipv4_addresses": [
                        "5.6.7.8"
                    ],
                },
                {
                    "name":  "mx1.censys.io",
                    "type":  "MX",
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

    PTR_LOOKUP_GOOGLE_PUB = [
      {
        "type":"PTR",
        "class":"IN",
        "name":"8.8.8.8.in-addr.arpa",
        "answer":"dns.google."
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
      }
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
        "certificate": "0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6"
      }
    ]

    def assertSuccess(self, res, cmd):
        self.assertEqual(res["status"], "NOERROR", cmd)

    def assertEqualAnswers(self, res, correct, cmd, key="answer"):
        self.assertIn("answers", res["data"])
        for answer in res["data"]["answers"]:
            del answer["ttl"]
        a = sorted(res["data"]["answers"], key=lambda x: x[key])
        b = sorted(correct, key=lambda x: x[key])
        helptext = "%s\nExpected:\n%s\n\nActual:\n%s" % (cmd,
                json.dumps(b,indent=4), json.dumps(a,indent=4))
        def _lowercase(obj):
            """ Make dictionary lowercase """
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "name":
                        obj[k] = v.lower()
                    else:
                        _lowercase(v)
        self.assertEqual(_lowercase(a), _lowercase(b), helptext)

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

    def test_a(self):
        c = "./zdns/zdns A"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_cname(self):
        c = "./zdns/zdns CNAME"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.WWW_CNAME_ANSWERS, cmd)

    def test_caa(self):
        c = "./zdns/zdns CAA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.CAA_RECORD, cmd, key="name")

    def test_txt(self):
        c = "./zdns/zdns TXT"
        name = "test_txt.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.TXT_RECORD, cmd)

    def test_a_iterative(self):
        c = "./zdns/zdns A --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_a_iterative_nxdomain(self):
        c = "./zdns/zdns A --iterative"
        name = "zdns-testing-nxdomain.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualNXDOMAIN(res, self.NXDOMAIN_ANSWER)

    def test_aaaa(self):
        c = "./zdns/zdns AAAA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd)

    def test_aaaa_iterative(self):
        c = "./zdns/zdns AAAA --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd)

    def test_mx(self):
        c = "./zdns/zdns MX"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd)

    def test_mx_iterative(self):
        c = "./zdns/zdns MX --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd)

    def test_ns(self):
        c = "./zdns/zdns NS"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd)

    def test_ns_iterative(self):
        c = "./zdns/zdns NS --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd)

    def test_mx_lookup(self):
        c = "./zdns/zdns mxlookup --ipv4-lookup --ipv6-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_iterative(self):
        c = "./zdns/zdns mxlookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_ipv4(self):
        c = "./zdns/zdns mxlookup --ipv4-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_mx_lookup_ipv6(self):
        c = "./zdns/zdns mxlookup --ipv6-lookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV6)

    def test_mx_lookup_default(self):
        c = "./zdns/zdns mxlookup"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_a_lookup(self):
        c = "./zdns/zdns alookup --ipv4-lookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING)

    def test_a_lookup_iterative(self):
        c = "./zdns/zdns alookup --ipv4-lookup --ipv6-lookup --iterative"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING)

    def test_a_lookup_ipv4(self):
        c = "./zdns/zdns alookup --ipv4-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_a_lookup_ipv6(self):
        c = "./zdns/zdns alookup --ipv6-lookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV6_WWW_ZDNS_TESTING)

    def test_a_lookup_default(self):
        c = "./zdns/zdns alookup"
        name = "www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_ptr(self):
        c = "./zdns/zdns PTR"
        name = "8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd)

    def test_ptr_iterative(self):
        c = "./zdns/zdns PTR --iterative"
        name = "8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd)

    def test_spf(self):
        c = "./zdns/zdns SPF"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.SPF_ANSWER["data"])

    def test_dmarc(self):
        c = "./zdns/zdns DMARC"
        name = "_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.DMARC_ANSWER["data"])

    def test_soa(self):
        c = "./zdns/zdns SOA"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.SOA_ANSWERS, cmd, key="serial")

    def test_srv(self):
        c = "./zdns/zdns SRV"
        name = "_sip._udp.sip.voice.google.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.SRV_ANSWERS, cmd, key="target")

    def test_tlsa(self):
        c = "./zdns/zdns TLSA"
        name = "_25._tcp.mail.ietf.org"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.TLSA_ANSWERS, cmd, key="certificate")

    def test_too_big_txt_udp(self):
        c = "./zdns/zdns TXT --udp-only --name-servers=8.8.8.8:53"
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["status"], "TRUNCATED")
        self.assertEqual(res["data"]["protocol"], "udp")

    def test_too_big_txt_tcp(self):
        c = "./zdns/zdns TXT --tcp-only --name-servers=8.8.8.8:53" # Azure DNS does not provide results.
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd, key="answer")

    def test_too_big_txt_all(self):
        c = "./zdns/zdns TXT --name-servers=8.8.8.8:53"
        name = "large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["protocol"], "tcp")
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd, key="answer")

    def test_override_name(self):
        c = "./zdns/zdns A --override-name=zdns-testing.com"
        name = "notrealname.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_server_mode_a_lookup_ipv4(self):
        c = "./zdns/zdns A --override-name=zdns-testing.com --name-server-mode"
        name = "8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_mixed_mode_a_lookup_ipv4(self):
        c = "./zdns/zdns A --name-servers=0.0.0.0"
        name = "zdns-testing.com,8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)


    def test_local_addr_interface_warning(self):
        c = u"./zdns/zdns A --local-addr 192.168.1.5 --local-interface en0"
        name = u"zdns-testing.com"
        command = c + " --threads=10 ; exit 0"
        c = u"echo '%s' | %s" % (name, command)
        o = subprocess.check_output(c, shell=True, stderr=subprocess.STDOUT)
        self.assertEqual("Both --local-addr and --local-interface specified." in o, True)


if __name__ == "__main__":
    unittest.main()
