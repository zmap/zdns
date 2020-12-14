#!/usr/bin/env python
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
        c = u"echo '%s' | %s" % (name, command)
        o = subprocess.check_output(c, shell=True)
        return c, json.loads(o.rstrip())

    def run_zdns_multiline(self, command, names):
        d = tempfile.mkdtemp
        f = "/".join([d,"temp"])
        with open(f) as fd:
            for name in names:
                fd.writeline(name)
        command = command + " --threads=10"
        c = u"cat '%s' | %s" % (f, command)
        o = subprocess.check_output(c, shell=True)
        os.rm(f)
        return c, [json.loads(l.rstrip()) for l in o]

    ROOT_A = set([
        u"1.2.3.4",
        u"2.3.4.5",
        u"3.4.5.6",
    ])

    ROOT_A_ANSWERS = [{u"type":"A", u"class":"IN", u"answer":x,
        u"name":"zdns-testing.com"} for x in ROOT_A]

    ROOT_AAAA = set([
        u"fd5a:3bce:8713::1",
        u"fde6:9bb3:dbd6::2",
        u"fdb3:ac76:a577::3"
    ])

    ROOT_AAAA_ANSWERS = [{u"type":"AAAA", u"class":"IN", u"answer":x,
        u"name":"zdns-testing.com"} for x in ROOT_AAAA]

    MX_SERVERS = [
            {u"answer":"mx1.zdns-testing.com.", u"preference":1, u"type":"MX", u"class":"IN", 'name':'zdns-testing.com'},
            {u"answer":"mx2.zdns-testing.com.", u"preference":5, u"type":"MX", u"class":"IN", 'name':'zdns-testing.com'},
            {u"answer":"mx1.censys.io.", u"preference":10, u"type":"MX", u"class":"IN", 'name':'zdns-testing.com'},
    ]

    NS_SERVERS = [
            {u"type": u"NS", u"class": u"IN", u"name": u"zdns-testing.com",
                u"answer": u"ns-cloud-c2.googledomains.com."},
            {u"type": u"NS", u"class": u"IN", u"name": u"zdns-testing.com",
                u"answer": u"ns-cloud-c3.googledomains.com."},
            {u"type": u"NS", u"class": u"IN", u"name": u"zdns-testing.com",
                u"answer": u"ns-cloud-c1.googledomains.com."},
            {u"type": u"NS", u"class": u"IN", u"name": u"zdns-testing.com",
                u"answer": u"ns-cloud-c4.googledomains.com."},
    ]

    NXDOMAIN_ANSWER = {
        u"name": u"zdns-testing-nxdomain.com",
        u"class": u"IN",
        u"status": u"NXDOMAIN"
    }

    MX_LOOKUP_ANSWER = {
        u"name":   u"zdns-testing.com",
        u"class":  u"IN",
        u"status": u"NOERROR",
        u"data": {
            u"exchanges": [
                {
                    u"name":  u"mx1.zdns-testing.com",
                    u"type":  u"MX",
                    u"class": u"IN",
                    u"preference": 1,
                    u"ipv4_addresses": [
                        u"1.2.3.4",
                        u"2.3.4.5"
                    ],
                    u"ipv6_addresses": [
                        u"fdb3:ac76:a577::4",
                        u"fdb3:ac76:a577::5"
                    ],

                },
                {
                    u"name":  u"mx2.zdns-testing.com",
                    u"type":  u"MX",
                    U"class": u"IN",
                    u"preference": 5,
                    u"ipv4_addresses": [
                        u"5.6.7.8"
                    ],
                },
                {
                    u"name":  u"mx1.censys.io",
                    u"type":  u"MX",
                    u"class": u"IN",
                    u"preference": 10,
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
        u"name": u"www.zdns-testing.com",
        u"class": u"IN",
        u"status": u"NOERROR",
        u"data": {
            u"ipv4_addresses": [
                u"1.2.3.4",
                u"2.3.4.5",
                u"3.4.5.6"
            ],
            u"ipv6_addresses": [
                u"fde6:9bb3:dbd6::2",
                u"fd5a:3bce:8713::1",
                u"fdb3:ac76:a577::3"
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
        u"type": u"CAA",
        u"class": u"IN",
        u"name": u"zdns-testing.com",
        u"tag": u"issue",
        u"value": u"letsencrypt.org",
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
        u"type": u"SRV",
        u"class": u"IN",
        u"name": u"_sip._udp.sip.voice.google.com",
        u"port": 5060,
        u"priority": 10,
        u"target": u"sip-anycast-1.voice.google.com.",
        u"weight": 1
      },
      {
        u"type": u"SRV",
        u"class": u"IN",
        u"name": u"_sip._udp.sip.voice.google.com",
        u"port": 5060,
        u"priority": 20,
        u"target": u"sip-anycast-2.voice.google.com.",
        u"weight": 1
      }
    ]

    TLSA_ANSWERS = [
      {
        u"type": u"TLSA",
        u"class": u"IN",
        u"name": u"_25._tcp.mail.ietf.org",
        u"cert_usage": 3,
        u"selector": 1,
        u"matching_type": 1,
        u"certificate": u"0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6"
      }
    ]

    def assertSuccess(self, res, cmd):
        self.assertEqual(res["status"], u"NOERROR", cmd)

    def assertEqualAnswers(self, res, correct, cmd, key='answer'):
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
        self.assertEqual(recursiveSort(res["data"]["exchanges"]),
                recursiveSort(correct["data"]["exchanges"]))

    def assertEqualALookup(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["status"], correct["status"])
        if "ipv4_addresses" in correct["data"]:
            self.assertEqual(sorted(res["data"]["ipv4_addresses"]),
                    sorted(correct["data"]["ipv4_addresses"]))
        else:
            self.assertNotIn("ipv4_addresses", res["data"])
        if "ipv6_addresses" in correct["data"]:
            self.assertEqual(sorted(res["data"]["ipv6_addresses"]),
                    sorted(correct["data"]["ipv6_addresses"]))
        else:
            self.assertNotIn("ipv6_addresses", res["data"])

    def test_a(self):
        c = u"./zdns/zdns A"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_cname(self):
        c = u"./zdns/zdns CNAME"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.WWW_CNAME_ANSWERS, cmd)

    def test_caa(self):
        c = u"./zdns/zdns CAA"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.CAA_RECORD, cmd, key='name')

    def test_txt(self):
        c = u"./zdns/zdns TXT"
        name = u"test_txt.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.TXT_RECORD, cmd)

    def test_a_iterative(self):
        c = u"./zdns/zdns A --iterative"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_a_iterative_nxdomain(self):
        c = u"./zdns/zdns A --iterative"
        name = u"zdns-testing-nxdomain.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualNXDOMAIN(res, self.NXDOMAIN_ANSWER)

    def test_aaaa(self):
        c = u"./zdns/zdns AAAA"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd)

    def test_aaaa_iterative(self):
        c = u"./zdns/zdns AAAA --iterative"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS, cmd)

    def test_mx(self):
        c = u"./zdns/zdns MX"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd)

    def test_mx_iterative(self):
        c = u"./zdns/zdns MX --iterative"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.MX_SERVERS, cmd)

    def test_ns(self):
        c = u"./zdns/zdns NS"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd)

    def test_ns_iterative(self):
        c = u"./zdns/zdns NS --iterative"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.NS_SERVERS, cmd)

    def test_mx_lookup(self):
        c = u"./zdns/zdns mxlookup --ipv4-lookup --ipv6-lookup"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_iterative(self):
        c = u"./zdns/zdns mxlookup --ipv4-lookup --ipv6-lookup --iterative"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER)

    def test_mx_lookup_ipv4(self):
        c = u"./zdns/zdns mxlookup --ipv4-lookup"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_mx_lookup_ipv6(self):
        c = u"./zdns/zdns mxlookup --ipv6-lookup"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV6)

    def test_mx_lookup_default(self):
        c = u"./zdns/zdns mxlookup"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualMXLookup(res, self.MX_LOOKUP_ANSWER_IPV4)

    def test_a_lookup(self):
        c = u"./zdns/zdns alookup --ipv4-lookup --ipv6-lookup"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING)

    def test_a_lookup_iterative(self):
        c = u"./zdns/zdns alookup --ipv4-lookup --ipv6-lookup --iterative"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_WWW_ZDNS_TESTING)

    def test_a_lookup_ipv4(self):
        c = u"./zdns/zdns alookup --ipv4-lookup"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_a_lookup_ipv6(self):
        c = u"./zdns/zdns alookup --ipv6-lookup"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV6_WWW_ZDNS_TESTING)

    def test_a_lookup_default(self):
        c = u"./zdns/zdns alookup"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.A_LOOKUP_IPV4_WWW_ZDNS_TESTING)

    def test_ptr(self):
        c = u"./zdns/zdns PTR"
        name = u"8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd)

    def test_ptr_iterative(self):
        c = u"./zdns/zdns PTR --iterative"
        name = u"8.8.8.8"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.PTR_LOOKUP_GOOGLE_PUB, cmd)

    def test_spf(self):
        c = u"./zdns/zdns SPF"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.SPF_ANSWER["data"])

    def test_dmarc(self):
        c = u"./zdns/zdns DMARC"
        name = u"_dmarc.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqual(res["data"], self.DMARC_ANSWER["data"])

    def test_soa(self):
        c = u"./zdns/zdns SOA"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.SOA_ANSWERS, cmd, key='serial')

    def test_srv(self):
        c = u"./zdns/zdns SRV"
        name = u"_sip._udp.sip.voice.google.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.SRV_ANSWERS, cmd, key='target')

    def test_tlsa(self):
        c = u"./zdns/zdns TLSA"
        name = u"_25._tcp.mail.ietf.org"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.TLSA_ANSWERS, cmd, key='certificate')

    def test_too_big_txt_udp(self):
        c = u"./zdns/zdns TXT --udp-only"
        name = u"large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEquals(res["status"], "TRUNCATED")
        self.assertEquals(res["data"]["protocol"], "udp")

    def test_too_big_txt_tcp(self):
        c = u"./zdns/zdns TXT --tcp-only"
        name = u"large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd,
                key="answer")

    def test_too_big_txt_all(self):
        c = u"./zdns/zdns TXT"
        name = u"large-text.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEquals(res["data"]["protocol"], "tcp")
        self.assertEqualAnswers(res, self.TCP_LARGE_TXT_ANSWERS, cmd,
                key="answer")

    def test_override_name(self):
        c = u"./zdns/zdns A --override-name=zdns-testing.com"
        name = u"notrealname.com"
        cmd, res = self.run_zdns(c, name)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_server_mode_a_lookup_ipv4(self):
        c = u"./zdns/zdns A --override-name=zdns-testing.com --name-server-mode"
        name = u"8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_mixed_mode_a_lookup_ipv4(self):
        c = u"./zdns/zdns A --name-servers=0.0.0.0"
        name = u"zdns-testing.com,8.8.8.8:53"
        cmd, res = self.run_zdns(c, name)
        self.assertEqual(res["data"]["resolver"], "8.8.8.8:53")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)


if __name__ == '__main__':
    unittest.main()
