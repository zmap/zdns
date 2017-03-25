#!/usr/bin/env python

import subprocess
import json
import unittest

class Tests(unittest.TestCase):

    maxDiff = None

    def run_zdns(self, command, name):
        c = "echo '%s' | %s" % (name, command)
        o = subprocess.check_output(c, shell=True)
        return c, json.loads(o.rstrip())

    ROOT_A = set([
        "1.2.3.4",
        "2.3.4.5",
        "3.4.5.6",
    ])

    ROOT_A_ANSWERS = [{"type":"A", "answer":x,
        "name":"zdns-testing.com"} for x in ROOT_A]

    ROOT_AAAA = set([
        "fd5a:3bce:8713::1",
        "fde6:9bb3:dbd6::2",
        "fdb3:ac76:a577::3"
    ])

    ROOT_AAAA_ANSWERS = [{"type":"AAAA", "answer":x,
        "name":"zdns-testing.com"} for x in ROOT_AAAA]

    MX_SERVERS = [
            {"answer":"mx1.zdns-testing.com", "preference":1, "type":"MX", 'name':'zdns-testing.com'},
            {"answer":"mx2.zdns-testing.com", "preference":5, "type":"MX", 'name':'zdns-testing.com'},
            {"answer":"mx1.censys.io", "preference":10, "type":"MX", 'name':'zdns-testing.com'},
    ]

    NS_SERVERS = [
            {"type": "NS", "name": "zdns-testing.com", "answer": "ns-cloud-b2.googledomains.com"},
            {"type": "NS", "name": "zdns-testing.com", "answer": "ns-cloud-b3.googledomains.com"},
            {"type": "NS", "name": "zdns-testing.com", "answer": "ns-cloud-b1.googledomains.com"},
            {"type": "NS", "name": "zdns-testing.com", "answer": "ns-cloud-b4.googledomains.com"},
    ]

    MX_LOOKUP_ANSWER = {
      "name": "zdns-testing.com",
      "status": "NOERROR",
      "data": {
        "exchanges": [
          {
            "name": "mx1.zdns-testing.com",
            "type": "MX",
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
            "preference": 5,
            "ipv4_addresses": [
              "5.6.7.8"
            ],
          },
          {
            "name": "mx1.censys.io",
            "type": "MX",
            "preference": 10,
          }
        ]
      }
    }

    def assertSuccess(self, res, cmd):
        self.assertEqual(res["status"], "NOERROR", cmd)

    def assertEqualAnswers(self, res, correct, cmd):
        for answer in res["data"]["answers"]:
            del answer["ttl"]
        self.assertEqual(sorted(res["data"]["answers"]), sorted(correct), cmd)

    def assertEqualMXLookup(self, res, correct):
        self.assertEqual(res["name"], correct["name"])
        self.assertEqual(res["status"], correct["status"])
        for exchange in res["data"]["exchanges"]:
            del exchange["ttl"]
        self.assertEqual(sorted(res["data"]["exchanges"]),
                sorted(correct["data"]["exchanges"]))

    def test_a(self):
        c = "./zdns/zdns A"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_a_iterative(self):
        c = "./zdns/zdns A --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

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


if __name__ == '__main__':
    unittest.main()
