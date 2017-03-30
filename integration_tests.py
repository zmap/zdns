#!/usr/bin/env python

import subprocess
import json
import unittest

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
        return sorted(d)

    if type(obj) == type(list()):
        return listSort(obj)

    elif type(obj) == type(dict()):
        return dictSort(obj)
    else:
        return obj

class Tests(unittest.TestCase):

    maxDiff = None

    def run_zdns(self, command, name):
        c = u"echo '%s' | %s" % (name, command)
        o = subprocess.check_output(c, shell=True)
        return c, json.loads(o.rstrip())

    ROOT_A = set([
        u"1.2.3.4",
        u"2.3.4.5",
        u"3.4.5.6",
    ])

    ROOT_A_ANSWERS = [{u"type":"A", u"answer":x,
        u"name":"zdns-testing.com"} for x in ROOT_A]

    ROOT_AAAA = set([
        u"fd5a:3bce:8713::1",
        u"fde6:9bb3:dbd6::2",
        u"fdb3:ac76:a577::3"
    ])

    ROOT_AAAA_ANSWERS = [{u"type":"AAAA", u"answer":x,
        u"name":"zdns-testing.com"} for x in ROOT_AAAA]

    MX_SERVERS = [
            {u"answer":"mx1.zdns-testing.com", u"preference":1, u"type":"MX", 'name':'zdns-testing.com'},
            {u"answer":"mx2.zdns-testing.com", u"preference":5, u"type":"MX", 'name':'zdns-testing.com'},
            {u"answer":"mx1.censys.io", u"preference":10, u"type":"MX", 'name':'zdns-testing.com'},
    ]

    NS_SERVERS = [
            {u"type": u"NS", u"name": u"zdns-testing.com", u"answer": u"ns-cloud-b2.googledomains.com"},
            {u"type": u"NS", u"name": u"zdns-testing.com", u"answer": u"ns-cloud-b3.googledomains.com"},
            {u"type": u"NS", u"name": u"zdns-testing.com", u"answer": u"ns-cloud-b1.googledomains.com"},
            {u"type": u"NS", u"name": u"zdns-testing.com", u"answer": u"ns-cloud-b4.googledomains.com"},
    ]

    MX_LOOKUP_ANSWER = {
      u"name": u"zdns-testing.com",
      u"status": u"NOERROR",
      u"data": {
        u"exchanges": [
          {
            u"name": u"mx1.zdns-testing.com",
            u"type": u"MX",
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
            u"name": u"mx2.zdns-testing.com",
            u"type": u"MX",
            u"preference": 5,
            u"ipv4_addresses": [
              u"5.6.7.8"
            ],
          },
          {
            u"name": u"mx1.censys.io",
            u"type": u"MX",
            u"preference": 10,
          }
        ]
      }
    }

    ALOOKUP_WWW_ZDNS_TESTING = {
      u"name": u"www.zdns-testing.com",
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

    def assertSuccess(self, res, cmd):
        self.assertEqual(res["status"], u"NOERROR", cmd)

    def assertEqualAnswers(self, res, correct, cmd):
        for answer in res["data"]["answers"]:
            del answer["ttl"]
        self.assertEqual(sorted(res["data"]["answers"]), sorted(correct), cmd)

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
        self.assertEqual(sorted(res["data"]["ipv4_addresses"]),
                sorted(correct["data"]["ipv4_addresses"]))
        self.assertEqual(sorted(res["data"]["ipv6_addresses"]),
                sorted(correct["data"]["ipv6_addresses"]))

    def test_a(self):
        c = u"./zdns/zdns A"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_a_iterative(self):
        c = u"./zdns/zdns A --iterative"
        name = u"zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

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

    def test_a_lookup(self):
        c = u"./zdns/zdns alookup --ipv4-lookup --ipv6-lookup"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.ALOOKUP_WWW_ZDNS_TESTING)

    def test_a_lookup_iterative(self):
        c = u"./zdns/zdns alookup --ipv4-lookup --ipv6-lookup --iterative"
        name = u"www.zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualALookup(res, self.ALOOKUP_WWW_ZDNS_TESTING)


if __name__ == '__main__':
    unittest.main()
