#!/usr/bin/env python

import subprocess
import json
import unittest

class Tests(unittest.TestCase):

    def run_zdns(self, command, name):
        c = "echo '%s' | %s" % (name, command)
        o = subprocess.check_output(c, shell=True)
        return json.loads(o.rstrip())

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

    def assertSuccess(self, res):
        self.assertEqual(res["status"], "NOERROR")

    def assertEqualAnswers(self, res, correct):
        for answer in res["data"]["answers"]:
            del answer["ttl"]
        self.assertEqual(sorted(res["data"]["answers"]), sorted(correct))

    def test_a(self):
        c = "./zdns/zdns A"
        name = "zdns-testing.com"
        res = self.run_zdns(c, name)
        self.assertSuccess(res)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS)

    def test_a_iterative(self):
        c = "./zdns/zdns A --iterative"
        name = "zdns-testing.com"
        res = self.run_zdns(c, name)
        self.assertSuccess(res)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS)

    def test_aaaa(self):
        c = "./zdns/zdns AAAA"
        name = "zdns-testing.com"
        res = self.run_zdns(c, name)
        self.assertSuccess(res)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS)

    def test_aaaa_iterative(self):
        c = "./zdns/zdns AAAA --iterative"
        name = "zdns-testing.com"
        res = self.run_zdns(c, name)
        self.assertSuccess(res)
        self.assertEqualAnswers(res, self.ROOT_AAAA_ANSWERS)


if __name__ == '__main__':
    unittest.main()
