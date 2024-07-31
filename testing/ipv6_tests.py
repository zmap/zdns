#!/usr/bin/env python3

import copy
import socket
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
    ZDNS_EXECUTABLE = "./zdns"

    ROOT_A = {"1.2.3.4", "2.3.4.5", "3.4.5.6"}

    ROOT_A_ANSWERS = [{"type": "A", "class": "IN", "answer": x,
                       "name": "zdns-testing.com"} for x in ROOT_A]

    def run_zdns(self, flags, name, executable=ZDNS_EXECUTABLE):
        flags = flags + " --threads=10"
        c = f"echo '{name}' | {executable} {flags}"
        o = subprocess.check_output(c, shell=True)
        return c, json.loads(o.rstrip())

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

    def test_a_ipv6(self):
        c = "A --6=true --name-servers=[2001:4860:4860::8888]:53"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_ipv6_unreachable(self):
        c = "A --iterative --6=true --4=false"
        name = "esrg.stanford.edu"
        cmd, res = self.run_zdns(c, name)
        # esrg.stanford.edu is hosted on NS's that do not have an IPv6 address. Therefore, this will fail.
        self.assertServFail(res, cmd)

    def test_ipv6_external_lookup_unreachable_nameserver(self):
        c = "A --6=true --4=false --name-servers=1.1.1.1"
        name = "zdns-testing.com"
        try:
            cmd, res = self.run_zdns(c, name)
        except Exception as e:
            return True
        self.fail("Should have thrown an exception, shouldn't be able to reach any IPv4 servers while in IPv6 mode")

    def test_ipv4_external_lookup_unreachable_nameserver(self):
        c = "A --6=false --4=true --name-servers=2606:4700:4700::1111"
        name = "zdns-testing.com"
        try:
            cmd, res = self.run_zdns(c, name)
        except Exception as e:
            return True
        self.fail("Should have thrown an exception, shouldn't be able to reach any IPv6 servers while in IPv4 mode")

    def test_ipv6_happy_path_external(self):
        c = "A --6=true"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_ipv6_happy_path_iterative(self):
        c = "A --6=true --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)

    def test_ipv6_happy_path_no_ipv4_iterative(self):
        c = "A --6=true --4=false --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd)
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd)


if __name__ == "__main__":
    try:
        # Attempt to create an IPv6 socket
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        print("Error: no IPv6 support on this machine, cannot test IPv6 functionality")
        exit(1)
    unittest.main()
