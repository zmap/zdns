#!/usr/bin/env python3

import socket
import subprocess
import json
import unittest


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

    def test_a_ipv6(self):
        c = "A --name-servers='[2001:4860:4860::8888]:53'"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_ipv6_unreachable(self):
        c = "A --iterative --6"
        name = "esrg.stanford.edu"
        cmd, res = self.run_zdns(c, name)
        # esrg.stanford.edu is hosted on NS's that do not have an IPv6 address. Therefore, the lookup won't get sufficient glue records to resolve the query.
        self.assertEqual(res["results"]["A"]["status"], "NONEEDEDGLUE", cmd)

    def test_ipv6_external_lookup_unreachable_nameserver(self):
        c = "A --6 --name-servers=1.1.1.1"
        name = "zdns-testing.com"
        try:
            cmd, res = self.run_zdns(c, name)
        except Exception as e:
            return True
        self.fail("Should have thrown an exception, shouldn't be able to reach any IPv4 servers while in IPv6 mode")

    def test_ipv4_external_lookup_unreachable_nameserver(self):
        c = "A --4 --name-servers=2606:4700:4700::1111"
        name = "zdns-testing.com"
        try:
            cmd, res = self.run_zdns(c, name)
        except Exception as e:
            return True
        self.fail("Should have thrown an exception, shouldn't be able to reach any IPv6 servers while in IPv4 mode")

    def test_ipv6_happy_path_external(self):
        c = "A --6"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_ipv6_happy_path_iterative(self):
        c = "A --6 --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")

    def test_ipv6_happy_path_no_ipv4_iterative(self):
        c = "A --6 --iterative"
        name = "zdns-testing.com"
        cmd, res = self.run_zdns(c, name)
        self.assertSuccess(res, cmd, "A")
        self.assertEqualAnswers(res, self.ROOT_A_ANSWERS, cmd, "A")


if __name__ == "__main__":
    try:
        # Attempt to create an IPv6 socket
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        print("Error: no IPv6 support on this machine, cannot test IPv6 functionality")
        exit(1)
    unittest.main()
