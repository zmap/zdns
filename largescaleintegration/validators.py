import os
from typing import List

import requests
import socket
import concurrent.futures
import asyncio
from pyppeteer import launch
import select
import subprocess
import unittest
import json

ZDNS_EXECUTABLE = "./zdns"


# async def can_visit_with_puppeteer(domain: str, ip_address: str) -> bool:
#     browser = await launch(headless=True, ignoreHTTPSErrors=True)
#     page = await browser.newPage()
#
#     try:
#         await page.setExtraHTTPHeaders({'Host': domain,
#                                         'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15'})
#         response = await page.goto(f"https://{ip_address}", {'waitUntil': 'networkidle0'})
#
#         # Check if the navigation was successful (status code 200)
#         if response.ok:
#             # Take a screenshot of the page
#             await page.screenshot({'path': '~/zdns/zdns-working/largescaleintegration/screenshot.png'})
#             return True
#         else:
#             return False
#
#     except Exception as e:
#         print(f"An error occurred with domain {domain} at IP {ip_address}: {e}")
#         return False
#     finally:
#         await browser.close()


def can_request_successfully(domain: str, ip: str) -> bool:
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15"
    headers = {"Host": domain, "User-Agent": user_agent}
    try:
        response = requests.get("https://" + ip, headers=headers, verify=False, timeout=5)
        if response.status_code < 400:
            return True
        print(f"Failed to request {domain} with requests with status code {response.status_code}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Failed to request {domain} with requests with error {e}")
        return False


def can_automatically_visit(domain: str, ip: str):
    if can_request_successfully(domain, ip):
        return (domain, ip, 0)
    # if domain == "arca.live":
    #     ip = "1.1.1.1"
    # if await can_visit_with_puppeteer(domain, ip):
    #     return 1
    return (domain, ip, -1)


def get_ip_address(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        print(f"Resolved {domain} to {ip}")
        return (domain, ip)
    except socket.gaierror:
        return (domain, "")


def run_zdns(input_domains, flags, executable=ZDNS_EXECUTABLE):
    # pipe the input domains into a call to zdns
    # return the output of zdns
    # Convert the list of domains to a single string, with each domain on a new line
    input_data = "\n".join(input_domains)

    # Start the zdns subprocess
    print(flags)
    process = subprocess.Popen([executable] + flags, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    # Send the input data to the subprocess and get the output
    process.stdin.write(input_data.encode())
    process.stdin.close()

    output = []

    while True:
        # Use select to wait for data to become available
        reads = [process.stdout.fileno(), process.stderr.fileno()]
        ret = select.select(reads, [], [])

        for fd in ret[0]:
            if fd == process.stdout.fileno():
                output.append(process.stdout.readline().decode())
            if fd == process.stderr.fileno():
                print("stderr: " + process.stderr.readline().decode())
        if process.poll() is not None:
            break

    return output


def get_requestable_domains(domains: List[str]) -> List[str]:
    domain_ip_pairs = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = [executor.submit(get_ip_address, domain) for domain in domains]

        for future in concurrent.futures.as_completed(results):
            domain, ip = future.result()
            domain_ip_pairs.append((domain, ip))

    successes_requests = []
    successes_puppeteer = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = [executor.submit(can_automatically_visit, domain, ip) for domain, ip in domain_ip_pairs]

        for future in concurrent.futures.as_completed(results):
            domain, ip, result = future.result()
            if result == 0:
                successes_requests.append(domain)
            # elif result == 1:
            #     successes_puppeteer.append(domain)
            elif result == -1:
                print(f"Failed to visit {domain} with either requests or puppeteer")

    print(f"Successfully requested {len(successes_requests)} out of {len(domains)} domains with requests")
    # print(f"Successfully visited {len(successes_puppeteer)} out of {len(domains)} domains with puppeteer")
    print("Requests successes:", successes_requests)
    # print("Puppeteer successes:", successes_puppeteer)
    print("Failures:", set(domains) - set(successes_requests) - set(successes_puppeteer))
    return successes_requests


# Returns a list of tuples, where each tuple contains the domain and the IP address ZDNS returned. A domain could have
# multiple IP addresses, so there could be multiple tuples for a single domain.
def get_zdns_results_a(domains: List[str]) -> List[tuple[str, str]]:
    zdns_output = run_zdns(domains, ["A", "--iterative"])
    domain_ip_pairs = []
    for line in zdns_output:
        if "answer" in line and "TIMEOUT" not in line and "CNAME" not in line:
            domain = line.split('"name":"')[1].split('"')[0]
            ip = line.split('"answer":"')[1].split('"')[0]
            domain_ip_pairs.append((domain, ip))
        else:
            print(f"Failed to resolve domain: {line}")
    return domain_ip_pairs


def get_zdns_results_a_lookup(domains: List[str]) -> List[tuple[str, str]]:
    zdns_output = run_zdns(domains, ["ALOOKUP", "--iterative"])
    domain_ip_pairs = []
    for line in zdns_output:
        if "ipv4_addresses" in line and "TIMEOUT" not in line:
            # use jq to parse the JSON output, to extract data.ipv4_addresses
            line_data = json.loads(line)
            data = line_data.get('data')
            ipv4_addresses = data.get('ipv4_addresses') if data else None
            if ipv4_addresses:
                for ip in ipv4_addresses:
                    domain = line_data.get('name')
                    domain_ip_pairs.append((domain, ip))
        else:
            print(f"Failed to resolve domain: {line}")
    return domain_ip_pairs


class TestZDNS(unittest.TestCase):
    def setUp(self):
        with open("top-1k.csv", "r") as f:
            domains = f.read().splitlines()

        domains = domains[0:100]
        # These are those domains which we can successfully request using the requests library directed at an IP address
        # This excludes domains that use some form of DDoS mitigation, such as Cloudflare, which have more sophisticated
        # bot detection
        self.known_reachable_domains = get_requestable_domains(domains)

    def test_zdns_a(self):
        zdns = get_zdns_results_a(self.known_reachable_domains)
        for domain, ip in zdns:
            self.assertTrue(can_request_successfully(domain, ip),
                            "ZDNS resolved a domain to an IP address that will not respond to requests for the given domain")

    def test_zdns_a_lookup(self):
        zdns = get_zdns_results_a_lookup(self.known_reachable_domains)
        for domain, ip in zdns:
            self.assertTrue(can_request_successfully(domain, ip), "ZDNS resolved a domain to an IP address that will not respond to requests for the given domain")


if __name__ == '__main__':
    unittest.main()
