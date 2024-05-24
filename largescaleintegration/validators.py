from typing import List

import requests
import socket
import concurrent.futures
import asyncio
from pyppeteer import launch


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
            print(f"Failed to request {domain} with requests with status code {response.status_code}")
            return True
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


# Returns a list of tuples, where each tuple contains the domain and the IP address ZDNS returned. A domain could have
# multiple IP addresses, so there could be multiple tuples for a single domain.
def get_zdns_results(domains: List[str]) -> List[tuple[str, str]]:
    return []


def main():
    # read in domains file
    with open("top-1k.csv", "r") as f:
        domains = f.read().splitlines()


    # Testing, only use the first 10 domains
    domains = domains[0:100]
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
            elif result == 1:
                successes_puppeteer.append(domain)
            elif result == -1:
                print(f"Failed to visit {domain} with either requests or puppeteer")

    print(f"Successfully requested {len(successes_requests)} out of {len(domains)} domains with requests")
    print(f"Successfully visited {len(successes_puppeteer)} out of {len(domains)} domains with puppeteer")
    print("Requests successes:", successes_requests)
    print("Puppeteer successes:", successes_puppeteer)
    print("Failures:", set(domains) - set(successes_requests) - set(successes_puppeteer))

main()