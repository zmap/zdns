#!/usr/bin/env python3
import json
import subprocess


ZDNS_EXECUTABLE = "./zdns"
EXPECTED_TEST_FILE = "./testing/large_scan_integration/expected_output.jsonl"

expected_test_data_lookup_domain_to_IPs = {}

# read in jsonl file expected_output.jsonl, excluding zone field
with open(EXPECTED_TEST_FILE, 'r') as f:
    for line in f:
        data = json.loads(line)
        # don't need zone info for this, that was just for uploading the DNS records to Google Cloud
        if 'zone' in data:
            del data['zone']
        ip_set = set()
        for ip in data['IPs']:
            ip_set.add(ip)
        expected_test_data_lookup_domain_to_IPs[data['domain']] = ip_set



def run_zdns(flags, executable=ZDNS_EXECUTABLE):
    input_domains = [domain for domain in expected_test_data_lookup_domain_to_IPs.keys()]
    # pipe the input domains into a call to zdns
    # return the output of zdns
    # Convert the list of domains to a single string, with each domain on a new line
    input_data = "\n".join(input_domains)

    # Start the zdns subprocess
    process = subprocess.Popen([executable] + flags, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    # Send the input data to the subprocess and get the output
    stdout, stderr = process.communicate(input=input_data.encode())
    return stdout.decode(), stderr.decode()


def get_IPs_from_actual_line_a_module(actual_line):
    if 'data' not in actual_line:
        return []
    if 'answers' not in actual_line['data']:
        return []
    IPs = []
    for answer in actual_line['data']['answers']:
        if 'answer' in answer:
            IPs.append(answer['answer'])
    return set(IPs)

def get_IPs_from_actual_line_alookup_module(actual_line):
    if 'data' not in actual_line:
        return []
    if 'ipv4_addresses' not in actual_line['data']:
        return []
    IPs = []
    for IP in actual_line['data']['ipv4_addresses']:
        IPs.append(IP)
    return set(IPs)


# verify_output takes the stdout from zdns and the module that was run and verifies that the output matches the expected output
def verify_output(stdout, module):
    # verify that the output matches the expected output
    output_lines = stdout.split("\n")
    for line in output_lines:
        if line == "":
            continue
        actual_line = json.loads(line)
        actual_domain = actual_line['name']
        assert actual_domain in expected_test_data_lookup_domain_to_IPs, f"Domain not found in expected data: {actual_domain}"

        actual_status = actual_line['status']
        if actual_status != "NOERROR":
            assert actual_status == "NOERROR", f"Status is not NOERROR: {actual_status}"
        if module == "A":
            actual_IPs = get_IPs_from_actual_line_a_module(actual_line)
        elif module == "ALOOKUP":
            actual_IPs = get_IPs_from_actual_line_alookup_module(actual_line)
        else:
            assert False, f"Invalid module: {module}"

        assert actual_IPs == set(expected_test_data_lookup_domain_to_IPs[actual_domain]), (
            f"IPs do not match for domain: {actual_domain}\n"
            f"Expected: {expected_test_data_lookup_domain_to_IPs[actual_domain]}\n"
            f"Actual: {actual_IPs}")


print("Beginning tests")
# it seems using the default of 1000 threads gets us rate-limited, downgrading to 100 threads
std_out, std_err = run_zdns(["A", "--iterative", "--threads", "100"])
verify_output(std_out, "A")
print("A module passed")
std_out, std_err = run_zdns(["ALOOKUP", "--iterative", "--threads", "100"])
verify_output(std_out, "ALOOKUP")
print("ALOOKUP module passed")
print("All tests passed")
