#!/usr/bin/env python3
import select
import subprocess

ZDNS_EXECUTABLE = "./zdns"
LIST_OF_DOMAINS_FILE = "./top-1k.csv"

# Validate a line of output from zdns
# Example output line:
#{"data":{"answers":[{"answer":"104.16.25.14","class":"IN","name":"www.patreon.com","ttl":300,"type":"A"},{"answer":"104.16.24.14","class":"IN","name":"www.patreon.com","ttl":300,"type":"A"}],"protocol":"udp","resolver":"108.162.193.149:53"},"name":"www.patreon.com","status":"NOERROR","timestamp":"2024-05-24T16:56:16Z"}
#{"data":{"answers":[{"answer":"ds-ats.member.g02.yahoodns.net.","class":"IN","name":"login.yahoo.com","ttl":300,"type":"CNAME"}],"protocol":"udp","resolver":"68.180.131.16:53"},"name":"login.yahoo.com","status":"NOERROR","timestamp":"2024-05-24T16:56:16Z"}
#{"data":{"protocol":"udp","resolver":"192.203.230.10:53"},"name":"discord.com","status":"TIMEOUT","timestamp":"2024-05-24T16:56:24Z"}

class ZDNSScanTest:
    timeouts = 0
    correct_answers = 0
    incorrect_answers = 0
    def __init__(self):

def validate_zdns_output_line(output_line):
    # Parse the JSON output line
    # Need to determine if the line encountered a timeout, then

# Run zdns on a list of domains
def run_zdns(input_domains, flags, executable=ZDNS_EXECUTABLE):
    # pipe the input domains into a call to zdns
    # return the output of zdns
    # Convert the list of domains to a single string, with each domain on a new line
    input_data = "\n".join(input_domains)

    # Start the zdns subprocess
    print(flags)
    process = subprocess.Popen([executable] + flags, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Send the input data to the subprocess and get the output
    process.stdin.write(input_data.encode())
    process.stdin.close()

    while True:
        # Use select to wait for data to become available
        reads = [process.stdout.fileno(), process.stderr.fileno()]
        ret = select.select(reads, [], [])

        for fd in ret[0]:
            if fd == process.stdout.fileno():
                validate_zdns_output_line(process.stdout.readline().decode())
            if fd == process.stderr.fileno():
                print("stderr: " + process.stderr.readline().decode())
        if process.poll() is not None:
            break
    # # Convert the output data from bytes to string
    # stdout_data = process.stdout.readline().decode()
    # stderr_data = process.stderr.readline().decode()

    # Return the output data
    # return stdout_data, stderr_data

if __name__ == '__main__':
    # Read the list of domains from the file
    with open(LIST_OF_DOMAINS_FILE, 'r') as f:
        domains = f.read().splitlines()

    # Run zdns on the list of domains
    print(domains[0])
    run_zdns(domains[9:10], ["A", "--iterative"])
