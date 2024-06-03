## Large Scan Integration Test
This script runs a large scan integration test for the A and ALOOKUP modules of zdns.

10,000 domains were set up in the zdns-testing.com namespace, 5k for `subdomain0.zdns-testing.com` and 5k for
`subdomain1.subdomain0.zdns-testing.com`, with the following structure:
```
a.subdomain0.zdns-testing.com -> "0.0.0.0", "0.0.0.1"
b.subdomain0.zdns-testing.com -> "0.0.0.2", "0.0.0.3"
...
gjh.subdomain0.zdns-testing.com -> "0.0.39.14", "0.0.39.15"

a.subdomain1.subdomain0.zdns-testing.com -> "0.1.0.0", "0.1.0.1"
b.subdomain1.subdomain0.zdns-testing.com -> "0.1.0.2", "0.1.0.3" 
...
gjh.subdomain1.subdomain0.zdns-testing.com -> "0.1.39.14", "0.1.39.15"
```

1. These two subdomains (`subdomain1.subdomain0` and `subdomain0`) have unique nameservers compared to eachother and to 
`zdns-testing.com`
2. NS records were set up to point from `zdns-testing.com` -> `subdomain0.zdns-testing.com` and
`subdomain0.zdns-testing.com` -> `subdomain1.subdomain0.zdns-testing.com`.

This should enable us to test the iterative resolution of zdns in a reproducible and reliable manner.
