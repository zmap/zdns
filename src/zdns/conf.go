/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package zdns

import "net"

const (
	GoogleDoHDomainName     = "dns.google"
	cloudflareDNSDomainName = "one.one.one.one"
	CloudflareDoHDomainName = "cloudflare-dns.com"
)

type TargetedDomain struct {
	Domain      string   `json:"name"`
	Nameservers []string `json:"nameservers"`
}

type Status string

const (
	// Standardized RCODE
	StatusNoError   Status = "NOERROR" // No Error
	StatusFormErr   Status = "FORMERR" // Format Error
	StatusServFail  Status = "SERVFAIL"
	StatusNXDomain  Status = "NXDOMAIN"
	StatusRefused   Status = "REFUSED"
	StatusTruncated Status = "TRUNCATED"

	StatusError        Status = "ERROR"
	StatusAuthFail     Status = "AUTHFAIL"
	StatusNoRecord     Status = "NORECORD"
	StatusBlacklist    Status = "BLACKLIST"
	StatusNoOutput     Status = "NO_OUTPUT"
	StatusNoAnswer     Status = "NO_ANSWER"
	StatusIllegalInput Status = "ILLEGAL_INPUT"
	StatusTimeout      Status = "TIMEOUT"
	StatusIterTimeout  Status = "ITERATIVE_TIMEOUT"
	StatusNoAuth       Status = "NOAUTH"
	StatusNoNeededGlue Status = "NONEEDEDGLUE" // When a nameserver is authoritative for itself and the parent nameserver doesn't provide the glue to look it up
	StatusCircular     Status = "CIRCULAR"     // When circular query dependencies are detected
)

func isStatusRetryable(status Status) bool {
	switch status {
	case StatusServFail, StatusNXDomain, StatusRefused, StatusTruncated, StatusError, StatusTimeout, StatusIterTimeout:
		return true
	}
	return false
}

var RootServersV4 = []NameServer{
	{IP: net.ParseIP("198.41.0.4"), Port: 53, DomainName: "a.root-servers.net"},     // A
	{IP: net.ParseIP("170.247.170.2"), Port: 53, DomainName: "b.root-servers.net"},  // B - Changed several times, this is current as of July '24
	{IP: net.ParseIP("192.33.4.12"), Port: 53, DomainName: "c.root-servers.net"},    // C
	{IP: net.ParseIP("199.7.91.13"), Port: 53, DomainName: "d.root-servers.net"},    // D
	{IP: net.ParseIP("192.203.230.10"), Port: 53, DomainName: "e.root-servers.net"}, // E
	{IP: net.ParseIP("192.5.5.241"), Port: 53, DomainName: "f.root-servers.net"},    // F
	{IP: net.ParseIP("192.112.36.4"), Port: 53, DomainName: "g.root-servers.net"},   // G
	{IP: net.ParseIP("198.97.190.53"), Port: 53, DomainName: "h.root-servers.net"},  // H
	{IP: net.ParseIP("192.36.148.17"), Port: 53, DomainName: "i.root-servers.net"},  // I
	{IP: net.ParseIP("192.58.128.30"), Port: 53, DomainName: "j.root-servers.net"},  // J
	{IP: net.ParseIP("193.0.14.129"), Port: 53, DomainName: "k.root-servers.net"},   // K
	{IP: net.ParseIP("199.7.83.42"), Port: 53, DomainName: "l.root-servers.net"},    // L
	{IP: net.ParseIP("202.12.27.33"), Port: 53, DomainName: "m.root-servers.net"},   // M
}

var RootServersV6 = []NameServer{
	{IP: net.ParseIP("2001:503:ba3e::2:30"), Port: 53, DomainName: "a.root-servers.net"}, // A
	{IP: net.ParseIP("2801:1b8:10::b"), Port: 53, DomainName: "b.root-servers.net"},      // B
	{IP: net.ParseIP("2001:500:2::c"), Port: 53, DomainName: "c.root-servers.net"},       // C
	{IP: net.ParseIP("2001:500:2d::d"), Port: 53, DomainName: "d.root-servers.net"},      // D
	{IP: net.ParseIP("2001:500:a8::e"), Port: 53, DomainName: "e.root-servers.net"},      // E
	{IP: net.ParseIP("2001:500:2f::f"), Port: 53, DomainName: "f.root-servers.net"},      // F
	{IP: net.ParseIP("2001:500:12::d0d"), Port: 53, DomainName: "g.root-servers.net"},    // G
	{IP: net.ParseIP("2001:500:1::53"), Port: 53, DomainName: "h.root-servers.net"},      // H
	{IP: net.ParseIP("2001:7fe::53"), Port: 53, DomainName: "i.root-servers.net"},        // I
	{IP: net.ParseIP("2001:503:c27::2:30"), Port: 53, DomainName: "j.root-servers.net"},  // J
	{IP: net.ParseIP("2001:7fd::1"), Port: 53, DomainName: "k.root-servers.net"},         // K
	{IP: net.ParseIP("2001:500:9f::42"), Port: 53, DomainName: "l.root-servers.net"},     // L
	{IP: net.ParseIP("2001:dc3::35"), Port: 53, DomainName: "m.root-servers.net"},        // M
}

var DefaultExternalResolversV4 = []NameServer{
	{IP: net.ParseIP("8.8.8.8"), Port: DefaultDNSPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("8.8.4.4"), Port: DefaultDNSPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("1.1.1.1"), Port: DefaultDNSPort, DomainName: cloudflareDNSDomainName},
	{IP: net.ParseIP("1.0.0.1"), Port: DefaultDNSPort, DomainName: cloudflareDNSDomainName},
}

var DefaultExternalResolversV6 = []NameServer{
	{IP: net.ParseIP("2001:4860:4860::8888"), Port: DefaultDNSPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("2001:4860:4860::8844"), Port: DefaultDNSPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("2606:4700:4700::1111"), Port: DefaultDNSPort, DomainName: cloudflareDNSDomainName},
	{IP: net.ParseIP("2606:4700:4700::1001"), Port: DefaultDNSPort, DomainName: cloudflareDNSDomainName},
}
var DefaultExternalDoTResolversV4 = []NameServer{
	{IP: net.ParseIP("8.8.8.8"), Port: DefaultDoTPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("8.8.4.4"), Port: DefaultDoTPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("1.1.1.1"), Port: DefaultDoTPort, DomainName: cloudflareDNSDomainName},
	{IP: net.ParseIP("1.0.0.1"), Port: DefaultDoTPort, DomainName: cloudflareDNSDomainName},
}

var DefaultExternalDoTResolversV6 = []NameServer{
	{IP: net.ParseIP("2001:4860:4860::8888"), Port: DefaultDoTPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("2001:4860:4860::8844"), Port: DefaultDoTPort, DomainName: GoogleDoHDomainName},
	{IP: net.ParseIP("2606:4700:4700::1111"), Port: DefaultDoTPort, DomainName: cloudflareDNSDomainName},
	{IP: net.ParseIP("2606:4700:4700::1001"), Port: DefaultDoTPort, DomainName: cloudflareDNSDomainName},
}
