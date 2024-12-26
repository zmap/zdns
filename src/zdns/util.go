/*
 * ZDNS Copyright 2022 Regents of the University of Michigan
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

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
)

const ZDNSVersion = "2.0.0"

func dotName(name string) string {
	if name == "." {
		return name
	}

	if strings.HasSuffix(name, ".") {
		log.Fatal("name already has trailing dot")
	}

	return strings.Join([]string{name, "."}, "")
}

func removeTrailingDotIfNotRoot(name string) string {
	if name == "." {
		return name
	}
	return strings.TrimSuffix(name, ".")
}

func TranslateMiekgErrorCode(err int) Status {
	return Status(dns.RcodeToString[err])
}

func isStatusAnswer(s Status) bool {
	if s == StatusNoError || s == StatusNXDomain {
		return true
	}
	return false
}

// getTryNumber returns the one-indexed try that the lookup succeeded on
func getTryNumber(totalRetries, retriesRemaining int) int {
	return totalRetries - retriesRemaining + 1
}

func nameIsBeneath(name, layer string) (bool, string) {
	name = strings.ToLower(name)
	layer = strings.ToLower(layer)
	name = strings.TrimSuffix(name, ".")
	if layer == "." {
		return true, name
	}

	if strings.HasSuffix(name, "."+layer) || name == layer {
		return true, name
	}
	return false, ""
}

func checkGlue(server string, result *SingleQueryResult, ipMode IPVersionMode, ipPreference IterationIPPreference) (*SingleQueryResult, Status) {
	var ansType string
	if ipMode == IPv4Only {
		ansType = "A"
	} else if ipMode == IPv6Only {
		ansType = "AAAA"
	} else if ipPreference == PreferIPv4 {
		// must be using either IPv4 or IPv6
		ansType = "A"
	} else if ipPreference == PreferIPv6 {
		// must be using either IPv4 or IPv6
		ansType = "AAAA"
	} else {
		log.Fatal("should never hit this case in check glue: ", ipMode, ipPreference)
	}
	res, status := checkGlueHelper(server, ansType, result)
	if status == StatusNoError || ipMode != IPv4OrIPv6 {
		// If we have a valid answer, or we're not looking for both A and AAAA records, return
		return res, status
	}
	// If we're looking for both A and AAAA records, and we didn't find an answer, try the other type
	if ansType == "A" {
		ansType = "AAAA"
	} else {
		ansType = "A"
	}
	return checkGlueHelper(server, ansType, result)
}

func checkGlueHelper(server, ansType string, result *SingleQueryResult) (*SingleQueryResult, Status) {
	for _, additional := range result.Additionals {
		ans, ok := additional.(Answer)
		if !ok {
			continue
		}
		// sanitize case and trailing dot
		// RFC 4343 - states DNS names are case-insensitive
		if ans.Type == ansType && strings.EqualFold(strings.TrimSuffix(ans.Name, "."), server) {
			var retv SingleQueryResult
			retv.Authorities = make([]interface{}, 0)
			retv.Answers = make([]interface{}, 0, 1)
			retv.Additionals = make([]interface{}, 0)
			retv.Answers = append(retv.Answers, ans)
			return &retv, StatusNoError
		}
	}
	return nil, StatusError
}

// nextAuthority returns the next authority to query based on the current name and layer
// Example: nextAuthority("www.google.com", ".") -> "com"
func nextAuthority(name, layer string) (string, error) {
	// We are our own authority for PTRs
	// (This is dealt with elsewhere)
	if strings.HasSuffix(name, "in-addr.arpa") && layer == "." {
		return "in-addr.arpa", nil
	}

	if name == "." && layer == "." {
		return ".", nil
	}

	idx := strings.LastIndex(name, ".")
	if idx < 0 || (idx+1) >= len(name) {
		return name, nil
	}
	if layer == "." {
		return name[idx+1:], nil
	}

	if !strings.HasSuffix(name, layer) {
		return "", errors.New("Server did not provide appropriate resolvers to continue recursion")
	}

	// Limit the search space to the prefix of the string that isn't layer
	idx = strings.LastIndex(name, layer) - 1
	if idx < 0 || (idx+1) >= len(name) {
		// Out of bounds. We are our own authority
		return name, nil
	}
	// Find the next step in the layer
	idx = strings.LastIndex(name[0:idx], ".")
	next := name[idx+1:]
	return next, nil
}

func makeVerbosePrefix(depth int) string {
	return fmt.Sprintf("DEPTH %02d", depth) + ":" + strings.Repeat("  ", 2*depth)
}

// Check whether the status is safe
func SafeStatus(status Status) bool {
	return status == StatusNoError
}

// Verify that A record is indeed IPv4 and AAAA is IPv6
func VerifyAddress(ansType string, ip string) bool {
	isIpv4 := false
	isIpv6 := false
	if net.ParseIP(ip) != nil {
		isIpv6 = strings.Contains(ip, ":")
		isIpv4 = !isIpv6
	}
	if ansType == "A" {
		return isIpv4
	} else if ansType == "AAAA" {
		return isIpv6
	}
	// TODO Phillip - this seems like strange behavior. Maybe assert that ansType is either 'A' or 'AAAA'?
	// I'll come back to this post-merge, it was like this in the original version.
	return !isIpv4 && !isIpv6
}

func Unique(a []string) []string {
	seen := make(map[string]bool)
	j := 0
	for _, v := range a {
		if !seen[v] {
			seen[v] = true
			a[j] = v
			j++
		}
	}
	return a[:j]
}

// TranslateDNSErrorCode translates a DNS error code from the DNS library to a Status
func TranslateDNSErrorCode(err int) Status {
	return Status(dns.RcodeToString[err])
}

// handleStatus is a helper function to deal with a status and error. Error is only returned if the status is an
// Iterative Timeout or NoNeededGlueRecord
func handleStatus(status Status, err error) (Status, error) {
	switch status {
	case StatusIterTimeout:
		return status, err
	case StatusNoNeededGlue:
		return status, err
	case StatusNXDomain:
		return status, nil
	case StatusServFail:
		return status, nil
	case StatusRefused:
		return status, nil
	case StatusAuthFail:
		return status, nil
	case StatusNoRecord:
		return status, nil
	case StatusBlacklist:
		return status, nil
	case StatusNoOutput:
		return status, nil
	case StatusNoAnswer:
		return status, nil
	case StatusTruncated:
		return status, nil
	case StatusIllegalInput:
		return status, nil
	default:
		var s Status
		return s, nil
	}
}

// DeepCopyIPs creates a deep copy of a slice of net.IP
func DeepCopyIPs(ips []net.IP) []net.IP {
	copied := make([]net.IP, len(ips))
	for i, ip := range ips {
		if ip != nil {
			// Deep copy the IP by copying the underlying byte slice
			copied[i] = append(net.IP(nil), ip...)
		}
	}
	return copied
}
