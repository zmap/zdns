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

package miekg

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/zmap/dns"
	"github.com/zmap/zdns/pkg/zdns"
)

func dotName(name string) string {
	return strings.Join([]string{name, "."}, "")
}

func TranslateMiekgErrorCode(err int) zdns.Status {
	return zdns.Status(dns.RcodeToString[err])
}

func isStatusAnswer(s zdns.Status) bool {
	if s == zdns.STATUS_NOERROR || s == zdns.STATUS_NXDOMAIN {
		return true
	}
	return false
}

func questionFromAnswer(a Answer) Question {
	return Question{Name: a.Name, Type: a.RrType, Class: a.RrClass}
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

func nextAuthority(name, layer string) (string, error) {
	// We are our own authority for PTRs
	// (This is dealt with elsewhere)
	if strings.HasSuffix(name, "in-addr.arpa") && layer == "." {
		return "in-addr.arpa", nil
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

	// Limit the search space to the prefix of the string that isnt layer
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

func checkGlue(server string, depth int, result Result) (Result, zdns.Status) {
	for _, additional := range result.Additional {
		ans, ok := additional.(Answer)
		if !ok {
			continue
		}
		if ans.Type == "A" && strings.TrimSuffix(ans.Name, ".") == server {
			var retv Result
			retv.Authorities = make([]interface{}, 0)
			retv.Answers = make([]interface{}, 0)
			retv.Additional = make([]interface{}, 0)
			retv.Answers = append(retv.Answers, ans)
			return retv, zdns.STATUS_NOERROR
		}
	}
	var r Result
	return r, zdns.STATUS_ERROR
}

func makeVerbosePrefix(depth int, threadID int) string {
	return fmt.Sprintf("THREADID %06d,DEPTH %02d", threadID, depth) + ":" + strings.Repeat("  ", 2*depth)
}

// Check whether the status is safe
func SafeStatus(status zdns.Status) bool {
	return status == zdns.STATUS_NOERROR
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
