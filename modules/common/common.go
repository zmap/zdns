package common

import (
	"net"
	"strings"

	"github.com/zmap/zdns"
)

// Verify that A record is indeed IPv4 and AAAA is IPv6
func VerifyAddress(ansType string, ip string) bool {
	isIpv4 := net.ParseIP(ip).To4() != nil
	isIpv6 := net.ParseIP(ip).To16() != nil && strings.Contains(ip, ":")
	if ansType == "A" {
		return isIpv4
	} else if ansType == "AAAA" {
		return isIpv6
	}
	return !isIpv4 && !isIpv6
}

func SafeStatus(status zdns.Status) bool {
	return status == zdns.STATUS_NOERROR
}
