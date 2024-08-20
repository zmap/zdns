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

package util

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"regexp"
	"strconv"
)

const (
	EnvPrefix              = "ZDNS"
	DefaultFilePermissions = 0644 // rw-r--r--
)

func AddDefaultPortToDNSServerName(inAddr string) (string, error) {
	// Try to split host and port to see if the port is already specified.
	host, port, err := net.SplitHostPort(inAddr)
	if err != nil {
		// might mean there's no port specified
		host = inAddr
	}

	// Validate the host part as an IP address.
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("invalid IP address")
	}

	// If the original input does not have a port, specify port 53
	if port == "" {
		port = "53"
	}

	return net.JoinHostPort(ip.String(), port), nil
}

func SplitHostPort(inaddr string) (net.IP, int, error) {
	host, port, err := net.SplitHostPort(inaddr)
	if err != nil {
		return nil, 0, err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, errors.Wrap(err, "invalid IP address")
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, 0, errors.Wrap(err, "invalid port")
	}

	return ip, portInt, nil
}

// SplitIPv4AndIPv6Addrs splits a list of IP addresses (either with port attached or not) into IPv4 and IPv6 addresses.
// Returns a slice of IPv4/IPv6 addresses that are guaranteed to be valid. If the port was attached, it'll be included.
func SplitIPv4AndIPv6Addrs(addrs []string) (ipv4 []string, ipv6 []string, err error) {
	for _, addr := range addrs {
		ip, _, err := SplitHostPort(addr)
		if err != nil {
			// addr may be an IP without a port
			ip = net.ParseIP(addr)
		}
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address: %s", addr)
		}
		// ip is valid, check if it's IPv4 or IPv6
		if ip.To4() != nil {
			ipv4 = append(ipv4, addr)
		} else if ip.To16() != nil {
			ipv6 = append(ipv6, addr)
		} else {
			return nil, nil, fmt.Errorf("invalid IP address: %s", addr)
		}
	}
	return ipv4, ipv6, nil
}

// IsStringValidDomainName checks if the given string is a valid domain name using regex
func IsStringValidDomainName(domain string) bool {
	var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// HasCtxExpired checks if the context has expired. Common function used in various places.
func HasCtxExpired(ctx *context.Context) bool {
	select {
	case <-(*ctx).Done():
		return true
	default:
		return false
	}
}

// Contains checks if a value is in a slice.
// Performance note: if you're going to be making multiple calls to Contains, it is much more performant to create a
// map of the slice to get O(1) lookups. This is for one-off lookups.
func Contains[T comparable](slice []T, entity T) bool {
	for _, v := range slice {
		if v == entity {
			return true
		}
	}
	return false
}

func RemoveDuplicates[T comparable](slice []T) []T {
	lookup := make(map[T]struct{}, len(slice)) // prealloc for performance
	result := make([]T, 0, len(slice))
	for _, v := range slice {
		if _, ok := lookup[v]; !ok {
			lookup[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

// Concat returns a new slice concatenating the passed in slices.
//
// Avoids a gotcha in Go where since append modifies the underlying memory of the input slice, doing
// newSlice := append(slice1, slice2) can modify slice1. See https://go.dev/doc/effective_go#append
// A std. library concat was added in go 1.22, but this is for backwards compatibility. https://pkg.go.dev/slices#Concat
// This is mostly similiar to the std. library concat, but with a few differences so it compiles on go 1.20.
func Concat[S ~[]E, E any](slices ...S) S {
	size := 0
	for _, s := range slices {
		size += len(s)
		if size < 0 {
			panic("len out of range")
		}
	}
	newSlice := make([]E, 0, size)
	for _, s := range slices {
		newSlice = append(newSlice, s...)
	}
	return newSlice
}

// IsIPv6 checks if the given IP address is an IPv6 address.
func IsIPv6(ip *net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}
