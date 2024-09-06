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
	"net"
	"regexp"
	"strconv"

	"github.com/pkg/errors"
)

const (
	EnvPrefix              = "ZDNS"
	DefaultFilePermissions = 0644 // rw-r--r--
	DefaultDNSPort         = "53"
	DefaultHTTPSPort       = "443"
	DefaultTLSPort         = "853"
)

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
