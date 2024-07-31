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
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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

// IsIPv6 checks if the given IP address is an IPv6 address.
func IsIPv6(ip *net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

// Reference: https://github.com/carolynvs/stingoftheviper/blob/main/main.go
// For how to make cobra/viper sync up, and still use custom struct
// Bind each cobra flag to its associated viper configuration (config file and environment variable)
func BindFlags(cmd *cobra.Command, v *viper.Viper, envPrefix string) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --alexa to ZDNS_ALEXA
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			err := v.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix))
			if err != nil {
				log.Fatal("failed to bind environment variable to flag: ", err)
			}
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				log.Fatalf("failed to set flag (%s) value: %v", f.Name, err)
			}
		}
	})
}

// GetDefaultResolvers returns a slice of default DNS resolvers to be used when no system resolvers could be discovered.
// Returns IPv4 and IPv6 resolvers.
func GetDefaultResolvers() ([]string, []string) {
	return []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}, []string{"2001:4860:4860::8888:53", "2001:4860:4860::8844:53", "2606:4700:4700::1111:53", "2606:4700:4700::1001:53"}
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
