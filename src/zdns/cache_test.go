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

import (
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/stretchr/testify/assert"
)

func TestCheckForNonExistentKey(t *testing.T) {
	cache := Cache{}
	cache.Init(4096)
	_, found := cache.GetCachedResults(Question{1, 1, "google.com"}, nil, 0)
	assert.False(t, found, "Expected no cache entry")
}

func TestNoNameServerLookupSuccess(t *testing.T) {
	res := SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:     3600,
			RrType:  1,
			RrClass: 1,
			Name:    "google.com",
			Answer:  "192.0.2.1",
		}},
		Additionals: nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{Authoritative: true},
	}
	cache := Cache{}
	cache.Init(4096)
	cache.SafeAddCachedAnswer(Question{Type: dns.TypeA, Name: "google.com", Class: dns.ClassINET}, &res, nil, "google.com", 0, false)
	_, found := cache.GetCachedResults(Question{dns.TypeA, 1, "google.com"}, nil, 0)
	assert.True(t, found, "Expected cache entry")
}

func TestNoNameServerLookupForNamedNameServer(t *testing.T) {
	res := SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:     3600,
			RrType:  1,
			RrClass: 1,
			Name:    "google.com",
			Answer:  "192.0.2.1",
		}},
		Additionals: nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{Authoritative: true},
	}
	cache := Cache{}
	cache.Init(4096)
	cache.SafeAddCachedAnswer(Question{Type: dns.TypeA, Name: "google.com", Class: dns.ClassINET}, &res, nil, "google.com", 0, false)
	_, found := cache.GetCachedResults(Question{1, 1, "google.com"}, &NameServer{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 53,
	}, 0)
	assert.False(t, found, "Cache has an answer from a generic nameserver, we wanted a specific one. Shouldn't be found.")
}

func TestNamedServerLookupForNonNamedNameServer(t *testing.T) {
	res := SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:     3600,
			RrType:  1,
			RrClass: 1,
			Name:    "google.com",
			Answer:  "192.0.2.1",
		}},
		Additionals: nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{Authoritative: true},
	}
	cache := Cache{}
	cache.Init(4096)
	cache.SafeAddCachedAnswer(Question{Type: dns.TypeA, Name: "google.com", Class: dns.ClassINET}, &res, &NameServer{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 53,
	}, "google.com", 0, false)
	_, found := cache.GetCachedResults(Question{1, 1, "google.com"}, nil, 0)
	assert.False(t, found, "Cache has an answer from a named nameserver, we wanted a generic one. Shouldn't be found.")
}

func TestNamedServerLookupForNamedNameServer(t *testing.T) {
	res := SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:     3600,
			RrType:  1,
			RrClass: 1,
			Name:    "google.com",
			Answer:  "192.0.2.1",
		}},
		Additionals: nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{Authoritative: true},
	}
	cache := Cache{}
	cache.Init(4096)
	cache.SafeAddCachedAnswer(Question{Type: dns.TypeA, Name: "google.com", Class: dns.ClassINET}, &res, &NameServer{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 53,
	}, "google.com", 0, false)
	_, found := cache.GetCachedResults(Question{1, 1, "google.com"}, &NameServer{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 53,
	}, 0)
	assert.True(t, found, "Should be found")
}

func TestNoNameServerLookupNotAuthoritative(t *testing.T) {
	res := SingleQueryResult{
		Answers: []interface{}{Answer{
			TTL:     3600,
			RrType:  1,
			RrClass: 1,
			Name:    "google.com",
			Answer:  "192.0.2.1",
		}},
		Additionals: nil,
		Authorities: nil,
		Protocol:    "",
		Flags:       DNSFlags{Authoritative: false},
	}
	cache := Cache{}
	cache.Init(4096)
	cache.SafeAddCachedAnswer(Question{Type: dns.TypeA, Name: "google.com", Class: dns.ClassINET}, &res, nil, "google.com", 0, false)
	_, found := cache.GetCachedResults(Question{1, 1, "google.com"}, nil, 0)
	assert.False(t, found, "shouldn't cache non-authoritative answers")
	cache.SafeAddCachedAnswer(Question{Type: dns.TypeA, Name: "google.com", Class: dns.ClassINET}, &res, nil, "google.com", 0, true)
	_, found = cache.GetCachedResults(Question{1, 1, "google.com"}, nil, 0)
	assert.True(t, found, "should cache non-authoritative answers")
}
