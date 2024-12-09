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
	"context"

	"github.com/miekg/dns"
)

// DNSSECStatus represents the overall validation status according to RFC 4035
type DNSSECStatus string

const (
	DNSSECSecure        DNSSECStatus = "Secure"
	DNSSECInsecure      DNSSECStatus = "Insecure"
	DNSSECBogus         DNSSECStatus = "Bogus"
	DNSSECIndeterminate DNSSECStatus = "Indeterminate"
)

type RRsetKey Question

func (r *RRsetKey) String() string {
	return "name: " + r.Name + ", type: " + dns.TypeToString[r.Type] + ", class: " + dns.ClassToString[r.Class]
}

// DNSSECPerSetResult represents the validation result for an RRSet
type DNSSECPerSetResult struct {
	RRset     RRsetKey     `json:"rrset"`
	Status    DNSSECStatus `json:"status"`
	Signature *RRSIGAnswer `json:"sig"`
	Error     string       `json:"error"`
}

// DNSSECResult captures all information generated during a DNSSEC validation
type DNSSECResult struct {
	Status        DNSSECStatus         `json:"status" groups:"dnssec,dnssec,normal,long,trace"`
	Reason        string               `json:"reason" groups:"dnssec,dnssec,normal,long,trace"`
	DS            []*DSAnswer          `json:"ds" groups:"dnssec,long,trace"`
	DNSKEY        []*DNSKEYAnswer      `json:"dnskey" groups:"dnssec,long,trace"`
	Answer        []DNSSECPerSetResult `json:"answer" groups:"dnssec,long,trace"`
	Additional    []DNSSECPerSetResult `json:"additional" groups:"dnssec,long,trace"`
	Authoritative []DNSSECPerSetResult `json:"authoritative" groups:"dnssec,long,trace"`
}

func getResultForRRset(rrsetKey RRsetKey, results []DNSSECPerSetResult) *DNSSECPerSetResult {
	for _, result := range results {
		if result.RRset == rrsetKey {
			return &result
		}
	}
	return nil
}

type dNSSECValidator struct {
	// Info shared across all validations for a chain of queries
	r           *Resolver
	ctx         context.Context
	isIterative bool
	status      DNSSECStatus
	reason      string

	// Temporary info for a single validation
	msg        *dns.Msg
	nameServer *NameServer
	ds         map[dns.DS]struct{}
	dNSKEY     map[dns.DNSKEY]struct{}
}

// makeDNSSECValidator creates a new DNSSECValidator instance
func makeDNSSECValidator(r *Resolver, ctx context.Context, isIterative bool) *dNSSECValidator {
	return &dNSSECValidator{
		r:           r,
		ctx:         ctx,
		isIterative: isIterative,
		status:      DNSSECSecure,
		reason:      "",
	}
}

// resetDNSSECValidator resets the DNSSECValidator instance for a new message
func (v *dNSSECValidator) resetDNSSECValidator(msg *dns.Msg, nameServer *NameServer) {
	v.msg = msg
	v.nameServer = nameServer
	v.ds = make(map[dns.DS]struct{})
	v.dNSKEY = make(map[dns.DNSKEY]struct{})
}

// makeDNSSECResult creates and initializes a new DNSSECResult instance
func makeDNSSECResult() *DNSSECResult {
	return &DNSSECResult{
		Status:        DNSSECIndeterminate,
		Reason:        "",
		DS:            make([]*DSAnswer, 0),
		DNSKEY:        make([]*DNSKEYAnswer, 0),
		Answer:        make([]DNSSECPerSetResult, 0),
		Additional:    make([]DNSSECPerSetResult, 0),
		Authoritative: make([]DNSSECPerSetResult, 0),
	}
}

// OverallStatus returns the overall validation status.
// If any RR set is bogus, the overall status is bogus.
// If any RR set in answer section or any DNSSEC-related RRSet is insecure, the overall status is insecure.
// If any RR set in answer section or any DNSSEC-related RRSet is indeterminate, the overall status is indeterminate.
// Otherwise, the overall status is secure.
// This function should be called after all PerSetResults are populated, and the result should is stored in r.Status.
func (r *DNSSECResult) populateStatus() {
	isDNSSECType := func(rrType uint16) bool {
		switch rrType {
		case dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
			return true
		default:
			return false
		}
	}

	r.Status = DNSSECSecure

	// Check for bogus results first (highest priority)
	checkSections := [][]DNSSECPerSetResult{r.Answer, r.Additional, r.Authoritative}
	for _, section := range checkSections {
		for _, result := range section {
			if result.Status == DNSSECBogus {
				r.Status = DNSSECBogus
				r.Reason = result.Error
				return
			}
		}
	}

	for _, result := range r.Answer {
		if result.Status == DNSSECInsecure {
			r.Status = DNSSECInsecure
			r.Reason = result.Error
			return
		}

		if result.Status == DNSSECIndeterminate {
			r.Status = DNSSECIndeterminate
			r.Reason = result.Error
		}
	}

	// Check DNSSEC-related RRsets in other sections
	for _, section := range [][]DNSSECPerSetResult{r.Additional, r.Authoritative} {
		for _, result := range section {
			if isDNSSECType(result.RRset.Type) {
				if result.Status == DNSSECInsecure {
					r.Status = DNSSECInsecure
					r.Reason = result.Error
					return
				}

				if r.Status != DNSSECSecure && result.Status == DNSSECIndeterminate {
					r.Status = DNSSECIndeterminate
					r.Reason = result.Error
					return
				}
			}
		}
	}

	// If we get here, either everything is secure or we have an indeterminate result
}
