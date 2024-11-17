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

// DNSSECStatus represents the overall validation status according to RFC 4035
type DNSSECStatus string

const (
	DNSSECSecure        DNSSECStatus = "Secure"
	DNSSECInsecure      DNSSECStatus = "Insecure"
	DNSSECBogus         DNSSECStatus = "Bogus"
	DNSSECIndeterminate DNSSECStatus = "Indeterminate"
)

// DNSSECPerSetResult represents the validation result for an RRSet
type DNSSECPerSetResult struct {
	Status       DNSSECStatus
	ValidatedSig *RRSIGAnswer
}

// DNSSECResult captures all information generated during a DNSSEC validation
type DNSSECResult struct {
	Status        DNSSECStatus
	DS            []*DSAnswer
	DNSKEY        []*DNSKEYAnswer
	Answer        map[string]DNSSECPerSetResult
	Additionals   map[string]DNSSECPerSetResult
	Authoritative map[string]DNSSECPerSetResult
}

// makeDNSSECResult creates and initializes a new DNSSECResult instance
func makeDNSSECResult() *DNSSECResult {
	return &DNSSECResult{
		Status:        DNSSECIndeterminate,
		DS:            make([]*DSAnswer, 0),
		DNSKEY:        make([]*DNSKEYAnswer, 0),
		Answer:        make(map[string]DNSSECPerSetResult),
		Additionals:   make(map[string]DNSSECPerSetResult),
		Authoritative: make(map[string]DNSSECPerSetResult),
	}
}

// AreAnswersSecure checks if all RR sets in the answer section are secure
func (r *DNSSECResult) AreAnswersSecure() bool {
	for _, result := range r.Answer {
		if result.Status != DNSSECSecure {
			return false
		}
	}
	return true
}
