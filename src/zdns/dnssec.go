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

/*
 * DNSSEC validator of ZDNS.
 * RFC reference:
 * - https://datatracker.ietf.org/doc/html/rfc4033
 * - https://datatracker.ietf.org/doc/html/rfc4034
 * - https://datatracker.ietf.org/doc/html/rfc4035 (probably the most relevant one)
 * - https://datatracker.ietf.org/doc/html/rfc8914
 * - https://datatracker.ietf.org/doc/html/rfc7958
 *
 * Other references:
 * - https://www.cloudflare.com/learning/dns/dnssec/how-dnssec-works/
 * - https://dnsviz.net/
 */

package zdns

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	rootanchors "github.com/zmap/go-dns-root-anchors"
)

const rootZone = "."
const (
	zoneSigningKeyFlag = 256
	keySigningKeyFlag  = 257
)

// validate performs DNSSEC validation for all sections of a DNS message.
// It validates the Answer, Additional, and Authority sections independently,
// collects all encountered DS and DNSKEY records, and determines the overall
// DNSSEC status.
//
// Parameters:
// - depth: Current recursion depth for logging purposes
// - trace: Trace context for tracking validation path
//
// Returns:
// - *DNSSECResult: Contains validation results for all message sections:
//   - Status: Overall DNSSEC validation status (Secure/Insecure/Bogus/Indeterminate)
//   - DS: Collection of DS records actually used during validation
//   - DNSKEY: Collection of DNSKEY records actually used during validation
//   - Answer/Additionals/Authoritative: Per-RRset validation results
//
// - Trace: Updated trace context containing validation path
func (v *dNSSECValidator) validate(depth int, trace Trace) (*DNSSECResult, Trace) {
	result := makeDNSSECResult()

	if !hasRRSIG(v.msg) {
		v.r.verboseLog(depth, "DNSSEC: No RRSIG records found in message")
		result.Status = DNSSECInsecure // This can't be secure, but it could be bogus instead
		return result, trace
	}

	// Validate the answer section
	sectionRes, trace := v.validateSection(v.msg.Answer, depth, trace)
	result.Answer = sectionRes

	// If the message is authoritative, we drop the additional and authoritative sections
	// in Resolver.iterativeLookup, hence no need to validate them here. Validating them
	// causes circular lookups in some cases and can confuse the user.
	if !v.msg.Authoritative {
		// Validate the additional section
		sectionRes, trace = v.validateSection(v.msg.Extra, depth, trace)
		result.Additionals = sectionRes

		// Validate the authoritative section
		sectionRes, trace = v.validateSection(v.msg.Ns, depth, trace)
		result.Authoritative = sectionRes
	}

	for ds := range v.ds {
		parsed := ParseAnswer(&ds).(DSAnswer) //nolint:golint,errcheck
		result.DS = append(result.DS, &parsed)
	}
	for dnskey := range v.dNSKEY {
		parsed := ParseAnswer(&dnskey).(DNSKEYAnswer) //nolint:golint,errcheck
		result.DNSKEY = append(result.DNSKEY, &parsed)
	}

	result.populateStatus()

	return result, trace
}

// validateSection validates DNSSEC records for a given DNS message section.
//
// Parameters:
// - section: DNS message section containing RRs to validate
// - depth: Current recursion depth for logging
// - trace: Trace context for tracking request path
//
// Returns:
// - []DNSSECPerSetResult: Results of DNSSEC validation per RRset
// - Trace: Updated trace context
func (v *dNSSECValidator) validateSection(section []dns.RR, depth int, trace Trace) ([]DNSSECPerSetResult, Trace) {
	typeToRRSets, typeToRRSigs := splitRRsetsAndSigs(section)
	result := make([]DNSSECPerSetResult, 0)

	// Verify if for each RRset there is a corresponding RRSIG
	for rrsKey, rrSet := range typeToRRSets {
		setResult := DNSSECPerSetResult{
			RRset:  rrsKey,
			Status: DNSSECIndeterminate,
		}

		rrsigs, ok := typeToRRSigs[rrsKey]
		if !ok {
			setResult.Status = DNSSECInsecure
		} else {
			v.r.verboseLog(depth, "DNSSEC: Verifying RRSIGs for RRset", rrsKey.String())

			// Validate the RRSIGs for the RRset using validateRRSIG
			sigUsed, updatedTrace, err := v.validateRRSIG(rrsKey.Type, rrSet, rrsigs, trace, depth+1)
			trace = updatedTrace
			if sigUsed != nil {
				setResult.Status = DNSSECSecure

				sigParsed := ParseAnswer(sigUsed).(RRSIGAnswer) //nolint:golint,errcheck
				setResult.Signature = &sigParsed
			} else {
				v.r.verboseLog(depth+1, "could not verify any RRSIG for RRset", rrsKey.String(), "err:", err)
				// TODO: This check for bogus is not comprehensive or entirely accurate.
				// If the error is due to the inability to retrieve DNSKEY or DS records, the status should be indeterminate.
				// If a DS record exists at the SOA, but no RRSIG is found here, the status should be bogus (this case is not handled here).
				// If no DS record is found at the SOA, the status should be insecure because a chain of trust cannot be established.
				// However, this is unlikely in this context because an RRSIG should not exist without a corresponding DS record,
				// unless the domain starts a different trust anchor (which most resolvers would not trust anyway).
				// Distinguishing between these cases requires additional context, which would involve storing or querying more information
				// about the domain. These operations can be costly, so we need to decide if the additional complexity is worth it.
				setResult.Status = DNSSECBogus
				setResult.Error = err.Error()
			}
		}

		result = append(result, setResult)
	}

	return result, trace
}

// hasRRSIG checks if any RRSIG records exist in any section of a DNS message.
func hasRRSIG(msg *dns.Msg) bool {
	// Check Answer section
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}

	// Check Authority section
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}

	// Check Additional section
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}

	return false
}

// splitRRsetsAndSigs separates DNS resource records into RRsets and their corresponding RRSIGs.
//
// Parameters:
// - rrs: Slice of DNS resource records to split
//
// Returns:
// - map[RRsetKey][]dns.RR: Map of RRset keys to their resource records
// - map[RRsetKey][]*dns.RRSIG: Map of RRset keys to their RRSIG records
func splitRRsetsAndSigs(rrs []dns.RR) (map[RRsetKey][]dns.RR, map[RRsetKey][]*dns.RRSIG) {
	typeToRRSets := make(map[RRsetKey][]dns.RR)
	typeToRRSigs := make(map[RRsetKey][]*dns.RRSIG)

	for _, rr := range rrs {
		rrsKey := RRsetKey{
			Name:  rr.Header().Name,
			Class: rr.Header().Class,
		}
		switch rr := rr.(type) {
		case *dns.RRSIG:
			rrsKey.Type = rr.TypeCovered
			typeToRRSigs[rrsKey] = append(typeToRRSigs[rrsKey], rr)
		default:
			rrsKey.Type = rr.Header().Rrtype
			typeToRRSets[rrsKey] = append(typeToRRSets[rrsKey], rr)
		}
	}

	return typeToRRSets, typeToRRSigs
}

// findSEPsFromAnswer extracts SEP keys from a DNSKEY RRset answer.
//
// Parameters:
// - rrSet: The DNSKEY RRset to parse
// - signerDomain: The domain for which SEP keys are being found
// - depth: Current recursion depth for logging
// - trace: Trace context for tracking validation path
//
// Returns:
// - map[uint16]*dns.DNSKEY: Map of KeyTag to SEP key records
// - Trace: Updated trace context
// - error: Error if invalid records are found or no SEP present
func (v *dNSSECValidator) findSEPsFromAnswer(rrSet []dns.RR, signerDomain string, depth int, trace Trace) (map[uint16]*dns.DNSKEY, Trace, error) {
	dnskeys := make(map[uint16]*dns.DNSKEY)

	for _, rr := range rrSet {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, trace, fmt.Errorf("invalid RR type in DNSKEY RRset: %v", rr)
		}

		switch dnskey.Flags {
		case keySigningKeyFlag, zoneSigningKeyFlag:
			dnskeys[dnskey.KeyTag()] = dnskey
		default:
			return nil, trace, fmt.Errorf("unexpected DNSKEY flag: %d", dnskey.Flags)
		}
	}

	if len(dnskeys) == 0 {
		return nil, trace, errors.New("could not find any DNSKEY")
	}

	// Find SEP keys
	sepKeys, trace, err := v.findSEPs(signerDomain, dnskeys, trace, depth)
	if err != nil {
		return nil, trace, err
	}

	return sepKeys, nil, nil
}

// getDNSKEYs retrieves and validates DNSKEY records from the signer domain.
//
// Parameters:
// - signerDomain: Domain name to query for DNSKEY records
// - trace: Trace context
// - depth: Current recursion depth for logging
//
// Returns:
// - map[uint16]*dns.DNSKEY: Map of KeyTag to SEP DNSKEY records
// - map[uint16]*dns.DNSKEY: Map of KeyTag to DNSKEY records
// - Trace: Updated trace context
// - error: Error if DNSKEY retrieval or validation fails
func (v *dNSSECValidator) getDNSKEYs(signerDomain string, trace Trace, depth int) (map[uint16]*dns.DNSKEY, map[uint16]*dns.DNSKEY, Trace, error) {
	dnskeys := make(map[uint16]*dns.DNSKEY)

	nameWithoutTrailingDot := removeTrailingDotIfNotRoot(signerDomain)
	if signerDomain == rootZone {
		nameWithoutTrailingDot = rootZone
	}

	dnskeyQuestion := QuestionWithMetadata{
		Q: Question{
			Name:  nameWithoutTrailingDot,
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassINET,
		},
		RetriesRemaining: &v.r.retriesRemaining,
	}

	res, trace, status, err := v.r.lookup(v.ctx, &dnskeyQuestion, v.r.rootNameServers, v.isIterative, trace)
	if status != StatusNoError {
		v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DNSKEYs for signer domain %s, query status: %s", signerDomain, status))
		return nil, nil, trace, fmt.Errorf("DNSKEY fetch failed, query status: %s", status)
	} else if err != nil {
		v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DNSKEYs for signer domain %s, err: %v", signerDomain, err))
		return nil, nil, trace, fmt.Errorf("DNSKEY fetch failed, err: %v", err)
	} else if res.DNSSECResult != nil && res.DNSSECResult.Status != DNSSECSecure { // 	// DNSSECResult may be nil if the response is from the cache.
		v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DNSKEYs for signer domain %s, DNSSEC status: %s", signerDomain, res.DNSSECResult.Status))

		if prevResult := getResultForRRset(RRsetKey(dnskeyQuestion.Q), res.DNSSECResult.Answer); prevResult != nil && prevResult.Error != "" {
			return nil, nil, trace, fmt.Errorf("DNSKEY fetch failed: %s", prevResult.Error)
		} else {
			return nil, nil, trace, fmt.Errorf("DNSKEY fetch failed, DNSSEC status: %s", res.DNSSECResult.Status)
		}
	}

	// RRSIGs of res should have been verified before returning to here.

	// Construct key tag to DNSKEY map
	for _, rr := range res.Answers {
		zTypedKey, ok := rr.(DNSKEYAnswer)
		if !ok {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Non-DNSKEY RR type in DNSKEY answer: %v", rr))
			continue
		}
		dnskey := zTypedKey.ToVanillaType()

		switch dnskey.Flags {
		case keySigningKeyFlag, zoneSigningKeyFlag:
			dnskeys[dnskey.KeyTag()] = dnskey
		default:
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Unexpected DNSKEY flag %d in DNSKEY answer", dnskey.Flags))
		}
	}

	// Error if no DNSKEY is found
	if len(dnskeys) == 0 {
		return nil, nil, trace, errors.New("missing at least one DNSKEY answer")
	}

	// Find SEP keys
	// Don't actually need to because this have must been checked during the lookup for DNSKEY records.
	// Keeping this here only so we can include matched DS records in the output.
	var sepKeys map[uint16]*dns.DNSKEY
	sepKeys, trace, err = v.findSEPs(signerDomain, dnskeys, trace, depth)
	if err != nil {
		return nil, nil, trace, err
	}

	return sepKeys, dnskeys, trace, nil
}

// findSEPs validates DS records against DNSKEY records,
// to find the SEP (Secure Entry Point) keys for a given signer domain.
//
// Parameters:
// - signerDomain: The signer domain to query for DS records
// - dnskeyMap: A map of KeyTag to DNSKEYs to search for SEP keys
// - trace: The trace context for tracking request path
// - depth: The recursion depth for logging purposes
//
// Returns:
// - map[uint16]*dns.DNSKEY: Map of KeyTag to SEP DNSKEY records
// - Trace: Updated trace context
// - error: If validation fails for any DS record
func (v *dNSSECValidator) findSEPs(signerDomain string, dnskeyMap map[uint16]*dns.DNSKEY, trace Trace, depth int) (map[uint16]*dns.DNSKEY, Trace, error) {
	nameWithoutTrailingDot := removeTrailingDotIfNotRoot(signerDomain)

	dsQuestion := QuestionWithMetadata{
		Q: Question{
			Name:  nameWithoutTrailingDot,
			Type:  dns.TypeDS,
			Class: dns.ClassINET,
		},
		RetriesRemaining: &v.r.retriesRemaining,
	}

	dsRecords := make(map[uint16]dns.DS)
	if signerDomain == rootZone {
		// Root zone, use the root anchors
		dsRecords = rootanchors.GetValidDSRecords()
	} else {
		// DNSSECResult may be nil if the response is from the cache.
		res, newTrace, status, err := v.r.lookup(v.ctx, &dsQuestion, v.r.rootNameServers, v.isIterative, trace)
		trace = newTrace
		if status != StatusNoError {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DS records for signer domain %s, query status: %s", signerDomain, status))
			return nil, trace, fmt.Errorf("DS fetch failed, query status: %s", status)
		} else if err != nil {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DS records for signer domain %s, err: %v", signerDomain, err))
			return nil, trace, fmt.Errorf("DS fetch failed, err: %v", err)
		} else if res.DNSSECResult != nil && res.DNSSECResult.Status != DNSSECSecure {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DS records for signer domain %s, DNSSEC status: %s", signerDomain, res.DNSSECResult.Status))

			if prevResult := getResultForRRset(RRsetKey(dsQuestion.Q), res.DNSSECResult.Answer); prevResult != nil && prevResult.Error != "" {
				return nil, trace, fmt.Errorf("DS fetch failed: %s", prevResult.Error)
			} else {
				return nil, trace, fmt.Errorf("DS fetch failed, DNSSEC status: %s", res.DNSSECResult.Status)
			}
		}

		// RRSIGs of res should have been verified before returning to here.

		for _, rr := range res.Answers {
			zTypedDS, ok := rr.(DSAnswer)
			if !ok {
				v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Non-DS RR type in DS answer: %v", rr))
				continue
			}
			ds := zTypedDS.ToVanillaType()
			dsRecords[ds.KeyTag] = *ds
		}
	}

	sepKeys := make(map[uint16]*dns.DNSKEY)
	for _, key := range dnskeyMap {
		authenticDS, ok := dsRecords[key.KeyTag()]
		if !ok {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: No DS record found for DNSKEY with KeyTag %d", key.KeyTag()))
			continue
		}

		actualDS := key.ToDS(authenticDS.DigestType)
		if actualDS == nil {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to convert DNSKEY with KeyTag %d to DS record", key.KeyTag()))
			continue
		}

		actualDigest := strings.ToUpper(actualDS.Digest)
		authenticDigest := strings.ToUpper(authenticDS.Digest)
		if actualDigest != authenticDigest {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: DS record mismatch for DNSKEY with KeyTag %d: expected %s, got %s", key.KeyTag(), authenticDigest, actualDigest))
		} else {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Delegation verified for DNSKEY with KeyTag %d, SEP established", key.KeyTag()))

			v.ds[*actualDS] = true
			sepKeys[key.KeyTag()] = key
		}
	}

	if len(sepKeys) == 0 {
		v.r.verboseLog(depth, "DNSSEC: No SEP found for signer domain", signerDomain)
		return nil, trace, errors.New("no SEP matching DS found")
	}

	return sepKeys, trace, nil
}

// validateRRSIG verifies RRSIGs for a given RRset using appropriate DNSKEYs.
// For DNSKEY RRsets, SEPs from the answer are used. For other types,
// ZSKs are retrieved from the signer domain.
//
// Parameters:
// - rrSetType: Type of records being validated
// - rrSet: Set of records to validate
// - rrsigs: RRSIG records to verify
// - trace: Trace context
// - depth: Current recursion depth for logging
//
// Returns:
// - *dns.RRSIG: First successfully validated RRSIG, or nil if none
// - Trace: Updated trace context
// - error: Error if no RRSIG could be validated
func (v *dNSSECValidator) validateRRSIG(rrSetType uint16, rrSet []dns.RR, rrsigs []*dns.RRSIG, trace Trace, depth int) (*dns.RRSIG, Trace, error) {
	var dnskeyMap map[uint16]*dns.DNSKEY
	var err error

	// Attempt to verify each RRSIG using only the DNSKEY matching its KeyTag
	lastErr := errors.New("no RRSIG to verify")
	for _, rrsig := range rrsigs {
		// If RRset type is DNSKEY, use SEPs found from the answer directly
		if rrSetType == dns.TypeDNSKEY {
			dnskeyMap, trace, err = v.findSEPsFromAnswer(rrSet, rrsig.SignerName, depth, trace)
			if err != nil {
				return nil, trace, err
			}
		} else {
			// For other RRset types, fetch DNSKEYs for each RRSIG's signer domain
			v.r.verboseLog(depth, "DNSSEC: Verifying RRSIG with signer", rrsig.SignerName)

			_, zskMap, updatedTrace, err := v.getDNSKEYs(rrsig.SignerName, trace, depth+1)
			dnskeyMap = zskMap
			if err != nil {
				lastErr = err
				continue
			}
			trace = updatedTrace
		}

		keyTag := rrsig.KeyTag

		// Check if the RRSIG is still valid
		if !rrsig.ValidityPeriod(time.Now()) {
			lastErr = fmt.Errorf("RRSIG with keytag=%d has expired or is not yet valid", keyTag)
			v.r.verboseLog(depth, "DNSSEC: RRSIG with keytag=", keyTag, "has expired or is not yet valid")
			continue
		}

		matchingKey, found := dnskeyMap[keyTag]
		if !found {
			lastErr = fmt.Errorf("no matching DNSKEY found for RRSIG with key tag %d", keyTag)
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: No matching DNSKEY found for RRSIG with key tag %d", keyTag))
			continue
		}

		// Verify the RRSIG with the matching DNSKEY
		if err := rrsig.Verify(matchingKey, rrSet); err == nil {
			v.dNSKEY[*matchingKey] = true
			return rrsig, trace, nil
		} else {
			lastErr = fmt.Errorf("RRSIG with keytag=%d failed to verify: %v", keyTag, err)
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: RRSIG with keytag=%d failed to verify: %v", keyTag, err))
			continue
		}
	}

	return nil, trace, lastErr
}
