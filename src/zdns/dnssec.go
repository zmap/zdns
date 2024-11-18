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

	// Validate the answer section
	sectionRes, trace := v.validateSection(v.msg.Answer, depth, trace)
	result.Answer = sectionRes

	// Validate the additional section
	sectionRes, trace = v.validateSection(v.msg.Extra, depth, trace)
	result.Additionals = sectionRes

	// Validate the authoritative section
	sectionRes, trace = v.validateSection(v.msg.Ns, depth, trace)
	result.Authoritative = sectionRes

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
			v.r.verboseLog(depth+1, "DNSSEC: Found RRset without RRSIG coverage,"+rrsKey.String())
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

// parseKSKsFromAnswer extracts Key Signing Keys (KSKs) from a DNSKEY RRset answer.
// Records with ZSK flags are ignored and non-DNSKEY records cause an error.
//
// Parameters:
// - rrSet: The DNSKEY RRset to parse
//
// Returns:
// - map[uint16]*dns.DNSKEY: Map of KeyTag to KSK records
// - error: Error if invalid records are found or no KSKs present
func parseKSKsFromAnswer(rrSet []dns.RR) (map[uint16]*dns.DNSKEY, error) {
	ksks := make(map[uint16]*dns.DNSKEY)

	for _, rr := range rrSet {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("invalid RR type in DNSKEY RRset: %v", rr)
		}
		switch dnskey.Flags {
		case keySigningKeyFlag:
			ksks[dnskey.KeyTag()] = dnskey
		case zoneSigningKeyFlag:
			// Skip ZSKs
			continue
		default:
			return nil, fmt.Errorf("unexpected DNSKEY flag: %d", dnskey.Flags)
		}
	}

	if len(ksks) == 0 {
		return nil, errors.New("could not find any KSK in DNSKEY RRset")
	}

	return ksks, nil
}

// getDNSKEYs retrieves and validates DNSKEY records from the signer domain.
//
// Parameters:
// - signerDomain: Domain name to query for DNSKEY records
// - trace: Trace context
// - depth: Current recursion depth for logging
//
// Returns:
// - map[uint16]*dns.DNSKEY: Map of KeyTag to KSK records
// - map[uint16]*dns.DNSKEY: Map of KeyTag to ZSK records
// - Trace: Updated trace context
// - error: Error if DNSKEY retrieval or validation fails
func (v *dNSSECValidator) getDNSKEYs(signerDomain string, trace Trace, depth int) (map[uint16]*dns.DNSKEY, map[uint16]*dns.DNSKEY, Trace, error) {
	ksks := make(map[uint16]*dns.DNSKEY)
	zsks := make(map[uint16]*dns.DNSKEY)

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
	// DNSSECResult may be nil if the response is from the cache.
	if status != StatusNoError || err != nil || (res.DNSSECResult != nil && res.DNSSECResult.Status != DNSSECSecure) {
		v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DNSKEYs for signer domain %s, query status: %s, err: %v", signerDomain, status, err))
		return nil, nil, trace, fmt.Errorf("cannot get DNSKEYs for signer domain %s", signerDomain)
	}

	// RRSIGs of res should have been verified before returning to here.

	// Separate DNSKEYs into KSKs and ZSKs maps based on flags
	for _, rr := range res.Answers {
		zTypedKey, ok := rr.(DNSKEYAnswer)
		if !ok {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Non-DNSKEY RR type in DNSKEY answer: %v", rr))
			continue
		}
		dnskey := zTypedKey.ToVanillaType()

		switch dnskey.Flags {
		case keySigningKeyFlag:
			ksks[dnskey.KeyTag()] = dnskey
		case zoneSigningKeyFlag:
			zsks[dnskey.KeyTag()] = dnskey
		default:
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Unexpected DNSKEY flag %d in DNSKEY answer", dnskey.Flags))
		}
	}

	// Error if no KSK/ZSK is found
	if len(ksks) == 0 || len(zsks) == 0 {
		return nil, nil, trace, errors.New("missing at least one KSK or ZSK in DNSKEY answer")
	}

	// Validate KSKs with DS records
	ksks, trace, err = v.validateDSRecords(signerDomain, ksks, trace, depth)
	if err != nil || ksks == nil {
		return nil, nil, trace, errors.Wrap(err, "DS validation failed")
	}

	return ksks, zsks, trace, nil
}

// validateDSRecords validates DS records against DNSKEY records,
// dropping KSKs with no matching DS record.
//
// Parameters:
// - signerDomain: The signer domain to query for DS records
// - dnskeyMap: A map of KeyTag to KSKs to validate against
// - trace: The trace context for tracking request path
// - depth: The recursion depth for logging purposes
//
// Returns:
// - map[uint16]*dns.DNSKEY: Map of validated KSKs
// - Trace: Updated trace context
// - error: If validation fails for any DS record
func (v *dNSSECValidator) validateDSRecords(signerDomain string, dnskeyMap map[uint16]*dns.DNSKEY, trace Trace, depth int) (map[uint16]*dns.DNSKEY, Trace, error) {
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
		if status != StatusNoError || err != nil || (res.DNSSECResult != nil && res.DNSSECResult.Status != DNSSECSecure) {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: Failed to get DS records for signer domain %s, query status: %s,  err: %v", signerDomain, status, err))
			return nil, trace, fmt.Errorf("failed to get DS records for signer domain %s", signerDomain)
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

	validatedKSKs := make(map[uint16]*dns.DNSKEY)
	for _, ksk := range dnskeyMap {
		authenticDS, ok := dsRecords[ksk.KeyTag()]
		if !ok {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: No DS record found for KSK with KeyTag %d", ksk.KeyTag()))
			continue
		}

		actualDS := ksk.ToDS(authenticDS.DigestType)
		actualDigest := strings.ToUpper(actualDS.Digest)
		authenticDigest := strings.ToUpper(authenticDS.Digest)
		if actualDigest != authenticDigest {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: DS record mismatch for KSK with KeyTag %d: expected %s, got %s", ksk.KeyTag(), authenticDigest, actualDigest))
		} else {
			v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: DS record for KSK with KeyTag %d is valid", ksk.KeyTag()))

			v.ds[*actualDS] = true
			validatedKSKs[ksk.KeyTag()] = ksk
		}
	}

	if len(validatedKSKs) == 0 {
		return nil, trace, errors.New("no valid KSK found")
	}

	return validatedKSKs, trace, nil
}

// validateRRSIG verifies RRSIGs for a given RRset using appropriate DNSKEYs.
// For DNSKEY RRsets, KSKs from the answer are used. For other types,
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

	// If RRset type is DNSKEY, use parsed KSKs from the answer directly
	if rrSetType == dns.TypeDNSKEY {
		dnskeyMap, err = parseKSKsFromAnswer(rrSet)
		if err != nil {
			return nil, trace, fmt.Errorf("failed to parse KSKs from DNSKEY answer: %v", err)
		}
	} else {
		// For other RRset types, fetch DNSKEYs for each RRSIG's signer domain
		for _, rrsig := range rrsigs {
			v.r.verboseLog(depth, "DNSSEC: Verifying RRSIG with signer", rrsig.SignerName)

			_, zskMap, updatedTrace, err := v.getDNSKEYs(rrsig.SignerName, trace, depth+1)
			dnskeyMap = zskMap
			if err != nil {
				return nil, updatedTrace, fmt.Errorf("failed to retrieve DNSKEYs for signer domain %s: %v", rrsig.SignerName, err)
			}
			trace = updatedTrace
		}
	}

	// Attempt to verify each RRSIG using only the DNSKEY matching its KeyTag
	for _, rrsig := range rrsigs {
		keyTag := rrsig.KeyTag

		// Check if the RRSIG is still valid
		if !rrsig.ValidityPeriod(time.Now()) {
			v.r.verboseLog(depth, "DNSSEC: RRSIG with keytag=", keyTag, "has expired or is not yet valid")
			continue
		}

		matchingKey, found := dnskeyMap[keyTag]
		if !found {
			return nil, trace, fmt.Errorf("no matching DNSKEY found for RRSIG with key tag %d", keyTag)
		}

		// Verify the RRSIG with the matching DNSKEY
		if err := rrsig.Verify(matchingKey, rrSet); err == nil {
			v.dNSKEY[*matchingKey] = true
			return rrsig, trace, nil
		}

		v.r.verboseLog(depth, fmt.Sprintf("DNSSEC: RRSIG with keytag=%d failed to verify", keyTag))
	}

	return nil, trace, errors.New("could not verify any RRSIG for RRset")
}
