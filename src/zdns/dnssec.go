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
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	rootanchors "github.com/zmap/go-dns-root-anchors"
)

const rootZone = "."
const (
	zoneSigningKeyFlag = 256
	keySigningKeyFlag  = 257
)

func (r *Resolver) validateChainOfDNSSECTrust(ctx context.Context, msg *dns.Msg, q Question, nameServer *NameServer, isIterative bool, depth int, trace Trace) (bool, Trace, error) {
	typeToRRSets := make(map[uint16][]dns.RR)
	typeToRRSigs := make(map[uint16][]*dns.RRSIG)

	// Extract all the RRSets from the message
	for _, rr := range msg.Answer {
		rrType := rr.Header().Rrtype
		if rrType == dns.TypeRRSIG {
			rrSig := rr.(*dns.RRSIG)
			typeToRRSigs[rrSig.TypeCovered] = append(typeToRRSigs[rrSig.TypeCovered], rrSig)
		} else {
			typeToRRSets[rrType] = append(typeToRRSets[rrType], rr)
		}
	}

	// Shortcut checks on RRSIG cardinality
	if len(typeToRRSigs) == 0 {
		// No RRSIGs, possibly because DNSSEC is not enabled... or we are hijacked
		r.verboseLog(depth+1, "DNSSEC: No RRSIGs found")
		return false, trace, nil
	}

	if len(typeToRRSets) != len(typeToRRSigs) {
		return false, trace, errors.New("mismatched number of RRsets and RRSIGs")
	}

	// Verify if for each RRset there is a corresponding RRSIG
	for rrType := range typeToRRSets {
		if _, ok := typeToRRSigs[rrType]; !ok {
			return false, trace, fmt.Errorf("found RRset for type %s but no RRSIG", dns.TypeToString[rrType])
		}
	}

	r.verboseLog(depth+1, fmt.Sprintf("DNSSEC: Found %d RRsets and %d RRSIGs", len(typeToRRSets), len(typeToRRSigs)))

	passed, trace, err := r.validateRRSIGs(ctx, typeToRRSets, typeToRRSigs, nameServer, isIterative, trace, depth)
	if err != nil {
		return false, trace, errors.Wrap(err, "could not validate RRSIGs")
	}

	return passed, trace, nil
}

// parseKSKsFromAnswer extracts only KSKs (Key Signing Keys) from a DNSKEY RRset answer,
// populating a map where the KeyTag is the key and the DNSKEY is the value.
// This function skips ZSKs and returns an error if any unexpected flags or types are encountered.
//
// Parameters:
// - rrSet: The DNSKEY RRset answer to parse.
//
// Returns:
// - map[uint16]*dns.DNSKEY: A map of KeyTag to KSKs.
// - error: An error if an unexpected flag or type is encountered.
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

// getDNSKEYs retrieves and separates KSKs and ZSKs from the signer domain's DNSKEYs,
// returning maps of KeyTags to DNSKEYs for both KSKs and ZSKs.
//
// Parameters:
// - ctx: Context for cancellation and timeout control.
// - signerDomain: The signer domain extracted from the RRSIG's SignerName field.
// - nameServer: The nameserver to use for the DNS query.
// - isIterative: Boolean indicating if the query should be iterative.
// - trace: The trace context for tracking the request path.
// - depth: The recursion or verification depth for logging purposes.
//
// Returns:
// - ksks: Map of KeyTag to KSKs (Key Signing Keys) retrieved from the signer domain.
// - zsks: Map of KeyTag to ZSKs (Zone Signing Keys) retrieved from the signer domain.
// - Trace: Updated trace context with the DNSKEY query included.
// - error: If the DNSKEY query fails or returns an unexpected status.
func (r *Resolver) getDNSKEYs(ctx context.Context, signerDomain string, nameServer *NameServer, isIterative bool, trace Trace, depth int) (map[uint16]*dns.DNSKEY, map[uint16]*dns.DNSKEY, Trace, error) {
	ksks := make(map[uint16]*dns.DNSKEY)
	zsks := make(map[uint16]*dns.DNSKEY)

	retries := r.retries
	nameWithoutTrailingDot := strings.TrimSuffix(dns.CanonicalName(signerDomain), rootZone)
	if signerDomain == rootZone {
		nameWithoutTrailingDot = rootZone
	}

	dnskeyQuestion := QuestionWithMetadata{
		Q: Question{
			Name:  nameWithoutTrailingDot,
			Type:  dns.TypeDNSKEY,
			Class: dns.ClassINET,
		},
		RetriesRemaining: &retries,
	}

	res, trace, status, err := r.lookup(ctx, &dnskeyQuestion, r.rootNameServers, isIterative, trace)
	if status != StatusNoError || err != nil {
		return nil, nil, trace, fmt.Errorf("cannot get DNSKEYs for signer domain %s, status: %s, err: %v", signerDomain, status, err)
	}

	// RRSIGs of res should have been verified before returning to here.

	// Separate DNSKEYs into KSKs and ZSKs maps based on flags
	for _, rr := range res.Answers {
		zTypedKey, ok := rr.(DNSKEYAnswer)
		if !ok {
			r.verboseLog(depth, fmt.Sprintf("DNSSEC: Non-DNSKEY RR type in DNSKEY answer: %v", rr))
			continue
		}
		dnskey := zTypedKey.ToVanillaType()

		switch dnskey.Flags {
		case keySigningKeyFlag:
			ksks[dnskey.KeyTag()] = dnskey
		case zoneSigningKeyFlag:
			zsks[dnskey.KeyTag()] = dnskey
		default:
			r.verboseLog(depth, fmt.Sprintf("DNSSEC: Unexpected DNSKEY flag %d in DNSKEY answer", dnskey.Flags))
		}
	}

	// Error if no KSK/ZSK is found
	if len(ksks) == 0 || len(zsks) == 0 {
		return nil, nil, trace, errors.New("missing at least one KSK or ZSK in DNSKEY answer")
	}

	// Validate KSKs with DS records
	if valid, trace, err := r.validateDSRecords(ctx, signerDomain, ksks, nameServer, isIterative, trace, depth); !valid {
		return nil, nil, trace, errors.Wrap(err, "DS validation failed")
	}

	return ksks, zsks, trace, nil
}

// validateDSRecords validates DS records against DNSKEY records.
//
// Parameters:
// - ctx: Context for cancellation and timeout control.
// - signerDomain: The signer domain to query for DS records.
// - dnskeyMap: A map of KeyTag to KSKs to validate against.
// - nameServer: The nameserver to use for the DNS query.
// - isIterative: Boolean indicating if the query should be iterative.
// - trace: The trace context for tracking the request path.
// - depth: The recursion or verification depth for logging purposes.
//
// Returns:
// - bool: Returns true if all DS records are valid; otherwise, false.
// - Trace: Updated trace context with the DS query included.
// - error: If validation fails for any DS record, returns an error with details.
func (r *Resolver) validateDSRecords(ctx context.Context, signerDomain string, dnskeyMap map[uint16]*dns.DNSKEY, nameServer *NameServer, isIterative bool, trace Trace, depth int) (bool, Trace, error) {
	retries := r.retries
	nameWithoutTrailingDot := strings.TrimSuffix(dns.CanonicalName(signerDomain), rootZone)

	dsQuestion := QuestionWithMetadata{
		Q: Question{
			Name:  nameWithoutTrailingDot,
			Type:  dns.TypeDS,
			Class: dns.ClassINET,
		},
		RetriesRemaining: &retries,
	}

	dsRecords := make(map[uint16]dns.DS)
	if signerDomain == rootZone {
		// Root zone, use the root anchors
		dsRecords = rootanchors.GetValidDSRecords()
	} else {
		res, trace, status, err := r.lookup(ctx, &dsQuestion, r.rootNameServers, isIterative, trace)
		if status != StatusNoError || err != nil {
			return false, trace, fmt.Errorf("cannot get DS records for signer domain %s, status: %s, err: %v", signerDomain, status, err)
		}

		// RRSIGs of res should have been verified before returning to here.

		for _, rr := range res.Answers {
			zTypedDS, ok := rr.(DSAnswer)
			if !ok {
				r.verboseLog(depth, fmt.Sprintf("DNSSEC: Non-DS RR type in DS answer: %v", rr))
				continue
			}
			ds := zTypedDS.ToVanillaType()
			dsRecords[ds.KeyTag] = *ds
		}
	}

	for _, ksk := range dnskeyMap {
		authenticDS, ok := dsRecords[ksk.KeyTag()]
		if !ok {
			return false, trace, fmt.Errorf("no DS record found for KSK with KeyTag %d", ksk.KeyTag())
		}

		actualDS := ksk.ToDS(authenticDS.DigestType)
		actualDigest := strings.ToUpper(actualDS.Digest)
		authenticDigest := strings.ToUpper(authenticDS.Digest)
		if actualDigest != authenticDigest {
			r.verboseLog(depth, fmt.Sprintf("DNSSEC: DS record mismatch for KSK with KeyTag %d: expected %s, got %s", ksk.KeyTag(), authenticDigest, actualDigest))
			return false, trace, fmt.Errorf("DS record mismatch for KSK with KeyTag %d", ksk.KeyTag())
		}
	}

	return true, trace, nil
}

// validateRRSIG verifies multiple RRSIGs for a given RRset. For each RRSIG, it retrieves the necessary
// DNSKEYs (KSKs for DNSKEY RRsets, ZSKs for others) from either the answer directly (for DNSKEY types) or
// by querying the signer domain. Each RRSIG is validated only with the DNSKEY matching its KeyTag.
//
// Parameters:
// - ctx: Context for cancellation and timeout control.
// - rrSetType: The type of the RRset (e.g., dns.TypeA, dns.TypeDNSKEY).
// - rrSet: The RRset that is being verified.
// - rrsigs: A slice of RRSIGs associated with the RRset.
// - nameServer: The nameserver to use for DNSKEY retrievals.
// - isIterative: Boolean indicating if the DNSKEY queries should be iterative.
// - trace: The trace context for tracking the request path.
// - depth: The recursion or verification depth for logging purposes.
//
// Returns:
// - bool: Returns true if at least one RRSIG is successfully verified for the RRset.
// - Trace: Updated trace context including the DNSKEY retrievals and verifications.
// - error: If no RRSIG is verified, returns an error describing the failure.
func (r *Resolver) validateRRSIG(ctx context.Context, rrSetType uint16, rrSet []dns.RR, rrsigs []*dns.RRSIG, nameServer *NameServer, isIterative bool, trace Trace, depth int) (bool, Trace, error) {
	var dnskeyMap map[uint16]*dns.DNSKEY
	var err error

	// If RRset type is DNSKEY, use pre-parsed KSKs from the answer directly
	if rrSetType == dns.TypeDNSKEY {
		dnskeyMap, err = parseKSKsFromAnswer(rrSet)
		if err != nil {
			return false, trace, fmt.Errorf("failed to parse KSKs from DNSKEY answer: %v", err)
		}
	} else {
		// For other RRset types, fetch DNSKEYs for each RRSIG's signer domain
		for _, rrsig := range rrsigs {
			r.verboseLog(depth, fmt.Sprintf("DNSSEC: Verifying RRSIG with signer %s", rrsig.SignerName))

			_, zskMap, updatedTrace, err := r.getDNSKEYs(ctx, rrsig.SignerName, nameServer, isIterative, trace, depth+1)
			dnskeyMap = zskMap
			if err != nil {
				return false, updatedTrace, fmt.Errorf("failed to retrieve DNSKEYs for signer domain %s: %v", rrsig.SignerName, err)
			}
			trace = updatedTrace
		}
	}

	// Attempt to verify each RRSIG using only the DNSKEY matching its KeyTag
	for _, rrsig := range rrsigs {
		keyTag := rrsig.KeyTag
		matchingKey, found := dnskeyMap[keyTag]
		if !found {
			return false, trace, fmt.Errorf("no matching DNSKEY found for RRSIG with key tag %d", keyTag)
		}

		// Verify the RRSIG with the matching DNSKEY
		if err := rrsig.Verify(matchingKey, rrSet); err == nil {
			return true, trace, nil
		}
		r.verboseLog(depth, fmt.Sprintf("DNSSEC: RRSIG with keytag=%d failed to verify", keyTag))
	}

	return false, trace, fmt.Errorf("could not verify any RRSIG for RRset")
}

// validateRRSIGs verifies multiple RRsets and their corresponding RRSIGs. It iterates over each RRset, retrieves
// the RRSIGs, and attempts to verify each RRSIG using validateRRSIG, using KSKs for DNSKEY RRset type and ZSKs
// for other types.
//
// Parameters:
// - ctx: Context for cancellation and timeout control.
// - typeToRRSets: A map of RR types to slices of DNS Resource Records (RRsets) of that type.
// - typeToRRSigs: A map of RR types to slices of RRSIGs associated with each RRset.
// - nameServer: The nameserver to use for DNSKEY retrievals.
// - isIterative: Boolean indicating if the DNSKEY queries should be iterative.
// - depth: The recursion or verification depth for logging purposes.
//
// Returns:
// - bool: Returns true if all RRSIGs for all RRsets are verified; otherwise, false if any RRSIG fails verification.
// - Trace: Updated trace context with all verification attempts included.
// - error: If verification fails for any RRSIG, returns an error with details.
func (r *Resolver) validateRRSIGs(ctx context.Context, typeToRRSets map[uint16][]dns.RR, typeToRRSigs map[uint16][]*dns.RRSIG, nameServer *NameServer, isIterative bool, trace Trace, depth int) (bool, Trace, error) {
	for rrType, rrSet := range typeToRRSets {
		rrsigs, ok := typeToRRSigs[rrType]
		if !ok || len(rrsigs) == 0 {
			return false, trace, fmt.Errorf("no RRSIG found for type %s", dns.TypeToString[rrType])
		}

		r.verboseLog(depth, fmt.Sprintf("DNSSEC: Verifying RRSIGs for type %s", dns.TypeToString[rrType]))

		// Validate the RRSIGs for the RRset using validateRRSIG
		passed, updatedTrace, err := r.validateRRSIG(ctx, rrType, rrSet, rrsigs, nameServer, isIterative, trace, depth+1)
		trace = updatedTrace
		if !passed {
			return false, trace, fmt.Errorf("could not verify any RRSIG for type %s: %v", dns.TypeToString[rrType], err)
		}
	}

	return true, trace, nil
}
