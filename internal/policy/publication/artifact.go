package publication

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	policyHashDomainV1       = "meshtransit/policy-release/v1\x00"
	policyHashDomainV2       = "meshtransit/policy-release/v2\x00"
	resourceCompilerFormatV2 = 2
	// MaximumCompilerFormatVersion bounds the version encoded in durable releases.
	MaximumCompilerFormatVersion = 65535
)

// ErrInvalidCandidate reports an unsafe or internally inconsistent compiled candidate.
var ErrInvalidCandidate = errors.New("policy publication: invalid candidate")

// SemanticHash is the canonical SHA-256 digest of compiled packet semantics.
type SemanticHash [sha256.Size]byte

// NewSemanticHash validates a non-zero canonical digest loaded at a boundary.
func NewSemanticHash(value [sha256.Size]byte) (SemanticHash, error) {
	hash := SemanticHash(value)
	if !hash.IsValid() {
		return SemanticHash{}, ErrInvalidCandidate
	}
	return hash, nil
}

// Bytes returns a copy of the digest.
func (hash SemanticHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether the digest is non-zero.
func (hash SemanticHash) IsValid() bool { return hash != SemanticHash{} }

// Candidate is a complete immutable compiled policy ready for short activation.
// Its semantic hash excludes the allocated revision so identical semantics hash
// identically across rollback or re-publication.
type Candidate struct {
	snapshot              policy.Snapshot
	compilerFormatVersion int
	semanticHash          SemanticHash
	resourceDestinations  []ResourceDestination
}

// NewCandidate validates and hashes one compiled policy artifact.
func NewCandidate(snapshot policy.Snapshot, compilerFormatVersion int) (Candidate, error) {
	return newCandidate(snapshot, compilerFormatVersion, nil)
}

// NewCandidateWithResourceDestinations constructs a format-v2 candidate whose
// compiled Device edges retain exact Resource resolution provenance.
func NewCandidateWithResourceDestinations(
	snapshot policy.Snapshot,
	destinations []ResourceDestination,
) (Candidate, error) {
	if len(destinations) == 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	return newCandidate(snapshot, resourceCompilerFormatV2, destinations)
}

func newCandidate(
	snapshot policy.Snapshot,
	compilerFormatVersion int,
	destinations []ResourceDestination,
) (Candidate, error) {
	if !snapshot.IsValid() || compilerFormatVersion <= 0 ||
		compilerFormatVersion > MaximumCompilerFormatVersion {
		return Candidate{}, ErrInvalidCandidate
	}
	destinations = cloneResourceDestinations(destinations)
	slices.SortFunc(destinations, compareResourceDestinations)
	candidate := Candidate{
		snapshot:              snapshot,
		compilerFormatVersion: compilerFormatVersion,
		resourceDestinations:  destinations,
	}
	candidate.semanticHash = hashCandidate(candidate)
	if !candidate.IsValid() {
		return Candidate{}, ErrInvalidCandidate
	}
	return candidate, nil
}

// Snapshot returns the immutable Node-resolved packet policy.
func (candidate Candidate) Snapshot() policy.Snapshot { return candidate.snapshot }

// CompilerFormatVersion returns the bounded compiler representation version.
func (candidate Candidate) CompilerFormatVersion() int { return candidate.compilerFormatVersion }

// SemanticHash returns the canonical compiled semantics digest.
func (candidate Candidate) SemanticHash() SemanticHash { return candidate.semanticHash }

// ResourceDestinations returns caller-owned Resource resolution provenance.
func (candidate Candidate) ResourceDestinations() []ResourceDestination {
	return cloneResourceDestinations(candidate.resourceDestinations)
}

// IsValid reports whether all candidate fields and their digest agree.
func (candidate Candidate) IsValid() bool {
	return candidate.snapshot.IsValid() && candidate.compilerFormatVersion > 0 &&
		candidate.compilerFormatVersion <= MaximumCompilerFormatVersion &&
		validResourceDestinations(candidate) &&
		candidate.semanticHash.IsValid() &&
		candidate.semanticHash == hashCandidate(candidate)
}

func validResourceDestinations(candidate Candidate) bool {
	destinations := candidate.resourceDestinations
	if len(destinations) == 0 {
		return true
	}
	if candidate.compilerFormatVersion != resourceCompilerFormatV2 ||
		len(destinations) > len(candidate.snapshot.Rules()) {
		return false
	}
	rules := candidate.snapshot.Rules()
	for index, destination := range destinations {
		if !destination.IsValid() || destination.reference.Scope() != candidate.snapshot.Scope() ||
			(index > 0 && (destinations[index-1].ruleID == destination.ruleID ||
				compareResourceDestinations(destinations[index-1], destination) >= 0)) {
			return false
		}
		matches := 0
		for _, rule := range rules {
			if rule.ID() == destination.ruleID &&
				rule.DestinationNodeID() == destination.destinationNodeID {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func hashCandidate(candidate Candidate) SemanticHash {
	rules := candidate.snapshot.Rules()
	domain := policyHashDomainV1
	if len(candidate.resourceDestinations) > 0 {
		domain = policyHashDomainV2
	}
	encoded := make(
		[]byte,
		0,
		len(domain)+48+len(rules)*80+len(candidate.resourceDestinations)*128,
	)
	encoded = append(encoded, domain...)
	workspaceID := candidate.snapshot.Scope().WorkspaceID().Bytes()
	networkID := candidate.snapshot.Scope().NetworkID().Bytes()
	encoded = append(encoded, workspaceID[:]...)
	encoded = append(encoded, networkID[:]...)
	encoded = appendInt64(encoded, int64(candidate.compilerFormatVersion))
	encoded = appendUint64(encoded, uint64(len(rules)))
	for _, rule := range rules {
		ruleID := publicid.ID(rule.ID()).Bytes()
		sourceID := publicid.ID(rule.SourceNodeID()).Bytes()
		destinationID := publicid.ID(rule.DestinationNodeID()).Bytes()
		encoded = append(encoded, ruleID[:]...)
		encoded = append(encoded, sourceID[:]...)
		encoded = append(encoded, destinationID[:]...)
		encoded = append(encoded, byte(rule.Protocol()))
		portRanges := rule.DestinationPortRanges()
		encoded = appendUint64(encoded, uint64(len(portRanges)))
		for _, portRange := range portRanges {
			encoded = appendUint16(encoded, portRange.First())
			encoded = appendUint16(encoded, portRange.Last())
		}
	}
	if len(candidate.resourceDestinations) > 0 {
		encoded = appendUint64(encoded, uint64(len(candidate.resourceDestinations)))
		for _, destination := range candidate.resourceDestinations {
			ruleID := publicid.ID(destination.ruleID).Bytes()
			resourceID := destination.reference.ResourceID().Bytes()
			destinationID := publicid.ID(destination.destinationNodeID).Bytes()
			resourceHash := destination.resourceSemanticHash.Bytes()
			encoded = append(encoded, ruleID[:]...)
			encoded = append(encoded, resourceID[:]...)
			encoded = appendInt64(encoded, destination.reference.ResourceVersion())
			encoded = appendInt64(encoded, destination.reference.TargetGeneration())
			encoded = appendInt64(encoded, destination.inventoryRevision)
			encoded = append(encoded, destinationID[:]...)
			encoded = append(encoded, resourceHash[:]...)
		}
	}
	return SemanticHash(sha256.Sum256(encoded))
}

func appendUint16(output []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(output, encoded[:]...)
}

func appendUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}

func appendInt64(output []byte, value int64) []byte {
	var encoded [binary.MaxVarintLen64]byte
	length := binary.PutVarint(encoded[:], value)
	return append(output, encoded[:length]...)
}
