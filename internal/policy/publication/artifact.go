package publication

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	policyHashDomain = "meshtransit/policy-release/v1\x00"
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
}

// NewCandidate validates and hashes one compiled policy artifact.
func NewCandidate(snapshot policy.Snapshot, compilerFormatVersion int) (Candidate, error) {
	if !snapshot.IsValid() || compilerFormatVersion <= 0 ||
		compilerFormatVersion > MaximumCompilerFormatVersion {
		return Candidate{}, ErrInvalidCandidate
	}
	candidate := Candidate{
		snapshot:              snapshot,
		compilerFormatVersion: compilerFormatVersion,
		semanticHash:          hashCandidate(snapshot, compilerFormatVersion),
	}
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

// IsValid reports whether all candidate fields and their digest agree.
func (candidate Candidate) IsValid() bool {
	return candidate.snapshot.IsValid() && candidate.compilerFormatVersion > 0 &&
		candidate.compilerFormatVersion <= MaximumCompilerFormatVersion &&
		candidate.semanticHash.IsValid() &&
		candidate.semanticHash == hashCandidate(candidate.snapshot, candidate.compilerFormatVersion)
}

func hashCandidate(snapshot policy.Snapshot, compilerFormatVersion int) SemanticHash {
	rules := snapshot.Rules()
	encoded := make([]byte, 0, len(policyHashDomain)+40+len(rules)*80)
	encoded = append(encoded, policyHashDomain...)
	workspaceID := snapshot.Scope().WorkspaceID().Bytes()
	networkID := snapshot.Scope().NetworkID().Bytes()
	encoded = append(encoded, workspaceID[:]...)
	encoded = append(encoded, networkID[:]...)
	encoded = appendInt64(encoded, int64(compilerFormatVersion))
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
