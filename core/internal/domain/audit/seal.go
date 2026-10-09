package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/publicid"
)

// SealHashVersion is the only seal the database computes today.
const SealHashVersion = 2

const (
	sealDomain          = "meshtransit/audit-event/v2\x00"
	maxSealPayloadBytes = 16384
)

// SealMaterial is every field seal v2 covers, as stored and as exported. Zero
// Workspace, Network, actor and correlation identifiers and empty semantic
// hashes encode an absent value; a present semantic hash is 32 bytes and may
// itself be all zero. PayloadCanonical is the exact stored payload text.
type SealMaterial struct {
	PreviousSeal       [sha256.Size]byte
	StreamID           publicid.ID
	Sequence           int64
	EventID            publicid.ID
	OccurredAt         time.Time
	WorkspaceID        publicid.ID
	NetworkID          publicid.ID
	ChangeID           publicid.ID
	ActorPrincipalID   publicid.ID
	Action             string
	Permission         string
	TargetKind         string
	TargetID           publicid.ID
	Result             string
	CorrelationID      publicid.ID
	BeforeSemanticHash []byte
	AfterSemanticHash  []byte
	PayloadVersion     int64
	PayloadCanonical   string
}

// Seal returns the seal v2 value. It matches mesh_audit.seal_audit_event:
// a domain prefix, then each field as an 8-byte big-endian length followed
// by its bytes; integers are 8-byte big-endian and time is Unix microseconds.
func Seal(material SealMaterial) ([sha256.Size]byte, error) {
	if !validSealMaterial(material) {
		return [sha256.Size]byte{}, ErrInvalidEventHash
	}
	encoded := make([]byte, 0, 512+len(material.PayloadCanonical))
	encoded = append(encoded, sealDomain...)
	encoded = appendBytes(encoded, material.PreviousSeal[:])
	encoded = appendID(encoded, material.StreamID)
	encoded = appendFixedInt64(encoded, material.Sequence)
	encoded = appendID(encoded, material.EventID)
	encoded = appendFixedInt64(encoded, material.OccurredAt.UnixMicro())
	encoded = appendOptionalID(encoded, material.WorkspaceID)
	encoded = appendOptionalID(encoded, material.NetworkID)
	encoded = appendID(encoded, material.ChangeID)
	encoded = appendOptionalID(encoded, material.ActorPrincipalID)
	encoded = appendString(encoded, material.Action)
	encoded = appendString(encoded, material.Permission)
	encoded = appendString(encoded, material.TargetKind)
	encoded = appendID(encoded, material.TargetID)
	encoded = appendString(encoded, material.Result)
	encoded = appendOptionalID(encoded, material.CorrelationID)
	encoded = appendBytes(encoded, material.BeforeSemanticHash)
	encoded = appendBytes(encoded, material.AfterSemanticHash)
	encoded = appendFixedInt64(encoded, material.PayloadVersion)
	encoded = appendString(encoded, material.PayloadCanonical)
	return sha256.Sum256(encoded), nil
}

func validSealMaterial(material SealMaterial) bool {
	return material.StreamID.IsValid() && material.Sequence > 0 && material.EventID.IsValid() &&
		!material.OccurredAt.IsZero() && material.ChangeID.IsValid() && material.TargetID.IsValid() &&
		(isZeroID(material.WorkspaceID) || material.WorkspaceID.IsValid()) &&
		(isZeroID(material.NetworkID) || (material.NetworkID.IsValid() && !isZeroID(material.WorkspaceID))) &&
		(isZeroID(material.ActorPrincipalID) || material.ActorPrincipalID.IsValid()) &&
		(isZeroID(material.CorrelationID) || material.CorrelationID.IsValid()) &&
		validLabel(material.Action) && validLabel(material.Permission) && validLabel(material.TargetKind) &&
		validResult(material.Result) && material.PayloadVersion > 0 &&
		optionalHashLength(material.BeforeSemanticHash) && optionalHashLength(material.AfterSemanticHash) &&
		len(material.PayloadCanonical) >= 2 && len(material.PayloadCanonical) <= maxSealPayloadBytes &&
		utf8.ValidString(material.PayloadCanonical)
}

func optionalHashLength(value []byte) bool {
	return len(value) == 0 || len(value) == sha256.Size
}

func validResult(value string) bool {
	return value == ResultSucceeded || value == ResultDenied || value == ResultFailed
}

func appendFixedInt64(output []byte, value int64) []byte {
	var encoded [8]byte
	//nolint:gosec // G115: the bit pattern is the two's complement PostgreSQL int8send emits.
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	return appendBytes(output, encoded[:])
}
