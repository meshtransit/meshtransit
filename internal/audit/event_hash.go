// Package audit owns canonical integrity material for immutable audit evidence.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	eventHashDomain      = "meshtransit/audit-event/v1\x00"
	maxEventLabelBytes   = 128
	canonicalLengthBytes = 8
)

// ErrInvalidEventHash reports incomplete or unbounded audit material.
var ErrInvalidEventHash = errors.New("audit: invalid event hash material")

// EventHashMaterial contains the immutable fields committed across the audit
// identity, business event, and outbox record. Zero NetworkRevision, actor,
// correlation, or semantic hashes explicitly encode an absent optional field.
type EventHashMaterial struct {
	PreviousHash       [sha256.Size]byte
	EventID            publicid.ID
	ChangeID           publicid.ID
	AggregateKind      string
	AggregateID        publicid.ID
	AggregateVersion   int64
	NetworkRevision    int64
	ActorPrincipalID   publicid.ID
	Action             string
	Permission         string
	CorrelationID      publicid.ID
	BeforeSemanticHash [sha256.Size]byte
	AfterSemanticHash  [sha256.Size]byte
	AuditPayloadHash   [sha256.Size]byte
	OutboxEventClass   string
	OutboxPayloadHash  [sha256.Size]byte
}

// HashEvent returns the domain-separated canonical SHA-256 chain value. The
// encoding is length-delimited so distinct field boundaries cannot collide.
func HashEvent(material EventHashMaterial) ([sha256.Size]byte, error) {
	if !material.EventID.IsValid() || !material.ChangeID.IsValid() ||
		!material.AggregateID.IsValid() || material.AggregateVersion <= 0 ||
		material.NetworkRevision < 0 || !validLabel(material.AggregateKind) ||
		!validLabel(material.Action) || !validLabel(material.Permission) ||
		!validLabel(material.OutboxEventClass) ||
		(!isZeroID(material.ActorPrincipalID) && !material.ActorPrincipalID.IsValid()) ||
		(!isZeroID(material.CorrelationID) && !material.CorrelationID.IsValid()) ||
		material.AuditPayloadHash == ([sha256.Size]byte{}) ||
		material.OutboxPayloadHash == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, ErrInvalidEventHash
	}

	encoded := make([]byte, 0, 512)
	encoded = appendBytes(encoded, []byte(eventHashDomain))
	encoded = appendBytes(encoded, material.PreviousHash[:])
	encoded = appendID(encoded, material.EventID)
	encoded = appendID(encoded, material.ChangeID)
	encoded = appendString(encoded, material.AggregateKind)
	encoded = appendID(encoded, material.AggregateID)
	encoded = appendInt64(encoded, material.AggregateVersion)
	encoded = appendInt64(encoded, material.NetworkRevision)
	encoded = appendOptionalID(encoded, material.ActorPrincipalID)
	encoded = appendString(encoded, material.Action)
	encoded = appendString(encoded, material.Permission)
	encoded = appendOptionalID(encoded, material.CorrelationID)
	encoded = appendOptionalHash(encoded, material.BeforeSemanticHash)
	encoded = appendOptionalHash(encoded, material.AfterSemanticHash)
	encoded = appendBytes(encoded, material.AuditPayloadHash[:])
	encoded = appendString(encoded, material.OutboxEventClass)
	encoded = appendBytes(encoded, material.OutboxPayloadHash[:])
	return sha256.Sum256(encoded), nil
}

func validLabel(value string) bool {
	if len(value) == 0 || len(value) > maxEventLabelBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func appendID(output []byte, id publicid.ID) []byte {
	value := id.Bytes()
	return appendBytes(output, value[:])
}

func appendOptionalID(output []byte, id publicid.ID) []byte {
	if isZeroID(id) {
		return appendBytes(output, nil)
	}
	return appendID(output, id)
}

func appendOptionalHash(output []byte, value [sha256.Size]byte) []byte {
	if value == ([sha256.Size]byte{}) {
		return appendBytes(output, nil)
	}
	return appendBytes(output, value[:])
}

func appendString(output []byte, value string) []byte {
	return appendBytes(output, []byte(value))
}

func appendInt64(output []byte, value int64) []byte {
	var encoded [binary.MaxVarintLen64]byte
	length := binary.PutVarint(encoded[:], value)
	return appendBytes(output, encoded[:length])
}

func appendBytes(output []byte, value []byte) []byte {
	var length [canonicalLengthBytes]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

func isZeroID(id publicid.ID) bool {
	return id == publicid.ID{}
}
