package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

// RecordVersion is the shape of an audit record outside the database: the
// read API, exports and any search index use exactly these fields, so a
// document from any of them can be checked against its seal.
const RecordVersion = 2

// Audit results.
const (
	ResultSucceeded = "succeeded"
	ResultDenied    = "denied"
	ResultFailed    = "failed"
)

// Integrity states.
const (
	IntegritySealed         = "sealed"
	IntegrityLegacyUnsealed = "legacy_unsealed"
)

// Actor kinds. An event without a principal was written by MeshCore itself.
const (
	ActorPrincipal = "principal"
	ActorSystem    = "system"
)

// RecordTimeLayout is fixed at microseconds, the database precision, so the
// text form round-trips to the sealed value.
const RecordTimeLayout = "2006-01-02T15:04:05.000000Z"

// ErrInvalidRecord reports a record that does not parse into seal material.
var ErrInvalidRecord = errors.New("audit: invalid record")

// Record is one audit event, flat and self-describing: tenant scope travels
// as public identifiers, so filtering needs no join. Payload is the parsed
// object for display and search; PayloadCanonical is the exact sealed text.
type Record struct {
	RecordVersion      int             `json:"record_version"`
	EventID            string          `json:"event_id"`
	EventTime          string          `json:"event_time"`
	StreamID           string          `json:"stream_id"`
	Sequence           int64           `json:"sequence"`
	WorkspaceID        string          `json:"workspace_id,omitempty"`
	NetworkID          string          `json:"network_id,omitempty"`
	ChangeID           string          `json:"change_id"`
	ActorKind          string          `json:"actor_kind"`
	ActorPrincipalID   string          `json:"actor_principal_id,omitempty"`
	Action             string          `json:"action"`
	Permission         string          `json:"permission"`
	Result             string          `json:"result"`
	TargetKind         string          `json:"target_kind"`
	TargetID           string          `json:"target_id"`
	CorrelationID      string          `json:"correlation_id,omitempty"`
	BeforeSemanticHash string          `json:"before_semantic_hash,omitempty"`
	AfterSemanticHash  string          `json:"after_semantic_hash,omitempty"`
	PayloadVersion     int64           `json:"payload_version"`
	Payload            map[string]any  `json:"payload"`
	PayloadCanonical   string          `json:"payload_canonical"`
	Integrity          RecordIntegrity `json:"integrity"`
}

// RecordIntegrity carries the seal chain link. Legacy events have no seal.
type RecordIntegrity struct {
	Status       string `json:"status"`
	HashVersion  int    `json:"hash_version,omitempty"`
	PreviousSeal string `json:"previous_seal,omitempty"`
	Seal         string `json:"seal,omitempty"`
}

// SealMaterial parses a sealed record back into the fields its seal covers.
func (record Record) SealMaterial() (SealMaterial, error) {
	if record.RecordVersion != RecordVersion || record.Integrity.Status != IntegritySealed ||
		record.Integrity.HashVersion != SealHashVersion {
		return SealMaterial{}, ErrInvalidRecord
	}
	occurred, err := time.Parse(RecordTimeLayout, record.EventTime)
	if err != nil {
		return SealMaterial{}, ErrInvalidRecord
	}
	material := SealMaterial{
		Sequence: record.Sequence, OccurredAt: occurred, Action: record.Action,
		Permission: record.Permission, TargetKind: record.TargetKind, Result: record.Result,
		PayloadVersion: record.PayloadVersion, PayloadCanonical: record.PayloadCanonical,
	}
	required := []struct {
		text   string
		target *publicid.ID
	}{
		{record.StreamID, &material.StreamID}, {record.EventID, &material.EventID},
		{record.ChangeID, &material.ChangeID}, {record.TargetID, &material.TargetID},
	}
	for _, field := range required {
		if *field.target, err = publicid.Parse(field.text); err != nil {
			return SealMaterial{}, ErrInvalidRecord
		}
	}
	optional := []struct {
		text   string
		target *publicid.ID
	}{
		{record.WorkspaceID, &material.WorkspaceID}, {record.NetworkID, &material.NetworkID},
		{record.ActorPrincipalID, &material.ActorPrincipalID}, {record.CorrelationID, &material.CorrelationID},
	}
	for _, field := range optional {
		if field.text == "" {
			continue
		}
		if *field.target, err = publicid.Parse(field.text); err != nil {
			return SealMaterial{}, ErrInvalidRecord
		}
	}
	if (record.ActorKind == ActorSystem) != (record.ActorPrincipalID == "") ||
		(record.ActorKind != ActorSystem && record.ActorKind != ActorPrincipal) {
		return SealMaterial{}, ErrInvalidRecord
	}
	if !decodeHash(record.Integrity.PreviousSeal, &material.PreviousSeal) {
		return SealMaterial{}, ErrInvalidRecord
	}
	if material.BeforeSemanticHash, err = decodeOptionalHash(record.BeforeSemanticHash); err != nil {
		return SealMaterial{}, err
	}
	if material.AfterSemanticHash, err = decodeOptionalHash(record.AfterSemanticHash); err != nil {
		return SealMaterial{}, err
	}
	return material, nil
}

// VerifySeal recomputes a sealed record's seal and compares it.
func (record Record) VerifySeal() error {
	material, err := record.SealMaterial()
	if err != nil {
		return err
	}
	var stated [sha256.Size]byte
	if !decodeHash(record.Integrity.Seal, &stated) {
		return ErrInvalidRecord
	}
	computed, err := Seal(material)
	if err != nil {
		return err
	}
	if computed != stated {
		return ErrInvalidRecord
	}
	return nil
}

// HashText is the lowercase hex form used for every hash in a record.
func HashText(value []byte) string {
	return hex.EncodeToString(value)
}

func decodeHash(text string, target *[sha256.Size]byte) bool {
	if len(text) != hex.EncodedLen(sha256.Size) {
		return false
	}
	_, err := hex.Decode(target[:], []byte(text))
	return err == nil
}

func decodeOptionalHash(text string) ([]byte, error) {
	if text == "" {
		return nil, nil
	}
	var value [sha256.Size]byte
	if !decodeHash(text, &value) {
		return nil, ErrInvalidRecord
	}
	return value[:], nil
}
