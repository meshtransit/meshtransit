package postgres

import (
	"encoding/json"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/node/revocation"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const (
	deviceRevocationOperation  = "device.revoke"
	deviceRevocationResultKind = "device_revocation"
)

type deviceRevocationIdempotencyRecord struct {
	publicID              string
	requestSemanticHash   []byte
	state                 string
	resultKind            string
	resultPublicID        string
	resultVersion         int64
	resultNetworkRevision int64
	resultPayload         string
	expiresAt             time.Time
	created               bool
}

type deviceRevocationResultPayload struct {
	NetworkRevision   int64  `json:"network_revision"`
	InventoryRevision int64  `json:"inventory_revision"`
	DevicePublicID    string `json:"device_public_id"`
	DeviceVersion     int64  `json:"device_version"`
	SessionGeneration int64  `json:"session_generation"`
	Terminal          bool   `json:"terminal"`
}

func scanDeviceRevocationIdempotencyRecord(
	row deviceRevocationRow,
	withCreated bool,
) (deviceRevocationIdempotencyRecord, error) {
	var record deviceRevocationIdempotencyRecord
	destinations := []any{
		&record.publicID,
		&record.requestSemanticHash,
		&record.state,
		&record.resultKind,
		&record.resultPublicID,
		&record.resultVersion,
		&record.resultNetworkRevision,
		&record.resultPayload,
		&record.expiresAt,
	}
	if withCreated {
		destinations = append(destinations, &record.created)
	}
	if err := row.Scan(destinations...); err != nil {
		return deviceRevocationIdempotencyRecord{}, err
	}
	record.expiresAt = record.expiresAt.UTC()
	return record, nil
}

func deviceRevocationRequestHash(value []byte) (revocation.RequestHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return revocation.RequestHash{}, ErrDeviceRevocationEvidence
	}
	copy(fixed[:], value)
	hash, err := revocation.NewRequestHash(fixed)
	if err != nil {
		return revocation.RequestHash{}, ErrDeviceRevocationEvidence
	}
	return hash, nil
}

func (record deviceRevocationIdempotencyRecord) completedResult(
	command revocation.Command,
) (revocation.Result, error) {
	if record.state != "completed" || record.resultKind != deviceRevocationResultKind ||
		record.resultPublicID == "" || record.resultVersion <= 1 ||
		record.resultNetworkRevision <= 1 {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}
	idempotencyRecordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}
	nodeID, err := node.ParseID(record.resultPublicID)
	if err != nil || nodeID != command.NodeID() {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}
	var payload deviceRevocationResultPayload
	if err := json.Unmarshal([]byte(record.resultPayload), &payload); err != nil {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}
	if !payload.Terminal || payload.DevicePublicID != record.resultPublicID ||
		payload.DeviceVersion != record.resultVersion ||
		payload.NetworkRevision != record.resultNetworkRevision {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}
	result, err := revocation.NewResult(revocation.ResultParams{
		IdempotencyRecordID: idempotencyRecordID,
		Scope:               command.Scope(),
		NodeID:              nodeID,
		DeviceVersion:       payload.DeviceVersion,
		SessionGeneration:   payload.SessionGeneration,
		NetworkRevision:     payload.NetworkRevision,
		InventoryRevision:   payload.InventoryRevision,
	})
	if err != nil {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}
	return result, nil
}

func resolveDeviceRevocationIdempotency(
	record deviceRevocationIdempotencyRecord,
	command revocation.Command,
	attempt revocation.Attempt,
) (revocation.Resolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return revocation.Resolution{}, revocation.ErrInvalidCommand
	}
	storedHash, err := deviceRevocationRequestHash(record.requestSemanticHash)
	if err != nil {
		return revocation.Resolution{}, err
	}
	if storedHash != requestHash {
		return revocation.Resolution{}, revocation.ErrIntentConflict
	}
	if !record.expiresAt.After(attempt.OccurredAt()) {
		return revocation.Resolution{}, revocation.ErrIdempotencyExpired
	}
	if record.created {
		if record.state != "pending" || record.publicID !=
			attempt.MutationIDs().IdempotencyRecordID().String() ||
			record.resultKind != "" || record.resultPublicID != "" ||
			record.resultVersion != 0 || record.resultNetworkRevision != 0 ||
			record.resultPayload != "{}" {
			return revocation.Resolution{}, ErrDeviceRevocationEvidence
		}
		return revocation.Resolution{}, nil
	}
	if record.state != "completed" {
		return revocation.Resolution{}, ErrDeviceRevocationEvidence
	}
	result, err := record.completedResult(command)
	if err != nil {
		return revocation.Resolution{}, err
	}
	resolution, err := revocation.NewCompletedResolution(result, storedHash)
	if err != nil {
		return revocation.Resolution{}, ErrDeviceRevocationEvidence
	}
	return resolution, nil
}

func deviceRevocationState(value string) (revocation.DeviceState, error) {
	switch value {
	case "active":
		return revocation.DeviceStateActive, nil
	case "expired":
		return revocation.DeviceStateExpired, nil
	case "revoked":
		return revocation.DeviceStateRevoked, nil
	case "deleted":
		return revocation.DeviceStateDeleted, nil
	default:
		return revocation.DeviceStateUnknown, ErrDeviceRevocationEvidence
	}
}

func deviceRevocationKeyState(value string) (revocation.KeyState, error) {
	switch value {
	case "active":
		return revocation.KeyStateActive, nil
	case "expired":
		return revocation.KeyStateExpired, nil
	case "revoked":
		return revocation.KeyStateRevoked, nil
	default:
		return revocation.KeyStateUnknown, ErrDeviceRevocationEvidence
	}
}

func deviceRevocationCommittedRecord(
	record deviceRevocationIdempotencyRecord,
	command revocation.Command,
	now time.Time,
) (revocation.Result, bool, error) {
	if record.publicID == "" {
		return revocation.Result{}, false, nil
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return revocation.Result{}, false, revocation.ErrInvalidCommand
	}
	storedHash, err := deviceRevocationRequestHash(record.requestSemanticHash)
	if err != nil {
		return revocation.Result{}, false, err
	}
	if storedHash != requestHash {
		return revocation.Result{}, false, revocation.ErrIntentConflict
	}
	if !record.expiresAt.After(now) {
		return revocation.Result{}, false, nil
	}
	if record.state != "completed" {
		return revocation.Result{}, false, ErrDeviceRevocationEvidence
	}
	result, err := record.completedResult(command)
	if err != nil {
		return revocation.Result{}, false, err
	}
	return result, true, nil
}
