package postgres

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

const (
	resourceCreateOperation       = "resource.create"
	resourceGroupCreateOperation  = "resource_group.create"
	resourceCreateResultKind      = "resource_creation"
	resourceGroupCreateResultKind = "resource_group_creation"
)

type resourceAuthorityIdempotencyRecord struct {
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

type resourceAuthorityResultPayload struct {
	Operation         string `json:"operation"`
	SubsystemRevision int64  `json:"subsystem_revision"`
	SemanticHash      string `json:"semantic_hash"`
}

func resourceAuthorityOperation(command authority.Command) string {
	if command.Operation() == authority.OperationCreateGroup {
		return resourceGroupCreateOperation
	}
	return resourceCreateOperation
}

func resourceAuthorityResultKind(command authority.Command) string {
	if command.Operation() == authority.OperationCreateGroup {
		return resourceGroupCreateResultKind
	}
	return resourceCreateResultKind
}

func scanResourceAuthorityIdempotencyRecord(
	row resourceAuthorityRow,
	withCreated bool,
) (resourceAuthorityIdempotencyRecord, error) {
	var record resourceAuthorityIdempotencyRecord
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
		return resourceAuthorityIdempotencyRecord{}, err
	}
	record.expiresAt = record.expiresAt.UTC()
	return record, nil
}

func resourceAuthorityRequestHash(value []byte) (authority.RequestHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.RequestHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewRequestHash(fixed)
	if err != nil {
		return authority.RequestHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func (record resourceAuthorityIdempotencyRecord) completedResult(
	command authority.Command,
) (authority.Result, error) {
	if record.state != "completed" || record.resultKind != resourceAuthorityResultKind(command) ||
		record.resultPublicID == "" || record.resultVersion != 1 ||
		record.resultNetworkRevision <= 1 {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	var payload resourceAuthorityResultPayload
	if err := json.Unmarshal([]byte(record.resultPayload), &payload); err != nil ||
		payload.Operation != resourceAuthorityOperation(command) || payload.SubsystemRevision <= 1 {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	semanticHashBytes, err := hex.DecodeString(payload.SemanticHash)
	if err != nil {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	semanticHash, err := resourceSemanticHash(semanticHashBytes)
	if err != nil || semanticHash != command.SemanticHash() {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	var resourceID resource.ID
	var groupID resource.GroupID
	if command.Operation() == authority.OperationCreateDevice {
		resourceID, err = resource.ParseID(record.resultPublicID)
	} else {
		groupID, err = resource.ParseGroupID(record.resultPublicID)
	}
	if err != nil {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewResult(
		command.Operation(), resourceID, groupID, command.Scope(),
		record.resultNetworkRevision, payload.SubsystemRevision,
		record.resultVersion, semanticHash,
	)
	if err != nil {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	return result, nil
}

func resolveResourceAuthorityIdempotency(
	record resourceAuthorityIdempotencyRecord,
	command authority.Command,
	ids authority.MutationIDs,
	occurredAt time.Time,
) (authority.Resolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.Resolution{}, authority.ErrInvalidCommand
	}
	storedHash, err := resourceAuthorityRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.Resolution{}, err
	}
	if storedHash != requestHash {
		return authority.Resolution{}, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(occurredAt) {
		return authority.Resolution{}, authority.ErrIdempotencyExpired
	}
	if record.created {
		if record.state != "pending" || record.publicID != ids.IdempotencyRecordID().String() ||
			record.resultKind != "" ||
			record.resultPublicID != "" || record.resultVersion != 0 ||
			record.resultNetworkRevision != 0 || record.resultPayload != "{}" {
			return authority.Resolution{}, ErrResourceAuthorityEvidence
		}
		return authority.Resolution{}, nil
	}
	if record.state != "completed" {
		return authority.Resolution{}, ErrResourceAuthorityEvidence
	}
	result, err := record.completedResult(command)
	if err != nil {
		return authority.Resolution{}, err
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.Resolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewCompletedResolution(result, recordID, storedHash)
	if err != nil {
		return authority.Resolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func resourceAuthorityCommittedRecord(
	record resourceAuthorityIdempotencyRecord,
	command authority.Command,
	now time.Time,
) (authority.Result, bool, error) {
	if record.publicID == "" {
		return authority.Result{}, false, nil
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.Result{}, false, authority.ErrInvalidCommand
	}
	storedHash, err := resourceAuthorityRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.Result{}, false, err
	}
	if storedHash != requestHash {
		return authority.Result{}, false, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(now) {
		return authority.Result{}, false, nil
	}
	if record.state != "completed" {
		return authority.Result{}, false, ErrResourceAuthorityEvidence
	}
	result, err := record.completedResult(command)
	if err != nil {
		return authority.Result{}, false, err
	}
	return result, true, nil
}
