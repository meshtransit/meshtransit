package postgres

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	authority "github.com/meshtransit/meshtransit/core/internal/domain/resource/authority"
)

const resourceRebindResultKind = "resource_rebind"

type resourceRebindResultPayload struct {
	DeviceID          string `json:"device_id"`
	TargetGeneration  int64  `json:"target_generation"`
	InventoryRevision int64  `json:"inventory_revision"`
	SemanticHash      string `json:"semantic_hash"`
	ImpactHash        string `json:"impact_hash"`
}

func rebindRequestHash(value []byte) (authority.RebindRequestHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.RebindRequestHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewRebindRequestHash(fixed)
	if err != nil {
		return authority.RebindRequestHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func rebindImpactHash(value []byte) (authority.RebindImpactHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.RebindImpactHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewRebindImpactHash(fixed)
	if err != nil {
		return authority.RebindImpactHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func (record resourceAuthorityIdempotencyRecord) rebindResult(
	command authority.RebindCommand,
) (authority.RebindResult, error) {
	if record.state != "completed" || record.resultKind != resourceRebindResultKind ||
		record.resultPublicID != command.ResourceID().String() ||
		record.resultVersion != command.ExpectedVersion()+1 || record.resultNetworkRevision <= 1 {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	var payload resourceRebindResultPayload
	if err := json.Unmarshal([]byte(record.resultPayload), &payload); err != nil ||
		payload.InventoryRevision <= 1 || payload.TargetGeneration <= 1 {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	deviceID, err := node.ParseID(payload.DeviceID)
	if err != nil || deviceID != command.DeviceID() {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	semanticHashBytes, err := hex.DecodeString(payload.SemanticHash)
	if err != nil {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	semanticHash, err := resourceSemanticHash(semanticHashBytes)
	if err != nil {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	impactHashBytes, err := hex.DecodeString(payload.ImpactHash)
	if err != nil {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	impactHash, err := rebindImpactHash(impactHashBytes)
	if err != nil || impactHash != command.ImpactHash() {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewRebindResult(
		command.ResourceID(), command.Scope(), deviceID, payload.TargetGeneration,
		record.resultVersion, record.resultNetworkRevision, payload.InventoryRevision,
		semanticHash, impactHash,
	)
	if err != nil {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	return result, nil
}

func resolveResourceRebindIdempotency(
	record resourceAuthorityIdempotencyRecord,
	command authority.RebindCommand,
	ids authority.RebindMutationIDs,
	occurredAt time.Time,
) (authority.RebindResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.RebindResolution{}, authority.ErrInvalidRebindCommand
	}
	storedHash, err := rebindRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.RebindResolution{}, err
	}
	if storedHash != requestHash {
		return authority.RebindResolution{}, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(occurredAt) {
		return authority.RebindResolution{}, authority.ErrIdempotencyExpired
	}
	if record.created {
		if record.state != "pending" || record.publicID != ids.IdempotencyRecordID().String() ||
			record.resultKind != "" || record.resultPublicID != "" || record.resultVersion != 0 ||
			record.resultNetworkRevision != 0 || record.resultPayload != "{}" {
			return authority.RebindResolution{}, ErrResourceAuthorityEvidence
		}
		return authority.RebindResolution{}, nil
	}
	if record.state != "completed" {
		return authority.RebindResolution{}, ErrResourceAuthorityEvidence
	}
	result, err := record.rebindResult(command)
	if err != nil {
		return authority.RebindResolution{}, err
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.RebindResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewCompletedRebindResolution(result, recordID, storedHash)
	if err != nil {
		return authority.RebindResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func resourceRebindCommittedRecord(
	record resourceAuthorityIdempotencyRecord,
	command authority.RebindCommand,
	now time.Time,
) (authority.RebindResult, bool, error) {
	if record.publicID == "" {
		return authority.RebindResult{}, false, nil
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.RebindResult{}, false, authority.ErrInvalidRebindCommand
	}
	storedHash, err := rebindRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.RebindResult{}, false, err
	}
	if storedHash != requestHash {
		return authority.RebindResult{}, false, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(now) {
		return authority.RebindResult{}, false, nil
	}
	if record.state != "completed" {
		return authority.RebindResult{}, false, ErrResourceAuthorityEvidence
	}
	result, err := record.rebindResult(command)
	if err != nil {
		return authority.RebindResult{}, false, err
	}
	return result, true, nil
}

func parseRebindAffectedGroups(value []byte) ([]resource.GroupID, error) {
	var encoded []string
	if err := json.Unmarshal(value, &encoded); err != nil ||
		len(encoded) > authority.MaximumRebindAffectedGroups {
		if len(encoded) > authority.MaximumRebindAffectedGroups {
			return nil, authority.ErrRebindImpactTooLarge
		}
		return nil, ErrResourceAuthorityEvidence
	}
	groupIDs := make([]resource.GroupID, len(encoded))
	for index, raw := range encoded {
		groupID, err := resource.ParseGroupID(raw)
		if err != nil {
			return nil, ErrResourceAuthorityEvidence
		}
		groupIDs[index] = groupID
	}
	return groupIDs, nil
}
