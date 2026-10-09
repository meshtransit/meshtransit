package postgres

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

const resourceGroupReplaceResultKind = "resource_group_replace"

type resourceGroupReplaceResultPayload struct {
	DefinitionVersion int64  `json:"definition_version"`
	GroupRevision     int64  `json:"group_revision"`
	SemanticHash      string `json:"semantic_hash"`
	ImpactHash        string `json:"impact_hash"`
}

func groupReplaceRequestHash(value []byte) (authority.GroupReplaceRequestHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.GroupReplaceRequestHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewGroupReplaceRequestHash(fixed)
	if err != nil {
		return authority.GroupReplaceRequestHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func groupReplaceImpactHash(value []byte) (authority.GroupReplaceImpactHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.GroupReplaceImpactHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewGroupReplaceImpactHash(fixed)
	if err != nil {
		return authority.GroupReplaceImpactHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func (record resourceAuthorityIdempotencyRecord) groupReplaceResult(
	command authority.GroupReplaceCommand,
) (authority.GroupReplaceResult, error) {
	if record.state != "completed" || record.resultKind != resourceGroupReplaceResultKind ||
		record.resultPublicID != command.GroupID().String() ||
		record.resultVersion != command.ExpectedVersion()+1 || record.resultNetworkRevision <= 1 {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	var payload resourceGroupReplaceResultPayload
	if err := json.Unmarshal([]byte(record.resultPayload), &payload); err != nil ||
		payload.DefinitionVersion <= 1 || payload.GroupRevision <= 1 {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	semanticHashBytes, err := hex.DecodeString(payload.SemanticHash)
	if err != nil {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	semanticHash, err := resourceSemanticHash(semanticHashBytes)
	if err != nil {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	impactHashBytes, err := hex.DecodeString(payload.ImpactHash)
	if err != nil {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	impactHash, err := groupReplaceImpactHash(impactHashBytes)
	if err != nil || impactHash != command.ImpactHash() {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewGroupReplaceResult(
		command.GroupID(), command.Scope(), payload.DefinitionVersion, record.resultVersion,
		record.resultNetworkRevision, payload.GroupRevision, semanticHash, impactHash,
	)
	if err != nil {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	return result, nil
}

func resolveResourceGroupReplaceIdempotency(
	record resourceAuthorityIdempotencyRecord,
	command authority.GroupReplaceCommand,
	ids authority.GroupReplaceMutationIDs,
	occurredAt time.Time,
) (authority.GroupReplaceResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.GroupReplaceResolution{}, authority.ErrInvalidGroupReplaceCommand
	}
	storedHash, err := groupReplaceRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.GroupReplaceResolution{}, err
	}
	if storedHash != requestHash {
		return authority.GroupReplaceResolution{}, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(occurredAt) {
		return authority.GroupReplaceResolution{}, authority.ErrIdempotencyExpired
	}
	if record.created {
		if record.state != "pending" || record.publicID != ids.IdempotencyRecordID().String() ||
			record.resultKind != "" || record.resultPublicID != "" || record.resultVersion != 0 ||
			record.resultNetworkRevision != 0 || record.resultPayload != "{}" {
			return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
		}
		return authority.GroupReplaceResolution{}, nil
	}
	if record.state != "completed" {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
	}
	result, err := record.groupReplaceResult(command)
	if err != nil {
		return authority.GroupReplaceResolution{}, err
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewCompletedGroupReplaceResolution(result, recordID, storedHash)
	if err != nil {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func resourceGroupReplaceCommittedRecord(
	record resourceAuthorityIdempotencyRecord,
	command authority.GroupReplaceCommand,
	now time.Time,
) (authority.GroupReplaceResult, bool, error) {
	if record.publicID == "" {
		return authority.GroupReplaceResult{}, false, nil
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.GroupReplaceResult{}, false, authority.ErrInvalidGroupReplaceCommand
	}
	storedHash, err := groupReplaceRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.GroupReplaceResult{}, false, err
	}
	if storedHash != requestHash {
		return authority.GroupReplaceResult{}, false, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(now) {
		return authority.GroupReplaceResult{}, false, nil
	}
	if record.state != "completed" {
		return authority.GroupReplaceResult{}, false, ErrResourceAuthorityEvidence
	}
	result, err := record.groupReplaceResult(command)
	if err != nil {
		return authority.GroupReplaceResult{}, false, err
	}
	return result, true, nil
}

type resourceGroupReferencePayload struct {
	ResourcePublicID string `json:"resource_public_id"`
	ResourceVersion  int64  `json:"resource_version"`
	TargetGeneration int64  `json:"target_generation"`
}

func encodeResourceGroupReferences(references []resource.Reference) ([]byte, error) {
	payload := make([]resourceGroupReferencePayload, len(references))
	for index, reference := range references {
		payload[index] = resourceGroupReferencePayload{
			ResourcePublicID: reference.ResourceID().String(),
			ResourceVersion:  reference.ResourceVersion(), TargetGeneration: reference.TargetGeneration(),
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrResourceAuthorityEvidence
	}
	return encoded, nil
}

func parseResourceGroupReferences(
	value []byte,
	scope network.Scope,
) ([]resource.Reference, error) {
	var payload []resourceGroupReferencePayload
	if err := json.Unmarshal(value, &payload); err != nil || len(payload) == 0 ||
		len(payload) > resource.MaximumGroupMembers {
		return nil, ErrResourceAuthorityEvidence
	}
	references := make([]resource.Reference, len(payload))
	for index, member := range payload {
		resourceID, err := resource.ParseID(member.ResourcePublicID)
		if err != nil {
			return nil, ErrResourceAuthorityEvidence
		}
		reference, err := resource.NewReference(
			scope, resourceID, member.ResourceVersion, member.TargetGeneration,
		)
		if err != nil {
			return nil, ErrResourceAuthorityEvidence
		}
		references[index] = reference
	}
	return references, nil
}
