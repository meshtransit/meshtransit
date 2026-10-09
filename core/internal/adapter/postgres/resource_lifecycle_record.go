package postgres

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	authority "github.com/meshtransit/meshtransit/core/internal/domain/resource/authority"
)

const (
	resourceLifecycleResultKind      = "resource_lifecycle"
	resourceGroupLifecycleResultKind = "resource_group_lifecycle"
)

type resourceLifecycleResultPayload struct {
	Operation         string `json:"operation"`
	State             string `json:"state"`
	SubsystemRevision int64  `json:"subsystem_revision"`
	SemanticHash      string `json:"semantic_hash"`
}

func resourceLifecycleOperation(command authority.LifecycleCommand) string {
	switch command.Operation() {
	case authority.LifecycleSuspendResource:
		return "resource.suspend"
	case authority.LifecycleResumeResource:
		return "resource.resume"
	case authority.LifecycleDeleteResource:
		return "resource.delete"
	case authority.LifecycleSuspendGroup:
		return "resource_group.suspend"
	case authority.LifecycleResumeGroup:
		return "resource_group.resume"
	case authority.LifecycleDeleteGroup:
		return "resource_group.delete"
	default:
		return ""
	}
}

func resourceLifecycleAction(command authority.LifecycleCommand) string {
	switch command.Operation() {
	case authority.LifecycleSuspendResource:
		return "resource.suspended"
	case authority.LifecycleResumeResource:
		return "resource.resumed"
	case authority.LifecycleDeleteResource:
		return "resource.deleted"
	case authority.LifecycleSuspendGroup:
		return "resource_group.suspended"
	case authority.LifecycleResumeGroup:
		return "resource_group.resumed"
	case authority.LifecycleDeleteGroup:
		return "resource_group.deleted"
	default:
		return ""
	}
}

func resourceLifecycleState(state resource.State) string {
	switch state {
	case resource.StateActive:
		return "active"
	case resource.StateSuspended:
		return "suspended"
	case resource.StateDeleted:
		return "deleted"
	default:
		return ""
	}
}

func parseResourceLifecycleState(value string) resource.State {
	switch value {
	case "active":
		return resource.StateActive
	case "suspended":
		return resource.StateSuspended
	case "deleted":
		return resource.StateDeleted
	default:
		return resource.StateUnknown
	}
}

func resourceLifecycleResultType(command authority.LifecycleCommand) string {
	if command.Operation().IsGroup() {
		return resourceGroupLifecycleResultKind
	}
	return resourceLifecycleResultKind
}

func lifecycleRequestHash(value []byte) (authority.LifecycleRequestHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.LifecycleRequestHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewLifecycleRequestHash(fixed)
	if err != nil {
		return authority.LifecycleRequestHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func (record resourceAuthorityIdempotencyRecord) lifecycleResult(
	command authority.LifecycleCommand,
) (authority.LifecycleResult, error) {
	if record.state != "completed" || record.resultKind != resourceLifecycleResultType(command) ||
		record.resultPublicID != command.AggregateID().String() ||
		record.resultVersion != command.ExpectedVersion()+1 || record.resultNetworkRevision <= 1 {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	var payload resourceLifecycleResultPayload
	if err := json.Unmarshal([]byte(record.resultPayload), &payload); err != nil ||
		payload.Operation != resourceLifecycleOperation(command) || payload.SubsystemRevision <= 1 {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	state := parseResourceLifecycleState(payload.State)
	semanticHashBytes, err := hex.DecodeString(payload.SemanticHash)
	if err != nil {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	semanticHash, err := resourceSemanticHash(semanticHashBytes)
	if err != nil {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewLifecycleResult(
		command.Operation(), command.ResourceID(), command.GroupID(), command.Scope(), state,
		record.resultVersion, record.resultNetworkRevision, payload.SubsystemRevision, semanticHash,
	)
	if err != nil {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	return result, nil
}

func resolveResourceLifecycleIdempotency(
	record resourceAuthorityIdempotencyRecord,
	command authority.LifecycleCommand,
	ids authority.LifecycleMutationIDs,
	occurredAt time.Time,
) (authority.LifecycleResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.LifecycleResolution{}, authority.ErrInvalidLifecycleCommand
	}
	storedHash, err := lifecycleRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.LifecycleResolution{}, err
	}
	if storedHash != requestHash {
		return authority.LifecycleResolution{}, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(occurredAt) {
		return authority.LifecycleResolution{}, authority.ErrIdempotencyExpired
	}
	if record.created {
		if record.state != "pending" || record.publicID != ids.IdempotencyRecordID().String() ||
			record.resultKind != "" || record.resultPublicID != "" || record.resultVersion != 0 ||
			record.resultNetworkRevision != 0 || record.resultPayload != "{}" {
			return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
		}
		return authority.LifecycleResolution{}, nil
	}
	if record.state != "completed" {
		return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
	}
	result, err := record.lifecycleResult(command)
	if err != nil {
		return authority.LifecycleResolution{}, err
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewCompletedLifecycleResolution(result, recordID, storedHash)
	if err != nil {
		return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func resourceLifecycleCommittedRecord(
	record resourceAuthorityIdempotencyRecord,
	command authority.LifecycleCommand,
	now time.Time,
) (authority.LifecycleResult, bool, error) {
	if record.publicID == "" {
		return authority.LifecycleResult{}, false, nil
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.LifecycleResult{}, false, authority.ErrInvalidLifecycleCommand
	}
	storedHash, err := lifecycleRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.LifecycleResult{}, false, err
	}
	if storedHash != requestHash {
		return authority.LifecycleResult{}, false, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(now) {
		return authority.LifecycleResult{}, false, nil
	}
	if record.state != "completed" {
		return authority.LifecycleResult{}, false, ErrResourceAuthorityEvidence
	}
	result, err := record.lifecycleResult(command)
	if err != nil {
		return authority.LifecycleResult{}, false, err
	}
	return result, true, nil
}
