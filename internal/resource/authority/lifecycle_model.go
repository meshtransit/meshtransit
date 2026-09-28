package authority

import (
	"crypto/sha256"
	"errors"
	"math"
	"time"

	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

const lifecycleRequestHashDomain = "meshtransit/resource-lifecycle-request/v1\x00"

var (
	// ErrInvalidLifecycleCommand reports incomplete or inconsistent lifecycle authority.
	ErrInvalidLifecycleCommand = errors.New("resource lifecycle: invalid command")
	// ErrInvalidLifecycleResolution reports inconsistent state returned under lock.
	ErrInvalidLifecycleResolution = errors.New("resource lifecycle: invalid resolution")
	// ErrInvalidLifecycleChange reports an incomplete atomic lifecycle decision.
	ErrInvalidLifecycleChange = errors.New("resource lifecycle: invalid change")
	// ErrInvalidLifecycleResult reports inconsistent committed lifecycle evidence.
	ErrInvalidLifecycleResult = errors.New("resource lifecycle: invalid result")
	// ErrLifecycleNotFound hides absent and cross-scope aggregate identities.
	ErrLifecycleNotFound = errors.New("resource lifecycle: aggregate unavailable")
	// ErrLifecycleVersionConflict reports a stale aggregate version precondition.
	ErrLifecycleVersionConflict = errors.New("resource lifecycle: stale aggregate version")
	// ErrInvalidLifecycleTransition reports an illegal source-to-target state change.
	ErrInvalidLifecycleTransition = errors.New("resource lifecycle: invalid transition")
)

// LifecycleOperation identifies one explicit Resource authority transition.
type LifecycleOperation uint8

const (
	// LifecycleOperationUnknown is the unusable zero value.
	LifecycleOperationUnknown LifecycleOperation = iota
	// LifecycleSuspendResource transitions an active Resource to suspended.
	LifecycleSuspendResource
	// LifecycleResumeResource transitions a suspended Resource to active.
	LifecycleResumeResource
	// LifecycleDeleteResource transitions an active or suspended Resource to deleted.
	LifecycleDeleteResource
	// LifecycleSuspendGroup transitions an active Resource Group to suspended.
	LifecycleSuspendGroup
	// LifecycleResumeGroup transitions a suspended Resource Group to active.
	LifecycleResumeGroup
	// LifecycleDeleteGroup transitions an active or suspended Resource Group to deleted.
	LifecycleDeleteGroup
)

// IsGroup reports whether the operation targets a Resource Group.
func (operation LifecycleOperation) IsGroup() bool {
	return operation == LifecycleSuspendGroup || operation == LifecycleResumeGroup ||
		operation == LifecycleDeleteGroup
}

// TargetState returns the state produced by a valid operation.
func (operation LifecycleOperation) TargetState() resource.State {
	switch operation {
	case LifecycleSuspendResource, LifecycleSuspendGroup:
		return resource.StateSuspended
	case LifecycleResumeResource, LifecycleResumeGroup:
		return resource.StateActive
	case LifecycleDeleteResource, LifecycleDeleteGroup:
		return resource.StateDeleted
	default:
		return resource.StateUnknown
	}
}

func (operation LifecycleOperation) isResource() bool {
	return operation == LifecycleSuspendResource || operation == LifecycleResumeResource ||
		operation == LifecycleDeleteResource
}

func (operation LifecycleOperation) isValid() bool {
	return operation.isResource() || operation.IsGroup()
}

// LifecycleCommand is one authenticated, version-bound lifecycle request.
type LifecycleCommand struct {
	operation           LifecycleOperation
	scope               network.Scope
	resourceID          resource.ID
	groupID             resource.GroupID
	expectedVersion     int64
	accountSession      accountsession.Session
	auditReason         AuditReason
	idempotencyEvidence idempotency.Proof
}

// NewResourceLifecycleCommand validates a Resource lifecycle request.
func NewResourceLifecycleCommand(
	operation LifecycleOperation,
	scope network.Scope,
	resourceID resource.ID,
	expectedVersion int64,
	session accountsession.Session,
	reason AuditReason,
	evidence idempotency.Proof,
) (LifecycleCommand, error) {
	command := LifecycleCommand{
		operation: operation, scope: scope, resourceID: resourceID,
		expectedVersion: expectedVersion, accountSession: session,
		auditReason: reason, idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return LifecycleCommand{}, ErrInvalidLifecycleCommand
	}
	return command, nil
}

// NewGroupLifecycleCommand validates a Resource Group lifecycle request.
func NewGroupLifecycleCommand(
	operation LifecycleOperation,
	scope network.Scope,
	groupID resource.GroupID,
	expectedVersion int64,
	session accountsession.Session,
	reason AuditReason,
	evidence idempotency.Proof,
) (LifecycleCommand, error) {
	command := LifecycleCommand{
		operation: operation, scope: scope, groupID: groupID,
		expectedVersion: expectedVersion, accountSession: session,
		auditReason: reason, idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return LifecycleCommand{}, ErrInvalidLifecycleCommand
	}
	return command, nil
}

// Operation returns the requested state transition.
func (command LifecycleCommand) Operation() LifecycleOperation { return command.operation }

// Scope returns the exact home Network scope.
func (command LifecycleCommand) Scope() network.Scope { return command.scope }

// ResourceID returns the target Resource identity when selected.
func (command LifecycleCommand) ResourceID() resource.ID { return command.resourceID }

// GroupID returns the target Resource Group identity when selected.
func (command LifecycleCommand) GroupID() resource.GroupID { return command.groupID }

// AggregateID returns the selected public aggregate identity.
func (command LifecycleCommand) AggregateID() publicid.ID {
	if command.operation.IsGroup() {
		return publicid.ID(command.groupID)
	}
	return publicid.ID(command.resourceID)
}

// ExpectedVersion returns the aggregate CAS base.
func (command LifecycleCommand) ExpectedVersion() int64 { return command.expectedVersion }

// AccountSession returns authenticated management authority.
func (command LifecycleCommand) AccountSession() accountsession.Session {
	return command.accountSession
}

// AuditReason returns the explicit mutation explanation.
func (command LifecycleCommand) AuditReason() AuditReason { return command.auditReason }

// IdempotencyEvidence returns secret-safe replay evidence.
func (command LifecycleCommand) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// RequestHash binds one idempotency key to exact lifecycle semantics.
func (command LifecycleCommand) RequestHash() (LifecycleRequestHash, error) {
	if !command.IsValid() {
		return LifecycleRequestHash{}, ErrInvalidLifecycleCommand
	}
	material := make([]byte, 0, len(lifecycleRequestHashDomain)+256)
	material = append(material, lifecycleRequestHashDomain...)
	material = append(material, byte(command.operation))
	for _, value := range [...]string{
		command.scope.WorkspaceID().String(),
		command.scope.NetworkID().String(),
		command.AggregateID().String(),
		command.accountSession.ID().String(),
		command.accountSession.PrincipalID().String(),
		command.auditReason.String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, command.expectedVersion)
	return NewLifecycleRequestHash(sha256.Sum256(material))
}

// IsValid reports whether exactly one operation-compatible aggregate is selected.
func (command LifecycleCommand) IsValid() bool {
	if !command.operation.isValid() || !command.scope.IsValid() || command.expectedVersion <= 0 ||
		command.expectedVersion == math.MaxInt64 ||
		!command.accountSession.IsValid() || !command.auditReason.IsValid() ||
		!command.idempotencyEvidence.IsValid() {
		return false
	}
	if command.operation.IsGroup() {
		return command.groupID.IsValid() && !command.resourceID.IsValid()
	}
	return command.operation.isResource() && command.resourceID.IsValid() && !command.groupID.IsValid()
}

// LifecycleRequestHash is deterministic idempotency evidence for a lifecycle request.
type LifecycleRequestHash [sha256.Size]byte

// NewLifecycleRequestHash validates a non-zero request semantic hash.
func NewLifecycleRequestHash(value [sha256.Size]byte) (LifecycleRequestHash, error) {
	hash := LifecycleRequestHash(value)
	if !hash.IsValid() {
		return LifecycleRequestHash{}, ErrInvalidLifecycleCommand
	}
	return hash, nil
}

// Bytes returns a defensive copy of the hash.
func (hash LifecycleRequestHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether hash evidence is present.
func (hash LifecycleRequestHash) IsValid() bool { return hash != LifecycleRequestHash{} }

// LifecycleResolution is Network revision authority observed under locks.
type LifecycleResolution struct {
	scope               network.Scope
	networkRevision     int64
	inventoryRevision   int64
	groupRevision       int64
	idempotencyRecordID publicid.ID
	requestHash         LifecycleRequestHash
	completed           LifecycleResult
}

// NewLifecycleResolution validates locked revision evidence.
func NewLifecycleResolution(
	scope network.Scope,
	networkRevision, inventoryRevision, groupRevision int64,
	idempotencyRecordID publicid.ID,
	requestHash LifecycleRequestHash,
) (LifecycleResolution, error) {
	resolution := LifecycleResolution{
		scope: scope, networkRevision: networkRevision,
		inventoryRevision: inventoryRevision, groupRevision: groupRevision,
		idempotencyRecordID: idempotencyRecordID, requestHash: requestHash,
	}
	if !resolution.IsValid() {
		return LifecycleResolution{}, ErrInvalidLifecycleResolution
	}
	return resolution, nil
}

// NewCompletedLifecycleResolution validates immutable replay evidence.
func NewCompletedLifecycleResolution(
	result LifecycleResult,
	idempotencyRecordID publicid.ID,
	requestHash LifecycleRequestHash,
) (LifecycleResolution, error) {
	resolution := LifecycleResolution{
		scope: result.Scope(), idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, completed: result,
	}
	if !resolution.IsValid() {
		return LifecycleResolution{}, ErrInvalidLifecycleResolution
	}
	return resolution, nil
}

// Scope returns exact locked scope.
func (resolution LifecycleResolution) Scope() network.Scope { return resolution.scope }

// NetworkRevision returns current client-visible revision.
func (resolution LifecycleResolution) NetworkRevision() int64 { return resolution.networkRevision }

// InventoryRevision returns current Resource inventory authority.
func (resolution LifecycleResolution) InventoryRevision() int64 {
	return resolution.inventoryRevision
}

// GroupRevision returns current Resource Group authority.
func (resolution LifecycleResolution) GroupRevision() int64 { return resolution.groupRevision }

// IdempotencyRecordID returns durable replay identity.
func (resolution LifecycleResolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns exact idempotent request semantics.
func (resolution LifecycleResolution) RequestHash() LifecycleRequestHash {
	return resolution.requestHash
}

// CompletedResult returns replayed committed evidence, if present.
func (resolution LifecycleResolution) CompletedResult() LifecycleResult {
	return resolution.completed
}

// IsCompleted reports whether this resolution is an immutable replay.
func (resolution LifecycleResolution) IsCompleted() bool { return resolution.completed.IsValid() }

// IsValid reports whether all monotonic revisions are present and coherent.
func (resolution LifecycleResolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.idempotencyRecordID.IsValid() ||
		!resolution.requestHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope && resolution.networkRevision == 0 &&
			resolution.inventoryRevision == 0 && resolution.groupRevision == 0
	}
	return resolution.networkRevision > 0 && resolution.inventoryRevision > 0 &&
		resolution.groupRevision > 0 && resolution.networkRevision >= resolution.inventoryRevision &&
		resolution.networkRevision >= resolution.groupRevision
}

// LifecycleChange is one validated, replayable atomic lifecycle decision.
type LifecycleChange struct {
	command     LifecycleCommand
	resolution  LifecycleResolution
	mutationIDs LifecycleMutationIDs
	occurredAt  time.Time
	expiresAt   time.Time
}

// NewLifecycleChange validates CAS, stable IDs, and decision time.
func NewLifecycleChange(
	command LifecycleCommand,
	resolution LifecycleResolution,
	mutationIDs LifecycleMutationIDs,
	occurredAt, expiresAt time.Time,
) (LifecycleChange, error) {
	change := LifecycleChange{
		command: command, resolution: resolution, mutationIDs: mutationIDs,
		occurredAt: occurredAt.UTC(), expiresAt: expiresAt.UTC(),
	}
	if !change.IsValid() {
		return LifecycleChange{}, ErrInvalidLifecycleChange
	}
	return change, nil
}

// Command returns the immutable request.
func (change LifecycleChange) Command() LifecycleCommand { return change.command }

// Resolution returns locked authority.
func (change LifecycleChange) Resolution() LifecycleResolution { return change.resolution }

// MutationIDs returns stable durable identities.
func (change LifecycleChange) MutationIDs() LifecycleMutationIDs { return change.mutationIDs }

// OccurredAt returns one stable decision time shared across retries.
func (change LifecycleChange) OccurredAt() time.Time { return change.occurredAt }

// ExpiresAt returns the exclusive durable replay-window bound.
func (change LifecycleChange) ExpiresAt() time.Time { return change.expiresAt }

// IsValid reports whether all atomic facts agree.
func (change LifecycleChange) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() &&
		change.mutationIDs.IsValid() && change.command.Scope() == change.resolution.Scope() &&
		!change.resolution.IsCompleted() && !change.occurredAt.IsZero() &&
		change.expiresAt.After(change.occurredAt)
}

// LifecycleResult is safe committed state-transition evidence.
type LifecycleResult struct {
	operation         LifecycleOperation
	resourceID        resource.ID
	groupID           resource.GroupID
	scope             network.Scope
	state             resource.State
	version           int64
	networkRevision   int64
	subsystemRevision int64
	semanticHash      resource.SemanticHash
}

// NewLifecycleResult validates committed lifecycle evidence.
func NewLifecycleResult(
	operation LifecycleOperation,
	resourceID resource.ID,
	groupID resource.GroupID,
	scope network.Scope,
	state resource.State,
	version, networkRevision, subsystemRevision int64,
	semanticHash resource.SemanticHash,
) (LifecycleResult, error) {
	result := LifecycleResult{
		operation: operation, resourceID: resourceID, groupID: groupID, scope: scope,
		state: state, version: version, networkRevision: networkRevision,
		subsystemRevision: subsystemRevision, semanticHash: semanticHash,
	}
	if !result.IsValid() {
		return LifecycleResult{}, ErrInvalidLifecycleResult
	}
	return result, nil
}

// Operation returns the committed transition kind.
func (result LifecycleResult) Operation() LifecycleOperation { return result.operation }

// ResourceID returns target Resource identity when selected.
func (result LifecycleResult) ResourceID() resource.ID { return result.resourceID }

// GroupID returns target Resource Group identity when selected.
func (result LifecycleResult) GroupID() resource.GroupID { return result.groupID }

// Scope returns committed exact scope.
func (result LifecycleResult) Scope() network.Scope { return result.scope }

// State returns committed lifecycle state.
func (result LifecycleResult) State() resource.State { return result.state }

// Version returns new aggregate authority version.
func (result LifecycleResult) Version() int64 { return result.version }

// NetworkRevision returns new client-visible revision.
func (result LifecycleResult) NetworkRevision() int64 { return result.networkRevision }

// SubsystemRevision returns new inventory or group revision.
func (result LifecycleResult) SubsystemRevision() int64 { return result.subsystemRevision }

// SemanticHash returns unchanged aggregate semantic authority.
func (result LifecycleResult) SemanticHash() resource.SemanticHash { return result.semanticHash }

// IsValid reports whether exactly one aggregate and the target state are present.
func (result LifecycleResult) IsValid() bool {
	if !result.operation.isValid() || !result.scope.IsValid() ||
		result.state != result.operation.TargetState() || result.version <= 1 ||
		result.networkRevision <= 1 || result.subsystemRevision <= 1 ||
		result.networkRevision < result.subsystemRevision || !result.semanticHash.IsValid() {
		return false
	}
	if result.operation.IsGroup() {
		return result.groupID.IsValid() && !result.resourceID.IsValid()
	}
	return result.resourceID.IsValid() && !result.groupID.IsValid()
}
