// Package authority owns authenticated Resource and Resource Group creation
// decisions and their explicit transaction boundary.
package authority

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/platform/idempotency"
)

const (
	maximumAuditReasonBytes = 512
	requestHashDomain       = "meshtransit/resource-authority-request/v1\x00"
)

var (
	// ErrInvalidAuditReason reports an absent, malformed, or excessive reason.
	ErrInvalidAuditReason = errors.New("resource authority: invalid audit reason")
	// ErrInvalidCommand reports incomplete or inconsistent creation authority.
	ErrInvalidCommand = errors.New("resource authority: invalid command")
	// ErrInvalidResolution reports inconsistent state returned under lock.
	ErrInvalidResolution = errors.New("resource authority: invalid resolution")
	// ErrInvalidChange reports an incomplete atomic mutation decision.
	ErrInvalidChange = errors.New("resource authority: invalid change")
	// ErrInvalidResult reports inconsistent committed authority evidence.
	ErrInvalidResult = errors.New("resource authority: invalid result")
	// ErrConflict reports a stale subsystem or member version.
	ErrConflict = errors.New("resource authority: stale revision")
	// ErrForbidden hides which session or permission check failed.
	ErrForbidden = errors.New("resource authority: forbidden")
	// ErrIntentConflict reports idempotency-key reuse with different semantics.
	ErrIntentConflict = errors.New("resource authority: idempotency conflict")
	// ErrIdempotencyExpired reports replay evidence outside its bounded window.
	ErrIdempotencyExpired = errors.New("resource authority: idempotency window expired")
)

// Operation identifies the authoritative aggregate being created.
type Operation uint8

const (
	// OperationUnknown is the unusable zero value.
	OperationUnknown Operation = iota
	// OperationCreateDevice creates one Device-backed Resource.
	OperationCreateDevice
	// OperationCreateGroup creates one immutable Resource Group version.
	OperationCreateGroup
)

// AuditReason is a bounded human explanation for one mutation.
type AuditReason struct{ value string }

// NewAuditReason trims surrounding whitespace and validates an explicit reason.
func NewAuditReason(value string) (AuditReason, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximumAuditReasonBytes || !utf8.ValidString(value) {
		return AuditReason{}, ErrInvalidAuditReason
	}
	return AuditReason{value: value}, nil
}

// String returns the normalized reason.
func (reason AuditReason) String() string { return reason.value }

// IsValid reports whether the reason satisfies its safety bound.
func (reason AuditReason) IsValid() bool {
	return reason.value != "" && reason.value == strings.TrimSpace(reason.value) &&
		len(reason.value) <= maximumAuditReasonBytes && utf8.ValidString(reason.value)
}

// Command is one authenticated creator-owned Resource authority request.
type Command struct {
	operation                 Operation
	device                    resource.DeviceDefinition
	group                     resource.GroupDefinition
	expectedSubsystemRevision int64
	accountSession            accountsession.Session
	auditReason               AuditReason
	idempotencyEvidence       idempotency.Proof
}

// NewCreateDeviceCommand validates a Device Resource creation request.
func NewCreateDeviceCommand(
	definition resource.DeviceDefinition,
	expectedInventoryRevision int64,
	session accountsession.Session,
	reason AuditReason,
	evidence idempotency.Proof,
) (Command, error) {
	command := Command{
		operation: OperationCreateDevice, device: definition,
		expectedSubsystemRevision: expectedInventoryRevision,
		accountSession:            session, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

// NewCreateGroupCommand validates a Resource Group creation request.
func NewCreateGroupCommand(
	definition resource.GroupDefinition,
	expectedGroupRevision int64,
	session accountsession.Session,
	reason AuditReason,
	evidence idempotency.Proof,
) (Command, error) {
	command := Command{
		operation: OperationCreateGroup, group: definition,
		expectedSubsystemRevision: expectedGroupRevision,
		accountSession:            session, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

// Operation returns the aggregate mutation kind.
func (command Command) Operation() Operation { return command.operation }

// Scope returns the exact home Network scope.
func (command Command) Scope() network.Scope {
	if command.operation == OperationCreateDevice {
		return command.device.Scope()
	}
	return command.group.Scope()
}

// Device returns the Device Resource definition when selected.
func (command Command) Device() resource.DeviceDefinition { return command.device }

// Group returns the Resource Group definition when selected.
func (command Command) Group() resource.GroupDefinition { return command.group }

// ExpectedSubsystemRevision returns the inventory or group CAS base.
func (command Command) ExpectedSubsystemRevision() int64 {
	return command.expectedSubsystemRevision
}

// AccountSession returns authenticated management authority.
func (command Command) AccountSession() accountsession.Session { return command.accountSession }

// AuditReason returns the explicit mutation explanation.
func (command Command) AuditReason() AuditReason { return command.auditReason }

// IdempotencyEvidence returns secret-safe replay evidence.
func (command Command) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// SemanticHash returns canonical aggregate semantics.
func (command Command) SemanticHash() resource.SemanticHash {
	if command.operation == OperationCreateDevice {
		return command.device.SemanticHash()
	}
	return command.group.SemanticHash()
}

// RequestHash binds one idempotency key to exact command semantics.
func (command Command) RequestHash() (RequestHash, error) {
	if !command.IsValid() {
		return RequestHash{}, ErrInvalidCommand
	}
	material := make([]byte, 0, len(requestHashDomain)+256)
	material = append(material, requestHashDomain...)
	material = append(material, byte(command.operation))
	for _, value := range [...]string{
		command.Scope().WorkspaceID().String(),
		command.Scope().NetworkID().String(),
		command.accountSession.ID().String(),
		command.accountSession.PrincipalID().String(),
		command.auditReason.String(),
	} {
		material = appendAuthorityText(material, value)
	}
	semanticHash := command.SemanticHash().Bytes()
	material = append(material, semanticHash[:]...)
	material = appendAuthorityInt64(material, command.expectedSubsystemRevision)
	return NewRequestHash(sha256.Sum256(material))
}

// RequestHash is deterministic idempotency evidence for one creation command.
type RequestHash [sha256.Size]byte

// NewRequestHash validates a non-zero request semantic hash.
func NewRequestHash(value [sha256.Size]byte) (RequestHash, error) {
	hash := RequestHash(value)
	if !hash.IsValid() {
		return RequestHash{}, ErrInvalidCommand
	}
	return hash, nil
}

// Bytes returns a defensive copy of the hash.
func (hash RequestHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether hash evidence is present.
func (hash RequestHash) IsValid() bool { return hash != RequestHash{} }

// IsValid reports whether exactly one creator-owned definition is selected.
func (command Command) IsValid() bool {
	if command.expectedSubsystemRevision <= 0 || !command.accountSession.IsValid() ||
		!command.auditReason.IsValid() || !command.idempotencyEvidence.IsValid() {
		return false
	}
	switch command.operation {
	case OperationCreateDevice:
		return command.device.IsValid() && !command.group.IsValid() &&
			command.device.OwnerPrincipalID() == command.accountSession.PrincipalID() &&
			command.device.CustodianPrincipalID() == command.accountSession.PrincipalID()
	case OperationCreateGroup:
		return command.group.IsValid() && !command.device.IsValid() &&
			command.group.OwnerPrincipalID() == command.accountSession.PrincipalID() &&
			command.group.CustodianPrincipalID() == command.accountSession.PrincipalID()
	default:
		return false
	}
}

// Resolution is Network revision authority observed under transaction locks.
type Resolution struct {
	scope               network.Scope
	networkRevision     int64
	inventoryRevision   int64
	groupRevision       int64
	idempotencyRecordID publicid.ID
	requestHash         RequestHash
	completed           Result
}

// NewResolution validates locked revision evidence.
func NewResolution(
	scope network.Scope,
	networkRevision, inventoryRevision, groupRevision int64,
	idempotencyRecordID publicid.ID,
	requestHash RequestHash,
) (Resolution, error) {
	resolution := Resolution{
		scope: scope, networkRevision: networkRevision,
		inventoryRevision: inventoryRevision, groupRevision: groupRevision,
		idempotencyRecordID: idempotencyRecordID, requestHash: requestHash,
	}
	if !resolution.IsValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// NewCompletedResolution validates an immutable replay result.
func NewCompletedResolution(
	result Result,
	idempotencyRecordID publicid.ID,
	requestHash RequestHash,
) (Resolution, error) {
	resolution := Resolution{
		scope: result.Scope(), idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, completed: result,
	}
	if !resolution.IsValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// Scope returns the exact locked scope.
func (resolution Resolution) Scope() network.Scope { return resolution.scope }

// NetworkRevision returns the client-visible revision.
func (resolution Resolution) NetworkRevision() int64 { return resolution.networkRevision }

// InventoryRevision returns Resource inventory authority.
func (resolution Resolution) InventoryRevision() int64 { return resolution.inventoryRevision }

// GroupRevision returns Resource Group authority.
func (resolution Resolution) GroupRevision() int64 { return resolution.groupRevision }

// IdempotencyRecordID returns durable replay identity.
func (resolution Resolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns exact idempotent request semantics.
func (resolution Resolution) RequestHash() RequestHash { return resolution.requestHash }

// CompletedResult returns replayed committed evidence, if present.
func (resolution Resolution) CompletedResult() Result { return resolution.completed }

// IsCompleted reports whether this resolution is an immutable replay.
func (resolution Resolution) IsCompleted() bool { return resolution.completed.IsValid() }

// IsValid reports whether all monotonic revisions are present and coherent.
func (resolution Resolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.idempotencyRecordID.IsValid() ||
		!resolution.requestHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope && resolution.networkRevision == 0 &&
			resolution.inventoryRevision == 0 && resolution.groupRevision == 0
	}
	return resolution.networkRevision > 0 &&
		resolution.inventoryRevision > 0 && resolution.groupRevision > 0 &&
		resolution.networkRevision >= resolution.inventoryRevision &&
		resolution.networkRevision >= resolution.groupRevision
}

// Change is one validated, replayable atomic authority mutation.
type Change struct {
	command     Command
	resolution  Resolution
	mutationIDs MutationIDs
	occurredAt  time.Time
	expiresAt   time.Time
}

// NewChange validates the CAS decision, stable IDs, and decision time.
func NewChange(
	command Command,
	resolution Resolution,
	mutationIDs MutationIDs,
	occurredAt time.Time,
	expiresAt time.Time,
) (Change, error) {
	change := Change{
		command: command, resolution: resolution,
		mutationIDs: mutationIDs, occurredAt: occurredAt.UTC(), expiresAt: expiresAt.UTC(),
	}
	if !change.IsValid() {
		return Change{}, ErrInvalidChange
	}
	return change, nil
}

// Command returns the immutable request.
func (change Change) Command() Command { return change.command }

// Resolution returns locked authority.
func (change Change) Resolution() Resolution { return change.resolution }

// MutationIDs returns stable durable identities.
func (change Change) MutationIDs() MutationIDs { return change.mutationIDs }

// OccurredAt returns one stable decision time shared across retries.
func (change Change) OccurredAt() time.Time { return change.occurredAt }

// ExpiresAt returns the exclusive durable replay-window bound.
func (change Change) ExpiresAt() time.Time { return change.expiresAt }

// IsValid reports whether all atomic facts agree.
func (change Change) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() &&
		change.mutationIDs.IsValidFor(change.command) &&
		change.command.Scope() == change.resolution.Scope() && !change.resolution.IsCompleted() &&
		!change.occurredAt.IsZero() && change.expiresAt.After(change.occurredAt)
}

func appendAuthorityText(output []byte, value string) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(len(value)))
	output = append(output, encoded[:]...)
	return append(output, value...)
}

func appendAuthorityInt64(output []byte, value int64) []byte {
	var encoded [8]byte
	// #nosec G115 -- command validation requires this revision to be positive.
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	return append(output, encoded[:]...)
}

// Result is safe committed Resource or Resource Group authority evidence.
type Result struct {
	operation         Operation
	resourceID        resource.ID
	groupID           resource.GroupID
	scope             network.Scope
	networkRevision   int64
	subsystemRevision int64
	version           int64
	semanticHash      resource.SemanticHash
}

// NewResult validates committed aggregate evidence.
func NewResult(
	operation Operation,
	resourceID resource.ID,
	groupID resource.GroupID,
	scope network.Scope,
	networkRevision, subsystemRevision, version int64,
	semanticHash resource.SemanticHash,
) (Result, error) {
	result := Result{
		operation: operation, resourceID: resourceID, groupID: groupID, scope: scope,
		networkRevision: networkRevision, subsystemRevision: subsystemRevision,
		version: version, semanticHash: semanticHash,
	}
	if !result.IsValid() {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}

// Operation returns the committed aggregate kind.
func (result Result) Operation() Operation { return result.operation }

// ResourceID returns the created Resource identity when selected.
func (result Result) ResourceID() resource.ID { return result.resourceID }

// GroupID returns the created Resource Group identity when selected.
func (result Result) GroupID() resource.GroupID { return result.groupID }

// Scope returns the committed exact scope.
func (result Result) Scope() network.Scope { return result.scope }

// NetworkRevision returns the new client-visible revision.
func (result Result) NetworkRevision() int64 { return result.networkRevision }

// SubsystemRevision returns the new inventory or group revision.
func (result Result) SubsystemRevision() int64 { return result.subsystemRevision }

// Version returns the initial aggregate version.
func (result Result) Version() int64 { return result.version }

// SemanticHash returns committed aggregate semantics.
func (result Result) SemanticHash() resource.SemanticHash { return result.semanticHash }

// IsValid reports whether exactly one aggregate identity is present.
func (result Result) IsValid() bool {
	if !result.scope.IsValid() || result.networkRevision <= 1 || result.subsystemRevision <= 1 ||
		result.networkRevision < result.subsystemRevision || result.version != 1 ||
		!result.semanticHash.IsValid() {
		return false
	}
	switch result.operation {
	case OperationCreateDevice:
		return result.resourceID.IsValid() && !result.groupID.IsValid()
	case OperationCreateGroup:
		return result.groupID.IsValid() && !result.resourceID.IsValid()
	default:
		return false
	}
}
