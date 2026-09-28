// Package authority owns authenticated Resource and Resource Group creation
// decisions and their explicit transaction boundary.
package authority

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/resource"
)

const maximumAuditReasonBytes = 512

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
}

// NewCreateDeviceCommand validates a Device Resource creation request.
func NewCreateDeviceCommand(
	definition resource.DeviceDefinition,
	expectedInventoryRevision int64,
	session accountsession.Session,
	reason AuditReason,
) (Command, error) {
	command := Command{
		operation: OperationCreateDevice, device: definition,
		expectedSubsystemRevision: expectedInventoryRevision,
		accountSession:            session, auditReason: reason,
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
) (Command, error) {
	command := Command{
		operation: OperationCreateGroup, group: definition,
		expectedSubsystemRevision: expectedGroupRevision,
		accountSession:            session, auditReason: reason,
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

// SemanticHash returns canonical aggregate semantics.
func (command Command) SemanticHash() resource.SemanticHash {
	if command.operation == OperationCreateDevice {
		return command.device.SemanticHash()
	}
	return command.group.SemanticHash()
}

// IsValid reports whether exactly one creator-owned definition is selected.
func (command Command) IsValid() bool {
	if command.expectedSubsystemRevision <= 0 || !command.accountSession.IsValid() ||
		!command.auditReason.IsValid() {
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
	scope             network.Scope
	networkRevision   int64
	inventoryRevision int64
	groupRevision     int64
}

// NewResolution validates locked revision evidence.
func NewResolution(
	scope network.Scope,
	networkRevision, inventoryRevision, groupRevision int64,
) (Resolution, error) {
	resolution := Resolution{
		scope: scope, networkRevision: networkRevision,
		inventoryRevision: inventoryRevision, groupRevision: groupRevision,
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

// IsValid reports whether all monotonic revisions are present and coherent.
func (resolution Resolution) IsValid() bool {
	return resolution.scope.IsValid() && resolution.networkRevision > 0 &&
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
}

// NewChange validates the CAS decision, stable IDs, and decision time.
func NewChange(
	command Command,
	resolution Resolution,
	mutationIDs MutationIDs,
	occurredAt time.Time,
) (Change, error) {
	change := Change{
		command: command, resolution: resolution,
		mutationIDs: mutationIDs, occurredAt: occurredAt.UTC(),
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

// IsValid reports whether all atomic facts agree.
func (change Change) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() &&
		change.mutationIDs.IsValidFor(change.command) &&
		change.command.Scope() == change.resolution.Scope() &&
		!change.occurredAt.IsZero()
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
