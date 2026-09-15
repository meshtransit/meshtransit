// Package revocation owns the terminal Device revocation application contract.
package revocation

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	maximumReasonBytes = 256
	requestHashDomain  = "meshtransit/device-revocation-request/v1\x00"
	stateHashDomain    = "meshtransit/device-revocation-state/v1\x00"
)

var (
	// ErrInvalidReason reports an absent, malformed, or excessive audit reason.
	ErrInvalidReason = errors.New("device revocation: invalid reason")
	// ErrInvalidCommand reports an incomplete or inconsistent revocation request.
	ErrInvalidCommand = errors.New("device revocation: invalid command")
	// ErrInvalidResolution reports malformed durable authority read under lock.
	ErrInvalidResolution = errors.New("device revocation: invalid resolution")
	// ErrInvalidAttempt reports incomplete replay identities or decision time.
	ErrInvalidAttempt = errors.New("device revocation: invalid attempt")
	// ErrInvalidChange reports an incomplete atomic revocation decision.
	ErrInvalidChange = errors.New("device revocation: invalid change")
	// ErrInvalidResult reports malformed committed revocation evidence.
	ErrInvalidResult = errors.New("device revocation: invalid result")
	// ErrNotFound hides whether a Device exists outside the authorized Network.
	ErrNotFound = errors.New("device revocation: target unavailable")
	// ErrConflict reports a stale expected Device version.
	ErrConflict = errors.New("device revocation: stale device version")
	// ErrIntentConflict reports idempotency-key reuse with different semantics.
	ErrIntentConflict = errors.New("device revocation: idempotency conflict")
	// ErrAlreadyRevoked reports a terminal Device reached by a new operation.
	ErrAlreadyRevoked = errors.New("device revocation: device already revoked")
	// ErrInvalidTransition reports a Device/key lifecycle that cannot be revoked.
	ErrInvalidTransition = errors.New("device revocation: invalid lifecycle transition")
	// ErrIdempotencyExpired reports replay evidence outside its bounded window.
	ErrIdempotencyExpired = errors.New("device revocation: idempotency window expired")
)

// Reason is a bounded human explanation retained only in audit evidence.
type Reason struct{ value string }

// NewReason trims surrounding whitespace and validates a revocation reason.
func NewReason(value string) (Reason, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximumReasonBytes || !utf8.ValidString(value) {
		return Reason{}, ErrInvalidReason
	}
	return Reason{value: value}, nil
}

// String returns the normalized reason.
func (reason Reason) String() string { return reason.value }

// IsValid reports whether the reason remains bounded and canonical.
func (reason Reason) IsValid() bool {
	return reason.value != "" && reason.value == strings.TrimSpace(reason.value) &&
		len(reason.value) <= maximumReasonBytes && utf8.ValidString(reason.value)
}

// CommandParams contains one authorized, scope-qualified revocation request.
type CommandParams struct {
	Scope               network.Scope
	NodeID              node.ID
	ExpectedVersion     int64
	ActorPrincipalID    identity.PrincipalID
	Reason              Reason
	IdempotencyEvidence idempotency.Proof
}

// Command requests terminal revocation of one Device and its current keys.
type Command struct {
	scope               network.Scope
	nodeID              node.ID
	expectedVersion     int64
	actorPrincipalID    identity.PrincipalID
	reason              Reason
	idempotencyEvidence idempotency.Proof
}

// NewCommand validates trusted authorization-bound request fields.
func NewCommand(params CommandParams) (Command, error) {
	command := Command{
		scope:               params.Scope,
		nodeID:              params.NodeID,
		expectedVersion:     params.ExpectedVersion,
		actorPrincipalID:    params.ActorPrincipalID,
		reason:              params.Reason,
		idempotencyEvidence: params.IdempotencyEvidence,
	}
	if !command.IsValid() {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

// Scope returns the exact authorized Network scope.
func (command Command) Scope() network.Scope { return command.scope }

// NodeID returns the target logical Node identity.
func (command Command) NodeID() node.ID { return command.nodeID }

// ExpectedVersion returns the strong Device version precondition.
func (command Command) ExpectedVersion() int64 { return command.expectedVersion }

// ActorPrincipalID returns the already-authorized human or service principal.
func (command Command) ActorPrincipalID() identity.PrincipalID { return command.actorPrincipalID }

// Reason returns the bounded audit explanation.
func (command Command) Reason() Reason { return command.reason }

// IdempotencyEvidence returns the secret-safe request replay proof.
func (command Command) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// IsValid reports whether all trusted-boundary inputs are present.
func (command Command) IsValid() bool {
	return command.scope.IsValid() && command.nodeID.IsValid() &&
		command.expectedVersion > 0 && command.expectedVersion < maxInt64 &&
		command.actorPrincipalID.IsValid() && command.reason.IsValid() &&
		command.idempotencyEvidence.IsValid()
}

// RequestHash returns deterministic semantics protected by the idempotency key.
func (command Command) RequestHash() (RequestHash, error) {
	if !command.IsValid() {
		return RequestHash{}, ErrInvalidCommand
	}
	material := make([]byte, 0, len(requestHashDomain)+256)
	material = append(material, requestHashDomain...)
	for _, value := range [...]string{
		command.scope.WorkspaceID().String(),
		command.scope.NetworkID().String(),
		command.nodeID.String(),
		command.actorPrincipalID.String(),
		command.reason.String(),
	} {
		material = strconv.AppendInt(material, int64(len(value)), 10)
		material = append(material, ':')
		material = append(material, value...)
	}
	material = strconv.AppendInt(material, command.expectedVersion, 10)
	value := sha256.Sum256(material)
	return NewRequestHash(value)
}

// RequestHash is deterministic idempotency evidence for one command body.
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

// DeviceState is the durable logical Device lifecycle read under lock.
type DeviceState uint8

const (
	// DeviceStateUnknown is the invalid zero value.
	DeviceStateUnknown DeviceState = iota
	// DeviceStateActive may transition to terminal revocation.
	DeviceStateActive
	// DeviceStateExpired is terminal for this operation.
	DeviceStateExpired
	// DeviceStateRevoked is terminal and fail closed.
	DeviceStateRevoked
	// DeviceStateDeleted is terminal and cannot be revived by revocation.
	DeviceStateDeleted
)

func (state DeviceState) isValid() bool {
	return state >= DeviceStateActive && state <= DeviceStateDeleted
}

// KeyState is the durable current key-epoch lifecycle read under lock.
type KeyState uint8

const (
	// KeyStateUnknown is the invalid zero value.
	KeyStateUnknown KeyState = iota
	// KeyStateActive may transition to terminal revocation.
	KeyStateActive
	// KeyStateExpired is terminal for this operation.
	KeyStateExpired
	// KeyStateRevoked is terminal and fail closed.
	KeyStateRevoked
)

func (state KeyState) isValid() bool {
	return state >= KeyStateActive && state <= KeyStateRevoked
}

// OpenResolutionParams contains Device authority acquired in deterministic lock order.
type OpenResolutionParams struct {
	IdempotencyRecordID publicid.ID
	RequestHash         RequestHash
	Scope               network.Scope
	NodeID              node.ID
	NetworkRevision     int64
	InventoryRevision   int64
	DeviceVersion       int64
	SessionGeneration   int64
	DeviceState         DeviceState
	MachineKeyEpoch     int64
	MachineKeyVersion   int64
	MachineKeyState     KeyState
	MachineKeyValidFrom time.Time
	NodeKeyEpoch        int64
	NodeKeyVersion      int64
	NodeKeyState        KeyState
	NodeKeyValidFrom    time.Time
}

// Resolution is either locked mutable authority or an immutable replay result.
type Resolution struct {
	idempotencyRecordID publicid.ID
	requestHash         RequestHash
	scope               network.Scope
	nodeID              node.ID
	networkRevision     int64
	inventoryRevision   int64
	deviceVersion       int64
	sessionGeneration   int64
	deviceState         DeviceState
	machineKeyEpoch     int64
	machineKeyVersion   int64
	machineKeyState     KeyState
	machineKeyValidFrom time.Time
	nodeKeyEpoch        int64
	nodeKeyVersion      int64
	nodeKeyState        KeyState
	nodeKeyValidFrom    time.Time
	completed           Result
}

// NewOpenResolution validates locked authority that still needs mutation.
func NewOpenResolution(params OpenResolutionParams) (Resolution, error) {
	resolution := Resolution{
		idempotencyRecordID: params.IdempotencyRecordID,
		requestHash:         params.RequestHash,
		scope:               params.Scope,
		nodeID:              params.NodeID,
		networkRevision:     params.NetworkRevision,
		inventoryRevision:   params.InventoryRevision,
		deviceVersion:       params.DeviceVersion,
		sessionGeneration:   params.SessionGeneration,
		deviceState:         params.DeviceState,
		machineKeyEpoch:     params.MachineKeyEpoch,
		machineKeyVersion:   params.MachineKeyVersion,
		machineKeyState:     params.MachineKeyState,
		machineKeyValidFrom: params.MachineKeyValidFrom.UTC(),
		nodeKeyEpoch:        params.NodeKeyEpoch,
		nodeKeyVersion:      params.NodeKeyVersion,
		nodeKeyState:        params.NodeKeyState,
		nodeKeyValidFrom:    params.NodeKeyValidFrom.UTC(),
	}
	if !resolution.isOpenValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// NewCompletedResolution validates immutable idempotent replay evidence.
func NewCompletedResolution(result Result, requestHash RequestHash) (Resolution, error) {
	resolution := Resolution{
		idempotencyRecordID: result.IdempotencyRecordID(),
		requestHash:         requestHash,
		completed:           result,
	}
	if !resolution.isCompletedValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// IdempotencyRecordID returns the durable replay record identity.
func (resolution Resolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns the command semantics stored with the replay key.
func (resolution Resolution) RequestHash() RequestHash { return resolution.requestHash }

// Scope returns the locked Network scope.
func (resolution Resolution) Scope() network.Scope { return resolution.scope }

// NodeID returns the locked Device identity.
func (resolution Resolution) NodeID() node.ID { return resolution.nodeID }

// NetworkRevision returns the current client-visible revision.
func (resolution Resolution) NetworkRevision() int64 { return resolution.networkRevision }

// InventoryRevision returns the current Device inventory revision.
func (resolution Resolution) InventoryRevision() int64 { return resolution.inventoryRevision }

// DeviceVersion returns the locked optimistic version.
func (resolution Resolution) DeviceVersion() int64 { return resolution.deviceVersion }

// SessionGeneration returns the locked durable session fence.
func (resolution Resolution) SessionGeneration() int64 { return resolution.sessionGeneration }

// DeviceState returns the locked Device lifecycle.
func (resolution Resolution) DeviceState() DeviceState { return resolution.deviceState }

// MachineKeyEpoch returns the locked current machine-key epoch.
func (resolution Resolution) MachineKeyEpoch() int64 { return resolution.machineKeyEpoch }

// MachineKeyVersion returns the locked current machine-key row version.
func (resolution Resolution) MachineKeyVersion() int64 { return resolution.machineKeyVersion }

// MachineKeyState returns the locked machine-key lifecycle.
func (resolution Resolution) MachineKeyState() KeyState { return resolution.machineKeyState }

// MachineKeyValidFrom returns the current machine-key validity start.
func (resolution Resolution) MachineKeyValidFrom() time.Time { return resolution.machineKeyValidFrom }

// NodeKeyEpoch returns the locked current Node-key epoch.
func (resolution Resolution) NodeKeyEpoch() int64 { return resolution.nodeKeyEpoch }

// NodeKeyVersion returns the locked current Node-key row version.
func (resolution Resolution) NodeKeyVersion() int64 { return resolution.nodeKeyVersion }

// NodeKeyState returns the locked Node-key lifecycle.
func (resolution Resolution) NodeKeyState() KeyState { return resolution.nodeKeyState }

// NodeKeyValidFrom returns the current Node-key validity start.
func (resolution Resolution) NodeKeyValidFrom() time.Time { return resolution.nodeKeyValidFrom }

// CompletedResult returns immutable replay evidence and whether it exists.
func (resolution Resolution) CompletedResult() (Result, bool) {
	return resolution.completed, resolution.completed.IsValid()
}

// IsValid reports whether the resolution is structurally safe.
func (resolution Resolution) IsValid() bool {
	return resolution.isOpenValid() || resolution.isCompletedValid()
}

func (resolution Resolution) isOpenValid() bool {
	return resolution.idempotencyRecordID.IsValid() && resolution.requestHash.IsValid() &&
		resolution.scope.IsValid() && resolution.nodeID.IsValid() &&
		resolution.networkRevision > 0 && resolution.networkRevision < maxInt64 &&
		resolution.inventoryRevision > 0 && resolution.inventoryRevision < maxInt64 &&
		resolution.deviceVersion > 0 && resolution.deviceVersion < maxInt64 &&
		resolution.sessionGeneration > 0 && resolution.sessionGeneration < maxInt64 &&
		resolution.deviceState.isValid() && resolution.machineKeyEpoch > 0 &&
		resolution.machineKeyVersion > 0 && resolution.machineKeyVersion < maxInt64 &&
		resolution.machineKeyState.isValid() && !resolution.machineKeyValidFrom.IsZero() &&
		resolution.nodeKeyEpoch > 0 && resolution.nodeKeyVersion > 0 &&
		resolution.nodeKeyVersion < maxInt64 && resolution.nodeKeyState.isValid() &&
		!resolution.nodeKeyValidFrom.IsZero() && !resolution.completed.IsValid()
}

func (resolution Resolution) isCompletedValid() bool {
	return resolution.idempotencyRecordID.IsValid() && resolution.requestHash.IsValid() &&
		resolution.completed.IsValid() &&
		resolution.completed.IdempotencyRecordID() == resolution.idempotencyRecordID &&
		!resolution.scope.IsValid() && !resolution.nodeID.IsValid()
}

// ResultParams contains the safe committed result of terminal revocation.
type ResultParams struct {
	IdempotencyRecordID publicid.ID
	Scope               network.Scope
	NodeID              node.ID
	DeviceVersion       int64
	SessionGeneration   int64
	NetworkRevision     int64
	InventoryRevision   int64
}

// Result is immutable, non-secret revocation outcome evidence.
type Result struct {
	idempotencyRecordID publicid.ID
	scope               network.Scope
	nodeID              node.ID
	deviceVersion       int64
	sessionGeneration   int64
	networkRevision     int64
	inventoryRevision   int64
}

// NewResult validates a committed revocation outcome.
func NewResult(params ResultParams) (Result, error) {
	result := Result{
		idempotencyRecordID: params.IdempotencyRecordID,
		scope:               params.Scope,
		nodeID:              params.NodeID,
		deviceVersion:       params.DeviceVersion,
		sessionGeneration:   params.SessionGeneration,
		networkRevision:     params.NetworkRevision,
		inventoryRevision:   params.InventoryRevision,
	}
	if !result.IsValid() {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}

// IdempotencyRecordID returns the stable replay result identity.
func (result Result) IdempotencyRecordID() publicid.ID { return result.idempotencyRecordID }

// Scope returns the exact revoked Network scope.
func (result Result) Scope() network.Scope { return result.scope }

// NodeID returns the revoked Device identity.
func (result Result) NodeID() node.ID { return result.nodeID }

// DeviceVersion returns the terminal Device version.
func (result Result) DeviceVersion() int64 { return result.deviceVersion }

// SessionGeneration returns the incremented session fence.
func (result Result) SessionGeneration() int64 { return result.sessionGeneration }

// NetworkRevision returns the committed client-visible revision.
func (result Result) NetworkRevision() int64 { return result.networkRevision }

// InventoryRevision returns the committed Device inventory revision.
func (result Result) InventoryRevision() int64 { return result.inventoryRevision }

// IsValid reports whether the outcome is safe to expose.
func (result Result) IsValid() bool {
	return result.idempotencyRecordID.IsValid() && result.scope.IsValid() &&
		result.nodeID.IsValid() && result.deviceVersion > 1 &&
		result.sessionGeneration > 1 && result.networkRevision > 1 &&
		result.inventoryRevision > 1
}

// Attempt binds one stable ID set and decision window to all transaction retries.
type Attempt struct {
	mutationIDs MutationIDs
	occurredAt  time.Time
	expiresAt   time.Time
}

// NewAttempt validates stable retry identities and bounded decision times.
func NewAttempt(ids MutationIDs, occurredAt, expiresAt time.Time) (Attempt, error) {
	attempt := Attempt{
		mutationIDs: ids,
		occurredAt:  occurredAt.UTC(),
		expiresAt:   expiresAt.UTC(),
	}
	if !attempt.IsValid() {
		return Attempt{}, ErrInvalidAttempt
	}
	return attempt, nil
}

// MutationIDs returns stable durable row identities.
func (attempt Attempt) MutationIDs() MutationIDs { return attempt.mutationIDs }

// OccurredAt returns the stable security decision time.
func (attempt Attempt) OccurredAt() time.Time { return attempt.occurredAt }

// ExpiresAt returns the replay evidence deadline.
func (attempt Attempt) ExpiresAt() time.Time { return attempt.expiresAt }

// IsValid reports whether the retry attempt is complete.
func (attempt Attempt) IsValid() bool {
	return attempt.mutationIDs.IsValid() && !attempt.occurredAt.IsZero() &&
		attempt.expiresAt.After(attempt.occurredAt)
}

// Change is one validated terminal transition and its replay evidence.
type Change struct {
	command    Command
	resolution Resolution
	attempt    Attempt
}

// NewChange validates an active Device/key transition to terminal revocation.
func NewChange(command Command, resolution Resolution, attempt Attempt) (Change, error) {
	change := Change{command: command, resolution: resolution, attempt: attempt}
	if !change.IsValid() {
		return Change{}, ErrInvalidChange
	}
	return change, nil
}

// Command returns the authorized revocation request.
func (change Change) Command() Command { return change.command }

// Resolution returns the authority locked for this decision.
func (change Change) Resolution() Resolution { return change.resolution }

// Attempt returns the stable replay and timing evidence.
func (change Change) Attempt() Attempt { return change.attempt }

// IsValid reports whether every transition fact agrees.
func (change Change) IsValid() bool {
	hash, err := change.command.RequestHash()
	return err == nil && change.command.IsValid() && change.resolution.isOpenValid() &&
		change.attempt.IsValid() && change.resolution.requestHash == hash &&
		change.resolution.scope == change.command.scope &&
		change.resolution.nodeID == change.command.nodeID &&
		change.resolution.deviceVersion == change.command.expectedVersion &&
		change.resolution.deviceState == DeviceStateActive &&
		change.resolution.machineKeyState == KeyStateActive &&
		change.resolution.nodeKeyState == KeyStateActive &&
		!change.attempt.occurredAt.Before(change.resolution.machineKeyValidFrom) &&
		!change.attempt.occurredAt.Before(change.resolution.nodeKeyValidFrom)
}

// BeforeSemanticHash hashes only locked authority state, never the audit reason.
func (change Change) BeforeSemanticHash() [sha256.Size]byte {
	return hashState(
		change.command.nodeID,
		change.resolution.deviceVersion,
		change.resolution.sessionGeneration,
		change.resolution.deviceState,
		change.resolution.machineKeyEpoch,
		change.resolution.machineKeyVersion,
		change.resolution.machineKeyState,
		change.resolution.nodeKeyEpoch,
		change.resolution.nodeKeyVersion,
		change.resolution.nodeKeyState,
	)
}

// AfterSemanticHash hashes the exact terminal state expected after persistence.
func (change Change) AfterSemanticHash() [sha256.Size]byte {
	return hashState(
		change.command.nodeID,
		change.resolution.deviceVersion+1,
		change.resolution.sessionGeneration+1,
		DeviceStateRevoked,
		change.resolution.machineKeyEpoch,
		change.resolution.machineKeyVersion+1,
		KeyStateRevoked,
		change.resolution.nodeKeyEpoch,
		change.resolution.nodeKeyVersion+1,
		KeyStateRevoked,
	)
}

func hashState(
	nodeID node.ID,
	deviceVersion int64,
	sessionGeneration int64,
	deviceState DeviceState,
	machineEpoch int64,
	machineVersion int64,
	machineState KeyState,
	nodeEpoch int64,
	nodeVersion int64,
	nodeState KeyState,
) [sha256.Size]byte {
	material := make([]byte, 0, len(stateHashDomain)+16+8*6+3)
	material = append(material, stateHashDomain...)
	nodeBytes := publicid.ID(nodeID).Bytes()
	material = append(material, nodeBytes[:]...)
	for _, value := range [...]int64{
		deviceVersion,
		sessionGeneration,
		machineEpoch,
		machineVersion,
		nodeEpoch,
		nodeVersion,
	} {
		material = strconv.AppendInt(material, value, 10)
		material = append(material, 0)
	}
	material = append(material, byte(deviceState), byte(machineState), byte(nodeState))
	return sha256.Sum256(material)
}

const maxInt64 = int64(^uint64(0) >> 1)
