package keyrotation

import (
	"crypto/sha256"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const rotationProofDomain = "meshtransit/node-key-rotation/v1\x00"

var (
	// ErrInvalidCommand reports malformed or aliased authenticated key material.
	ErrInvalidCommand = errors.New("node key rotation: invalid command")
	// ErrInvalidResolution reports inconsistent durable identity authority.
	ErrInvalidResolution = errors.New("node key rotation: invalid resolution")
	// ErrInvalidChange reports an incomplete atomic rotation decision.
	ErrInvalidChange = errors.New("node key rotation: invalid change")
	// ErrInvalidResult reports malformed committed rotation evidence.
	ErrInvalidResult = errors.New("node key rotation: invalid result")
	// ErrNotFound hides whether the authenticated machine has a live Device.
	ErrNotFound = errors.New("node key rotation: device unavailable")
	// ErrConflict reports stale or mismatched old-key authority.
	ErrConflict = errors.New("node key rotation: stale key epoch")
)

// CommandParams contains transport-authenticated rotation material.
type CommandParams struct {
	OperationID enrollment.RegistrationID
	MachineKey  node.MachineKey
	OldNodeKey  node.Key
	NewNodeKey  node.Key
}

// Command requests one monotonic Node-key epoch transition.
type Command struct {
	operationID enrollment.RegistrationID
	machineKey  node.MachineKey
	oldNodeKey  node.Key
	newNodeKey  node.Key
}

// NewCommand validates distinct, non-zero old and new Node keys.
func NewCommand(params CommandParams) (Command, error) {
	command := Command{
		operationID: params.OperationID,
		machineKey:  params.MachineKey,
		oldNodeKey:  params.OldNodeKey,
		newNodeKey:  params.NewNodeKey,
	}
	if !command.IsValid() {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

// OperationID returns the request correlation identity.
func (command Command) OperationID() enrollment.RegistrationID { return command.operationID }

// MachineKey returns the transport-authenticated machine identity.
func (command Command) MachineKey() node.MachineKey { return command.machineKey }

// OldNodeKey returns the exact current epoch expected by the caller.
func (command Command) OldNodeKey() node.Key { return command.oldNodeKey }

// NewNodeKey returns the proposed next epoch public key.
func (command Command) NewNodeKey() node.Key { return command.newNodeKey }

// IsValid reports whether the authenticated transition is structurally safe.
func (command Command) IsValid() bool {
	return command.operationID.IsValid() && command.machineKey.IsValid() &&
		command.oldNodeKey.IsValid() && command.newNodeKey.IsValid() &&
		command.oldNodeKey != command.newNodeKey
}

// RotationProofHash binds machine continuity to the exact old/new transition.
func (command Command) RotationProofHash() ([sha256.Size]byte, error) {
	if !command.IsValid() {
		return [sha256.Size]byte{}, ErrInvalidCommand
	}
	machine := command.machineKey.Bytes()
	oldKey := command.oldNodeKey.Bytes()
	newKey := command.newNodeKey.Bytes()
	material := make([]byte, 0, len(rotationProofDomain)+len(machine)+len(oldKey)+len(newKey))
	material = append(material, rotationProofDomain...)
	material = append(material, machine[:]...)
	material = append(material, oldKey[:]...)
	material = append(material, newKey[:]...)
	return sha256.Sum256(material), nil
}

// OpenResolutionParams contains locked current authority before mutation.
type OpenResolutionParams struct {
	Scope             network.Scope
	NodeID            node.ID
	Hostname          node.Hostname
	MachineKey        node.MachineKey
	CurrentNodeKey    node.Key
	NetworkRevision   int64
	InventoryRevision int64
	DeviceVersion     int64
	SessionGeneration int64
	NodeKeyEpoch      int64
	NodeKeyVersion    int64
	NodeKeyValidFrom  time.Time
	// BudgetWindowStart is when the epoch BudgetEpoch names became active;
	// it must be zero exactly when BudgetEpoch reports false.
	BudgetWindowStart time.Time
}

// Resolution is either locked mutable authority or a converged replay result.
type Resolution struct {
	scope             network.Scope
	nodeID            node.ID
	hostname          node.Hostname
	machineKey        node.MachineKey
	currentNodeKey    node.Key
	networkRevision   int64
	inventoryRevision int64
	deviceVersion     int64
	sessionGeneration int64
	nodeKeyEpoch      int64
	nodeKeyVersion    int64
	nodeKeyValidFrom  time.Time
	budgetWindowStart time.Time
	completed         Result
}

// NewOpenResolution validates locked active Device and key-epoch evidence.
func NewOpenResolution(params OpenResolutionParams) (Resolution, error) {
	resolution := Resolution{
		scope:             params.Scope,
		nodeID:            params.NodeID,
		hostname:          params.Hostname,
		machineKey:        params.MachineKey,
		currentNodeKey:    params.CurrentNodeKey,
		networkRevision:   params.NetworkRevision,
		inventoryRevision: params.InventoryRevision,
		deviceVersion:     params.DeviceVersion,
		sessionGeneration: params.SessionGeneration,
		nodeKeyEpoch:      params.NodeKeyEpoch,
		nodeKeyVersion:    params.NodeKeyVersion,
		nodeKeyValidFrom:  params.NodeKeyValidFrom.UTC(),
		budgetWindowStart: params.BudgetWindowStart.UTC(),
	}
	if !resolution.isOpenValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// NewCompletedResolution validates a replay that already committed.
func NewCompletedResolution(result Result) (Resolution, error) {
	resolution := Resolution{completed: result}
	if !resolution.isCompletedValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// Scope returns the exact Network owning the Device.
func (resolution Resolution) Scope() network.Scope { return resolution.scope }

// NodeID returns the stable logical Device public identity.
func (resolution Resolution) NodeID() node.ID { return resolution.nodeID }

// Hostname returns the preserved canonical Device hostname.
func (resolution Resolution) Hostname() node.Hostname { return resolution.hostname }

// MachineKey returns the locked active machine public key.
func (resolution Resolution) MachineKey() node.MachineKey { return resolution.machineKey }

// CurrentNodeKey returns the locked active Node key.
func (resolution Resolution) CurrentNodeKey() node.Key { return resolution.currentNodeKey }

// NetworkRevision returns the locked client-visible revision.
func (resolution Resolution) NetworkRevision() int64 { return resolution.networkRevision }

// InventoryRevision returns the locked Device inventory revision.
func (resolution Resolution) InventoryRevision() int64 { return resolution.inventoryRevision }

// DeviceVersion returns the locked aggregate version.
func (resolution Resolution) DeviceVersion() int64 { return resolution.deviceVersion }

// SessionGeneration returns the current durable session fence.
func (resolution Resolution) SessionGeneration() int64 { return resolution.sessionGeneration }

// NodeKeyEpoch returns the current monotonic Node-key epoch.
func (resolution Resolution) NodeKeyEpoch() int64 { return resolution.nodeKeyEpoch }

// NodeKeyVersion returns the current key-row optimistic version.
func (resolution Resolution) NodeKeyVersion() int64 { return resolution.nodeKeyVersion }

// NodeKeyValidFrom returns when the current Node-key epoch became active.
func (resolution Resolution) NodeKeyValidFrom() time.Time { return resolution.nodeKeyValidFrom }

// CompletedResult returns a converged replay result when present.
func (resolution Resolution) CompletedResult() (Result, bool) {
	return resolution.completed, resolution.completed.IsValid()
}

// IsValid reports whether the resolution has exactly one safe shape.
func (resolution Resolution) IsValid() bool {
	return resolution.isOpenValid() || resolution.isCompletedValid()
}

func (resolution Resolution) isOpenValid() bool {
	return resolution.scope.IsValid() && resolution.nodeID.IsValid() &&
		resolution.hostname.IsValid() && resolution.machineKey.IsValid() &&
		resolution.currentNodeKey.IsValid() && resolution.networkRevision > 0 &&
		resolution.inventoryRevision > 0 && resolution.deviceVersion > 0 &&
		resolution.sessionGeneration > 0 && resolution.nodeKeyEpoch > 0 &&
		resolution.nodeKeyVersion > 0 && !resolution.nodeKeyValidFrom.IsZero() &&
		resolution.budgetEvidenceValid() && !resolution.completed.IsValid()
}

func (resolution Resolution) isCompletedValid() bool {
	return resolution.completed.IsValid() && !resolution.scope.IsValid() &&
		!resolution.nodeID.IsValid() && !resolution.hostname.IsValid() &&
		!resolution.machineKey.IsValid() && !resolution.currentNodeKey.IsValid() &&
		resolution.networkRevision == 0 && resolution.inventoryRevision == 0 &&
		resolution.deviceVersion == 0 && resolution.sessionGeneration == 0 &&
		resolution.nodeKeyEpoch == 0 && resolution.nodeKeyVersion == 0 &&
		resolution.nodeKeyValidFrom.IsZero() && resolution.budgetWindowStart.IsZero()
}

// ResultParams contains the complete committed rotation projection.
type ResultParams struct {
	OperationID       enrollment.RegistrationID
	Scope             network.Scope
	NodeID            node.ID
	Hostname          node.Hostname
	DeviceVersion     int64
	NodeKeyEpoch      int64
	SessionGeneration int64
	NetworkRevision   int64
	InventoryRevision int64
}

// Result is the secret-free committed rotation outcome.
type Result struct {
	operationID       enrollment.RegistrationID
	scope             network.Scope
	nodeID            node.ID
	hostname          node.Hostname
	deviceVersion     int64
	nodeKeyEpoch      int64
	sessionGeneration int64
	networkRevision   int64
	inventoryRevision int64
}

// NewResult validates a committed rotation outcome.
func NewResult(params ResultParams) (Result, error) {
	result := Result{
		operationID:       params.OperationID,
		scope:             params.Scope,
		nodeID:            params.NodeID,
		hostname:          params.Hostname,
		deviceVersion:     params.DeviceVersion,
		nodeKeyEpoch:      params.NodeKeyEpoch,
		sessionGeneration: params.SessionGeneration,
		networkRevision:   params.NetworkRevision,
		inventoryRevision: params.InventoryRevision,
	}
	if !result.IsValid() {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}

// OperationID returns the request correlation identity.
func (result Result) OperationID() enrollment.RegistrationID { return result.operationID }

// Scope returns the exact Network owning the rotated Device.
func (result Result) Scope() network.Scope { return result.scope }

// NodeID returns the stable logical Device identity.
func (result Result) NodeID() node.ID { return result.nodeID }

// Hostname returns the preserved canonical Device hostname.
func (result Result) Hostname() node.Hostname { return result.hostname }

// DeviceVersion returns the committed aggregate version.
func (result Result) DeviceVersion() int64 { return result.deviceVersion }

// NodeKeyEpoch returns the committed active Node-key epoch.
func (result Result) NodeKeyEpoch() int64 { return result.nodeKeyEpoch }

// SessionGeneration returns the committed session fence.
func (result Result) SessionGeneration() int64 { return result.sessionGeneration }

// NetworkRevision returns the committed client-visible revision.
func (result Result) NetworkRevision() int64 { return result.networkRevision }

// InventoryRevision returns the committed Device inventory revision.
func (result Result) InventoryRevision() int64 { return result.inventoryRevision }

// IsValid reports whether the committed projection is complete.
func (result Result) IsValid() bool {
	return result.operationID.IsValid() && result.scope.IsValid() &&
		result.nodeID.IsValid() && result.hostname.IsValid() &&
		result.deviceVersion > 1 && result.nodeKeyEpoch > 1 &&
		result.sessionGeneration > 1 && result.networkRevision > 1 &&
		result.inventoryRevision > 1
}

// Change is one validated atomic rotation decision.
type Change struct {
	command     Command
	resolution  Resolution
	mutationIDs MutationIDs
	occurredAt  time.Time
	proofHash   [sha256.Size]byte
}

// NewChange validates machine continuity, exact old epoch, and decision time.
func NewChange(
	command Command,
	resolution Resolution,
	mutationIDs MutationIDs,
	occurredAt time.Time,
) (Change, error) {
	proofHash, err := command.RotationProofHash()
	if err != nil {
		return Change{}, err
	}
	change := Change{
		command:     command,
		resolution:  resolution,
		mutationIDs: mutationIDs,
		occurredAt:  occurredAt.UTC(),
		proofHash:   proofHash,
	}
	if !change.IsValid() {
		return Change{}, ErrInvalidChange
	}
	return change, nil
}

// Command returns the authenticated old/new transition.
func (change Change) Command() Command { return change.command }

// Resolution returns the locked authority used by the decision.
func (change Change) Resolution() Resolution { return change.resolution }

// MutationIDs returns stable row identities shared across retries.
func (change Change) MutationIDs() MutationIDs { return change.mutationIDs }

// OccurredAt returns the stable decision time shared across retries.
func (change Change) OccurredAt() time.Time { return change.occurredAt }

// ProofHash returns the domain-separated machine and old/new key binding.
func (change Change) ProofHash() [sha256.Size]byte { return change.proofHash }

// IsValid reports whether the decision is bound to current locked authority.
func (change Change) IsValid() bool {
	proof, err := change.command.RotationProofHash()
	return err == nil && change.resolution.isOpenValid() && change.mutationIDs.IsValid() &&
		!change.occurredAt.IsZero() &&
		!change.occurredAt.Before(change.resolution.NodeKeyValidFrom()) &&
		change.command.MachineKey() == change.resolution.MachineKey() &&
		change.command.OldNodeKey() == change.resolution.CurrentNodeKey() &&
		change.proofHash == proof
}
