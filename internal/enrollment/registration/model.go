package registration

import (
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
)

var (
	// ErrInvalidCommand reports an incomplete registration request.
	ErrInvalidCommand = errors.New("registration: invalid command")
	// ErrInvalidResolution reports inconsistent state returned under lock.
	ErrInvalidResolution = errors.New("registration: invalid resolution")
	// ErrInvalidChange reports an incomplete atomic registration mutation.
	ErrInvalidChange = errors.New("registration: invalid change")
	// ErrInvalidResult reports inconsistent committed registration state.
	ErrInvalidResult = errors.New("registration: invalid result")
	// ErrIntentConflict reports reuse of an intent ID with different authenticated semantics.
	ErrIntentConflict = errors.New("registration: intent conflict")
)

// Command is an authenticated, server-scoped credential registration request.
// It contains no plaintext bearer token; the credential proof is verified at
// the authentication boundary before this use case is invoked.
type Command struct {
	RegistrationID enrollment.RegistrationID
	Scope          network.Scope
	CredentialID   enrollment.CredentialID
	Identity       node.RegistrationIdentity
	Hostname       node.Hostname
	RecoveryEpoch  int64
}

// IsValid reports whether all trusted-boundary inputs are present.
func (command Command) IsValid() bool {
	return command.RegistrationID.IsValid() && command.Scope.IsValid() &&
		command.CredentialID.IsValid() && command.Identity.IsValid() &&
		command.Hostname.IsValid() && command.RecoveryEpoch > 0
}

// Disposition identifies whether registration created or resumed a logical Node.
type Disposition uint8

const (
	// DispositionUnknown is the invalid zero value.
	DispositionUnknown Disposition = iota
	// DispositionCreated means a new logical Node was created.
	DispositionCreated
	// DispositionResumed means an authenticated existing Node was retained.
	DispositionResumed
)

func (disposition Disposition) isValid() bool {
	return disposition == DispositionCreated || disposition == DispositionResumed
}

// Result is the safe committed outcome returned by registration and replay.
type Result struct {
	registrationID  enrollment.RegistrationID
	scope           network.Scope
	nodeID          node.ID
	hostname        node.Hostname
	disposition     Disposition
	networkRevision int64
}

// NewResult validates a committed registration outcome loaded by an adapter.
func NewResult(
	registrationID enrollment.RegistrationID,
	scope network.Scope,
	nodeID node.ID,
	hostname node.Hostname,
	disposition Disposition,
	networkRevision int64,
) (Result, error) {
	result := Result{
		registrationID:  registrationID,
		scope:           scope,
		nodeID:          nodeID,
		hostname:        hostname,
		disposition:     disposition,
		networkRevision: networkRevision,
	}
	if !result.IsValid() {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}

// RegistrationID returns the idempotent registration intent.
func (result Result) RegistrationID() enrollment.RegistrationID { return result.registrationID }

// Scope returns the exact committed Network scope.
func (result Result) Scope() network.Scope { return result.scope }

// NodeID returns the single logical Node outcome.
func (result Result) NodeID() node.ID { return result.nodeID }

// Hostname returns the final collision-safe hostname.
func (result Result) Hostname() node.Hostname { return result.hostname }

// Disposition returns whether the Node was created or resumed.
func (result Result) Disposition() Disposition { return result.disposition }

// NetworkRevision returns the authoritative revision committed with the result.
func (result Result) NetworkRevision() int64 { return result.networkRevision }

// IsValid reports whether the value is safe to return as committed state.
func (result Result) IsValid() bool {
	return result.registrationID.IsValid() && result.scope.IsValid() && result.nodeID.IsValid() &&
		result.hostname.IsValid() && result.disposition.isValid() && result.networkRevision > 0
}

// Resolution is durable registration state read under the required locks.
type Resolution struct {
	registration      enrollment.Registration
	credential        enrollment.Credential
	credentialID      enrollment.CredentialID
	requestHash       RequestHash
	existingNode      node.ID
	completed         Result
	completedIdentity node.RegistrationIdentity
}

// NewOpenResolution constructs locked state that still requires a mutation.
func NewOpenResolution(
	registration enrollment.Registration,
	credential enrollment.Credential,
	existingNode node.ID,
	requestHash RequestHash,
) (Resolution, error) {
	resolution := Resolution{
		registration: registration,
		credential:   credential,
		credentialID: credential.ID(),
		requestHash:  requestHash,
		existingNode: existingNode,
	}
	if !resolution.isOpenValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// NewCompletedResolution constructs an idempotent replay outcome with the
// original credential and cryptographic identity binding.
func NewCompletedResolution(
	registration enrollment.Registration,
	credentialID enrollment.CredentialID,
	identity node.RegistrationIdentity,
	requestHash RequestHash,
	result Result,
) (Resolution, error) {
	resolution := Resolution{
		registration:      registration,
		credentialID:      credentialID,
		requestHash:       requestHash,
		completed:         result,
		completedIdentity: identity,
	}
	if !resolution.isCompletedValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// Registration returns the locked registration state.
func (resolution Resolution) Registration() enrollment.Registration { return resolution.registration }

// Credential returns the locked credential state for an open registration.
func (resolution Resolution) Credential() enrollment.Credential { return resolution.credential }

// CredentialID returns the credential bound to this registration intent.
func (resolution Resolution) CredentialID() enrollment.CredentialID { return resolution.credentialID }

// RequestHash returns the durable semantic hash bound to the intent ID.
func (resolution Resolution) RequestHash() RequestHash { return resolution.requestHash }

// ExistingNodeID returns a resumable Node and whether one exists.
func (resolution Resolution) ExistingNodeID() (node.ID, bool) {
	return resolution.existingNode, resolution.existingNode.IsValid()
}

// CompletedResult returns the previously committed result and whether one exists.
func (resolution Resolution) CompletedResult() (Result, bool) {
	return resolution.completed, resolution.completed.IsValid()
}

// CompletedIdentity returns the committed cryptographic identity and whether one exists.
func (resolution Resolution) CompletedIdentity() (node.RegistrationIdentity, bool) {
	return resolution.completedIdentity, resolution.completedIdentity.IsValid()
}

func (resolution Resolution) isOpenValid() bool {
	state := resolution.registration.State()
	return resolution.registration.IsValid() && resolution.credential.IsValid() &&
		(state == enrollment.RegistrationStatePending || state == enrollment.RegistrationStateAuthorized) &&
		resolution.registration.ProfileID() == resolution.credential.ProfileID() &&
		resolution.credentialID == resolution.credential.ID() && resolution.requestHash.IsValid() &&
		!resolution.completed.IsValid() &&
		!resolution.completedIdentity.IsValid()
}

func (resolution Resolution) isCompletedValid() bool {
	nodeID, completed := resolution.registration.NodeID()
	return resolution.registration.IsValid() && completed && resolution.completed.IsValid() &&
		resolution.credentialID.IsValid() && resolution.requestHash.IsValid() &&
		resolution.completedIdentity.IsValid() &&
		resolution.registration.ID() == resolution.completed.RegistrationID() &&
		resolution.registration.Scope() == resolution.completed.Scope() &&
		nodeID == resolution.completed.NodeID() && !resolution.credential.IsValid() &&
		!resolution.existingNode.IsValid()
}

// Change contains one fully validated atomic registration mutation.
type Change struct {
	registration enrollment.Registration
	credential   enrollment.Credential
	identity     node.RegistrationIdentity
	nodeID       node.ID
	hostname     node.Hostname
	disposition  Disposition
	occurredAt   time.Time
}

// NewChange validates the application decision passed to persistence.
func NewChange(
	registration enrollment.Registration,
	credential enrollment.Credential,
	identity node.RegistrationIdentity,
	nodeID node.ID,
	hostname node.Hostname,
	disposition Disposition,
	occurredAt time.Time,
) (Change, error) {
	change := Change{
		registration: registration,
		credential:   credential,
		identity:     identity,
		nodeID:       nodeID,
		hostname:     hostname,
		disposition:  disposition,
		occurredAt:   occurredAt.UTC(),
	}
	if !change.IsValid() {
		return Change{}, ErrInvalidChange
	}
	return change, nil
}

// Registration returns the completed state to persist.
func (change Change) Registration() enrollment.Registration { return change.registration }

// Credential returns the consumed state to persist.
func (change Change) Credential() enrollment.Credential { return change.credential }

// Identity returns the authenticated machine and Node keys.
func (change Change) Identity() node.RegistrationIdentity { return change.identity }

// NodeID returns the logical Node to create or resume.
func (change Change) NodeID() node.ID { return change.nodeID }

// Hostname returns the requested canonical hostname.
func (change Change) Hostname() node.Hostname { return change.hostname }

// Disposition returns the requested persistence path.
func (change Change) Disposition() Disposition { return change.disposition }

// OccurredAt returns the stable decision time shared across transaction retries.
func (change Change) OccurredAt() time.Time { return change.occurredAt }

// IsValid reports whether the atomic change is internally consistent.
func (change Change) IsValid() bool {
	registrationNodeID, completed := change.registration.NodeID()
	return change.registration.IsValid() && completed && change.credential.IsValid() &&
		change.identity.IsValid() && change.nodeID.IsValid() && change.hostname.IsValid() &&
		change.disposition.isValid() && !change.occurredAt.IsZero() && registrationNodeID == change.nodeID &&
		change.registration.ProfileID() == change.credential.ProfileID() &&
		change.registration.MachineFingerprint() == change.identity.MachineKey().Fingerprint()
}
