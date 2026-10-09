package approval

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/compilation"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/platform/idempotency"
)

var (
	// ErrInvalidRequestIntent reports incomplete client-acknowledged simulation intent.
	ErrInvalidRequestIntent = errors.New("policy approval: invalid request intent")
	// ErrInvalidRequestCommand reports incomplete proposal persistence authority.
	ErrInvalidRequestCommand = errors.New("policy approval: invalid request command")
	// ErrInvalidRequestResolution reports inconsistent locked proposal authority.
	ErrInvalidRequestResolution = errors.New("policy approval: invalid request resolution")
	// ErrInvalidRequestChange reports inconsistent pending-request mutation evidence.
	ErrInvalidRequestChange = errors.New("policy approval: invalid request change")
	// ErrInvalidRequestResult reports malformed committed pending-request evidence.
	ErrInvalidRequestResult = errors.New("policy approval: invalid request result")
)

// RequestIntentParams contains a draft plus the exact evidence acknowledged by its proposer.
type RequestIntentParams struct {
	CompilationRequest    compilation.Request
	CandidateSemanticHash publication.SemanticHash
	ImpactHash            simulation.ImpactHash
	AccountSession        accountsession.Session
	AuditReason           AuditReason
	IdempotencyEvidence   idempotency.Proof
}

// RequestIntent asks the service to freshly simulate and persist one proposal.
type RequestIntent struct {
	compilationRequest    compilation.Request
	candidateSemanticHash publication.SemanticHash
	impactHash            simulation.ImpactHash
	accountSession        accountsession.Session
	auditReason           AuditReason
	idempotencyEvidence   idempotency.Proof
}

// NewRequestIntent validates one client-acknowledged proposal request.
func NewRequestIntent(params RequestIntentParams) (RequestIntent, error) {
	intent := RequestIntent{
		compilationRequest:    params.CompilationRequest,
		candidateSemanticHash: params.CandidateSemanticHash,
		impactHash:            params.ImpactHash, accountSession: params.AccountSession,
		auditReason:         params.AuditReason,
		idempotencyEvidence: params.IdempotencyEvidence,
	}
	if !intent.IsValid() {
		return RequestIntent{}, ErrInvalidRequestIntent
	}
	return intent, nil
}

// CompilationRequest returns immutable typed policy intent.
func (intent RequestIntent) CompilationRequest() compilation.Request {
	return intent.compilationRequest
}

// CandidateSemanticHash returns the proposer-acknowledged compiled digest.
func (intent RequestIntent) CandidateSemanticHash() publication.SemanticHash {
	return intent.candidateSemanticHash
}

// ImpactHash returns the proposer-acknowledged complete impact digest.
func (intent RequestIntent) ImpactHash() simulation.ImpactHash { return intent.impactHash }

// AccountSession returns the proposing authenticated human.
func (intent RequestIntent) AccountSession() accountsession.Session {
	return intent.accountSession
}

// AuditReason returns the proposal explanation.
func (intent RequestIntent) AuditReason() AuditReason { return intent.auditReason }

// IdempotencyEvidence returns secret-safe replay evidence.
func (intent RequestIntent) IdempotencyEvidence() idempotency.Proof {
	return intent.idempotencyEvidence
}

// IsValid reports whether proposal inputs are complete and exact-scoped.
func (intent RequestIntent) IsValid() bool {
	return intent.compilationRequest.IsValid() && intent.candidateSemanticHash.IsValid() &&
		intent.impactHash.IsValid() && intent.accountSession.IsValid() &&
		intent.auditReason.IsValid() && intent.idempotencyEvidence.IsValid()
}

// RequestCommand is freshly simulated proposal evidence ready for persistence.
type RequestCommand struct {
	binding             Binding
	accountSession      accountsession.Session
	auditReason         AuditReason
	idempotencyEvidence idempotency.Proof
}

// NewRequestCommand validates a freshly simulated proposal mutation.
func NewRequestCommand(
	binding Binding,
	session accountsession.Session,
	reason AuditReason,
	evidence idempotency.Proof,
) (RequestCommand, error) {
	command := RequestCommand{
		binding: binding, accountSession: session, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return RequestCommand{}, ErrInvalidRequestCommand
	}
	return command, nil
}

// Binding returns the exact candidate, vector, and impact evidence.
func (command RequestCommand) Binding() Binding { return command.binding }

// Scope returns the exact proposed Network scope.
func (command RequestCommand) Scope() network.Scope { return command.binding.Scope() }

// AccountSession returns the proposing authenticated human.
func (command RequestCommand) AccountSession() accountsession.Session {
	return command.accountSession
}

// AuditReason returns the explicit proposal explanation.
func (command RequestCommand) AuditReason() AuditReason { return command.auditReason }

// IdempotencyEvidence returns secret-safe replay evidence.
func (command RequestCommand) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// RequestHash binds the idempotency record to exact proposal semantics.
func (command RequestCommand) RequestHash() (RequestHash, error) {
	if !command.IsValid() {
		return RequestHash{}, ErrInvalidRequestCommand
	}
	material := make([]byte, 0, 512)
	material = append(material, requestHashDomainV1...)
	material = appendBinding(material, command.binding)
	material = appendSession(material, command.accountSession)
	material = appendText(material, command.auditReason.String())
	return NewRequestHash(sha256.Sum256(material))
}

// IsValid reports whether the persistence command is complete.
func (command RequestCommand) IsValid() bool {
	return command.binding.IsValid() && command.accountSession.IsValid() &&
		command.auditReason.IsValid() && command.idempotencyEvidence.IsValid()
}

// RequestResolution is locked proposal authority or immutable replay evidence.
type RequestResolution struct {
	scope               network.Scope
	baselineVector      accessgraph.RevisionVector
	idempotencyRecordID publicid.ID
	requestHash         RequestHash
	completed           RequestResult
}

// NewRequestResolution validates locked proposal authority.
func NewRequestResolution(
	scope network.Scope,
	baselineVector accessgraph.RevisionVector,
	idempotencyRecordID publicid.ID,
	requestHash RequestHash,
) (RequestResolution, error) {
	resolution := RequestResolution{
		scope: scope, baselineVector: baselineVector,
		idempotencyRecordID: idempotencyRecordID, requestHash: requestHash,
	}
	if !resolution.IsValid() {
		return RequestResolution{}, ErrInvalidRequestResolution
	}
	return resolution, nil
}

// NewCompletedRequestResolution validates committed proposal replay evidence.
func NewCompletedRequestResolution(
	result RequestResult,
	idempotencyRecordID publicid.ID,
	requestHash RequestHash,
) (RequestResolution, error) {
	resolution := RequestResolution{
		scope: result.Scope(), idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, completed: result,
	}
	if !resolution.IsValid() {
		return RequestResolution{}, ErrInvalidRequestResolution
	}
	return resolution, nil
}

// Scope returns the exact locked Network scope.
func (resolution RequestResolution) Scope() network.Scope { return resolution.scope }

// BaselineVector returns fresh authority observed under the proposal lock.
func (resolution RequestResolution) BaselineVector() accessgraph.RevisionVector {
	return resolution.baselineVector
}

// IdempotencyRecordID returns durable replay-record identity.
func (resolution RequestResolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns exact proposal semantics.
func (resolution RequestResolution) RequestHash() RequestHash {
	return resolution.requestHash
}

// CompletedResult returns replayed proposal evidence, if present.
func (resolution RequestResolution) CompletedResult() RequestResult {
	return resolution.completed
}

// IsCompleted reports whether the resolution is immutable replay evidence.
func (resolution RequestResolution) IsCompleted() bool {
	return resolution.completed.IsValid()
}

// IsValid reports whether fresh or replay evidence is coherent.
func (resolution RequestResolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.idempotencyRecordID.IsValid() ||
		!resolution.requestHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope &&
			!resolution.baselineVector.IsValid()
	}
	return resolution.baselineVector.IsValid()
}

// RequestChange is one atomic, replayable pending policy-approval request.
type RequestChange struct {
	command            RequestCommand
	resolution         RequestResolution
	mutationIDs        RequestMutationIDs
	occurredAt         time.Time
	requestExpiresAt   time.Time
	idempotencyExpires time.Time
}

// NewRequestChange validates proposal mutation evidence.
func NewRequestChange(params RequestChangeParams) (RequestChange, error) {
	change := RequestChange{
		command: params.Command, resolution: params.Resolution,
		mutationIDs: params.MutationIDs, occurredAt: params.OccurredAt.UTC(),
		requestExpiresAt:   params.RequestExpiresAt.UTC(),
		idempotencyExpires: params.IdempotencyExpiresAt.UTC(),
	}
	if !change.IsValid() {
		return RequestChange{}, ErrInvalidRequestChange
	}
	return change, nil
}

// RequestChangeParams contains a complete proposal mutation decision.
type RequestChangeParams struct {
	Command              RequestCommand
	Resolution           RequestResolution
	MutationIDs          RequestMutationIDs
	OccurredAt           time.Time
	RequestExpiresAt     time.Time
	IdempotencyExpiresAt time.Time
}

// Command returns immutable proposal intent.
func (change RequestChange) Command() RequestCommand { return change.command }

// Resolution returns locked authority and idempotency evidence.
func (change RequestChange) Resolution() RequestResolution { return change.resolution }

// MutationIDs returns retry-stable durable identities.
func (change RequestChange) MutationIDs() RequestMutationIDs { return change.mutationIDs }

// OccurredAt returns the stable proposal decision time.
func (change RequestChange) OccurredAt() time.Time { return change.occurredAt }

// RequestExpiresAt returns the exclusive independent-approval deadline.
func (change RequestChange) RequestExpiresAt() time.Time { return change.requestExpiresAt }

// IdempotencyExpiresAt returns the exclusive replay-evidence deadline.
func (change RequestChange) IdempotencyExpiresAt() time.Time {
	return change.idempotencyExpires
}

// IsValid reports whether all proposal mutation facts agree.
func (change RequestChange) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() &&
		!change.resolution.IsCompleted() && change.mutationIDs.IsValid() &&
		change.command.Scope() == change.resolution.Scope() &&
		change.command.Binding().BaselineVector().Equal(change.resolution.BaselineVector()) &&
		!change.occurredAt.IsZero() &&
		change.command.AccountSession().IsActiveAt(change.occurredAt) &&
		change.requestExpiresAt.Equal(change.occurredAt.Add(RequestLifetime)) &&
		change.idempotencyExpires.After(change.requestExpiresAt)
}

// RequestResultParams contains safe committed pending-request evidence.
type RequestResultParams struct {
	RequestID           RequestID
	Binding             Binding
	ProposerPrincipalID identity.PrincipalID
	ProposerSessionID   accountsession.ID
	RequestVersion      int64
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// RequestResult is safe committed evidence awaiting an independent human.
type RequestResult struct {
	requestID           RequestID
	binding             Binding
	proposerPrincipalID identity.PrincipalID
	proposerSessionID   accountsession.ID
	requestVersion      int64
	createdAt           time.Time
	expiresAt           time.Time
}

// NewRequestResult validates committed pending-request evidence.
func NewRequestResult(params RequestResultParams) (RequestResult, error) {
	result := RequestResult{
		requestID: params.RequestID, binding: params.Binding,
		proposerPrincipalID: params.ProposerPrincipalID,
		proposerSessionID:   params.ProposerSessionID,
		requestVersion:      params.RequestVersion, createdAt: params.CreatedAt.UTC(),
		expiresAt: params.ExpiresAt.UTC(),
	}
	if !result.IsValid() {
		return RequestResult{}, ErrInvalidRequestResult
	}
	return result, nil
}

// RequestID returns the durable proposal identity.
func (result RequestResult) RequestID() RequestID { return result.requestID }

// Binding returns exact candidate, vector, and impact evidence.
func (result RequestResult) Binding() Binding { return result.binding }

// Scope returns the exact Network boundary.
func (result RequestResult) Scope() network.Scope { return result.binding.Scope() }

// ProposerPrincipalID returns the authenticated proposing human.
func (result RequestResult) ProposerPrincipalID() identity.PrincipalID {
	return result.proposerPrincipalID
}

// ProposerSessionID returns the proposing Account Session.
func (result RequestResult) ProposerSessionID() accountsession.ID {
	return result.proposerSessionID
}

// RequestVersion returns the pending-request CAS version.
func (result RequestResult) RequestVersion() int64 { return result.requestVersion }

// State returns the durable lifecycle state.
func (RequestResult) State() State { return StatePending }

// CreatedAt returns the committed proposal time.
func (result RequestResult) CreatedAt() time.Time { return result.createdAt }

// ExpiresAt returns the exclusive approval and publication deadline.
func (result RequestResult) ExpiresAt() time.Time { return result.expiresAt }

// Equal reports exact committed proposal equality.
func (result RequestResult) Equal(other RequestResult) bool {
	return result.IsValid() && other.IsValid() && result.requestID == other.requestID &&
		result.binding.Equal(other.binding) &&
		result.proposerPrincipalID == other.proposerPrincipalID &&
		result.proposerSessionID == other.proposerSessionID &&
		result.requestVersion == other.requestVersion &&
		result.createdAt.Equal(other.createdAt) && result.expiresAt.Equal(other.expiresAt)
}

// IsValid reports whether committed pending-request evidence is complete.
func (result RequestResult) IsValid() bool {
	return result.requestID.IsValid() && result.binding.IsValid() &&
		result.proposerPrincipalID.IsValid() && result.proposerSessionID.IsValid() &&
		result.requestVersion == 1 && !result.createdAt.IsZero() &&
		result.expiresAt.Equal(result.createdAt.Add(RequestLifetime))
}
