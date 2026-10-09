package approval

import (
	"crypto/sha256"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/idempotency"
)

var (
	// ErrInvalidApprovalCommand reports incomplete independent-human decision authority.
	ErrInvalidApprovalCommand = errors.New("policy approval: invalid approval command")
	// ErrInvalidApprovalResolution reports inconsistent locked request authority.
	ErrInvalidApprovalResolution = errors.New("policy approval: invalid approval resolution")
	// ErrInvalidApprovalChange reports inconsistent immutable decision evidence.
	ErrInvalidApprovalChange = errors.New("policy approval: invalid approval change")
	// ErrInvalidApprovalResult reports malformed committed approval evidence.
	ErrInvalidApprovalResult = errors.New("policy approval: invalid approval result")
)

// CommandParams contains an independent human's exact decision input.
type CommandParams struct {
	Scope                  network.Scope
	RequestID              RequestID
	ExpectedRequestVersion int64
	CandidateSemanticHash  publication.SemanticHash
	ImpactHash             simulation.ImpactHash
	AccountSession         accountsession.Session
	AuditReason            AuditReason
	IdempotencyEvidence    idempotency.Proof
}

// Command approves one unchanged pending request.
type Command struct {
	scope                  network.Scope
	requestID              RequestID
	expectedRequestVersion int64
	candidateSemanticHash  publication.SemanticHash
	impactHash             simulation.ImpactHash
	accountSession         accountsession.Session
	auditReason            AuditReason
	idempotencyEvidence    idempotency.Proof
}

// NewCommand validates one independent human decision.
func NewCommand(params CommandParams) (Command, error) {
	command := Command{
		scope: params.Scope, requestID: params.RequestID,
		expectedRequestVersion: params.ExpectedRequestVersion,
		candidateSemanticHash:  params.CandidateSemanticHash,
		impactHash:             params.ImpactHash, accountSession: params.AccountSession,
		auditReason:         params.AuditReason,
		idempotencyEvidence: params.IdempotencyEvidence,
	}
	if !command.IsValid() {
		return Command{}, ErrInvalidApprovalCommand
	}
	return command, nil
}

// Scope returns the exact Network boundary.
func (command Command) Scope() network.Scope { return command.scope }

// RequestID returns the pending proposal identity.
func (command Command) RequestID() RequestID { return command.requestID }

// ExpectedRequestVersion returns the decision CAS base.
func (command Command) ExpectedRequestVersion() int64 {
	return command.expectedRequestVersion
}

// CandidateSemanticHash returns the approver-acknowledged compiled digest.
func (command Command) CandidateSemanticHash() publication.SemanticHash {
	return command.candidateSemanticHash
}

// ImpactHash returns the approver-acknowledged complete impact digest.
func (command Command) ImpactHash() simulation.ImpactHash {
	return command.impactHash
}

// AccountSession returns the independent approving human.
func (command Command) AccountSession() accountsession.Session {
	return command.accountSession
}

// AuditReason returns the decision explanation.
func (command Command) AuditReason() AuditReason { return command.auditReason }

// IdempotencyEvidence returns secret-safe replay evidence.
func (command Command) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// DecisionHash binds the idempotency record to exact approval semantics.
func (command Command) DecisionHash() (DecisionHash, error) {
	if !command.IsValid() {
		return DecisionHash{}, ErrInvalidApprovalCommand
	}
	material := make([]byte, 0, 384)
	material = append(material, decisionHashDomainV1...)
	material = appendText(material, command.scope.WorkspaceID().String())
	material = appendText(material, command.scope.NetworkID().String())
	material = appendText(material, command.requestID.String())
	material = appendInt64(material, command.expectedRequestVersion)
	semanticHash := command.candidateSemanticHash.Bytes()
	material = append(material, semanticHash[:]...)
	impactHash := command.impactHash.Bytes()
	material = append(material, impactHash[:]...)
	material = appendSession(material, command.accountSession)
	material = appendText(material, command.auditReason.String())
	return NewDecisionHash(sha256.Sum256(material))
}

// IsValid reports whether the approval input is complete.
func (command Command) IsValid() bool {
	return command.scope.IsValid() && command.requestID.IsValid() &&
		command.expectedRequestVersion > 0 && command.candidateSemanticHash.IsValid() &&
		command.impactHash.IsValid() && command.accountSession.IsValid() &&
		command.auditReason.IsValid() && command.idempotencyEvidence.IsValid()
}

// ResolutionParams contains one locked pending request.
type ResolutionParams struct {
	Scope               network.Scope
	RequestID           RequestID
	RequestVersion      int64
	State               State
	Binding             Binding
	ProposerPrincipalID identity.PrincipalID
	ProposerSessionID   accountsession.ID
	RequestExpiresAt    time.Time
	IdempotencyRecordID publicid.ID
	DecisionHash        DecisionHash
}

// Resolution is locked pending-request authority or immutable replay evidence.
type Resolution struct {
	scope               network.Scope
	requestID           RequestID
	requestVersion      int64
	state               State
	binding             Binding
	proposerPrincipalID identity.PrincipalID
	proposerSessionID   accountsession.ID
	requestExpiresAt    time.Time
	idempotencyRecordID publicid.ID
	decisionHash        DecisionHash
	completed           Result
}

// NewResolution validates locked pending-request authority.
func NewResolution(params ResolutionParams) (Resolution, error) {
	resolution := Resolution{
		scope: params.Scope, requestID: params.RequestID,
		requestVersion: params.RequestVersion, state: params.State,
		binding: params.Binding, proposerPrincipalID: params.ProposerPrincipalID,
		proposerSessionID:   params.ProposerSessionID,
		requestExpiresAt:    params.RequestExpiresAt.UTC(),
		idempotencyRecordID: params.IdempotencyRecordID,
		decisionHash:        params.DecisionHash,
	}
	if !resolution.IsValid() || resolution.IsCompleted() {
		return Resolution{}, ErrInvalidApprovalResolution
	}
	return resolution, nil
}

// NewCompletedResolution validates committed approval replay evidence.
func NewCompletedResolution(
	result Result,
	idempotencyRecordID publicid.ID,
	decisionHash DecisionHash,
) (Resolution, error) {
	resolution := Resolution{
		scope: result.Scope(), requestID: result.RequestID(),
		idempotencyRecordID: idempotencyRecordID,
		decisionHash:        decisionHash, completed: result,
	}
	if !resolution.IsValid() {
		return Resolution{}, ErrInvalidApprovalResolution
	}
	return resolution, nil
}

// Scope returns the exact locked Network scope.
func (resolution Resolution) Scope() network.Scope { return resolution.scope }

// RequestID returns the locked proposal identity.
func (resolution Resolution) RequestID() RequestID {
	return resolution.requestID
}

// RequestVersion returns the current request CAS version.
func (resolution Resolution) RequestVersion() int64 {
	return resolution.requestVersion
}

// State returns the current durable request state.
func (resolution Resolution) State() State { return resolution.state }

// Binding returns the exact proposal evidence.
func (resolution Resolution) Binding() Binding { return resolution.binding }

// ProposerPrincipalID returns the proposing human identity.
func (resolution Resolution) ProposerPrincipalID() identity.PrincipalID {
	return resolution.proposerPrincipalID
}

// ProposerSessionID returns the proposing Account Session.
func (resolution Resolution) ProposerSessionID() accountsession.ID {
	return resolution.proposerSessionID
}

// RequestExpiresAt returns the exclusive decision and publication deadline.
func (resolution Resolution) RequestExpiresAt() time.Time {
	return resolution.requestExpiresAt
}

// IdempotencyRecordID returns durable replay-record identity.
func (resolution Resolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// DecisionHash returns exact approval semantics.
func (resolution Resolution) DecisionHash() DecisionHash {
	return resolution.decisionHash
}

// CompletedResult returns replayed approval evidence, if present.
func (resolution Resolution) CompletedResult() Result {
	return resolution.completed
}

// IsCompleted reports whether the resolution is immutable replay evidence.
func (resolution Resolution) IsCompleted() bool {
	return resolution.completed.IsValid()
}

// IsValid reports whether fresh or replay evidence is coherent.
func (resolution Resolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.requestID.IsValid() ||
		!resolution.idempotencyRecordID.IsValid() || !resolution.decisionHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope &&
			resolution.completed.RequestID() == resolution.requestID &&
			resolution.requestVersion == 0 && resolution.state == StateUnknown &&
			!resolution.binding.IsValid() && !resolution.proposerPrincipalID.IsValid() &&
			!resolution.proposerSessionID.IsValid() && resolution.requestExpiresAt.IsZero()
	}
	return resolution.requestVersion == 1 && resolution.state == StatePending &&
		resolution.binding.IsValid() && resolution.binding.Scope() == resolution.scope &&
		resolution.proposerPrincipalID.IsValid() && resolution.proposerSessionID.IsValid() &&
		!resolution.requestExpiresAt.IsZero()
}

// ChangeParams contains one complete independent-human decision.
type ChangeParams struct {
	Command              Command
	Resolution           Resolution
	MutationIDs          MutationIDs
	OccurredAt           time.Time
	IdempotencyExpiresAt time.Time
}

// Change is one atomic, immutable human approval decision.
type Change struct {
	command            Command
	resolution         Resolution
	mutationIDs        MutationIDs
	occurredAt         time.Time
	idempotencyExpires time.Time
}

// NewChange validates complete decision evidence.
func NewChange(params ChangeParams) (Change, error) {
	change := Change{
		command: params.Command, resolution: params.Resolution,
		mutationIDs: params.MutationIDs, occurredAt: params.OccurredAt.UTC(),
		idempotencyExpires: params.IdempotencyExpiresAt.UTC(),
	}
	if !change.IsValid() {
		return Change{}, ErrInvalidApprovalChange
	}
	return change, nil
}

// Command returns the immutable human decision.
func (change Change) Command() Command { return change.command }

// Resolution returns the locked pending request.
func (change Change) Resolution() Resolution { return change.resolution }

// MutationIDs returns retry-stable durable identities.
func (change Change) MutationIDs() MutationIDs { return change.mutationIDs }

// OccurredAt returns the stable approval decision time.
func (change Change) OccurredAt() time.Time { return change.occurredAt }

// IdempotencyExpiresAt returns the exclusive replay-evidence deadline.
func (change Change) IdempotencyExpiresAt() time.Time {
	return change.idempotencyExpires
}

// IsValid reports whether proposal, approver, and acknowledged evidence agree.
func (change Change) IsValid() bool {
	command := change.command
	resolution := change.resolution
	if !command.IsValid() || !resolution.IsValid() || resolution.IsCompleted() ||
		!change.mutationIDs.IsValid() || command.Scope() != resolution.Scope() ||
		command.RequestID() != resolution.RequestID() ||
		command.ExpectedRequestVersion() != resolution.RequestVersion() ||
		command.CandidateSemanticHash() != resolution.Binding().CandidateSemanticHash() ||
		command.ImpactHash() != resolution.Binding().ImpactHash() ||
		change.occurredAt.IsZero() || !command.AccountSession().IsActiveAt(change.occurredAt) ||
		!change.occurredAt.Before(resolution.RequestExpiresAt()) ||
		!change.idempotencyExpires.After(resolution.RequestExpiresAt()) {
		return false
	}
	return command.AccountSession().PrincipalID() != resolution.ProposerPrincipalID() &&
		command.AccountSession().ID() != resolution.ProposerSessionID()
}

// ResultParams contains safe committed independent-human evidence.
type ResultParams struct {
	EvidenceID          EvidenceID
	RequestID           RequestID
	Binding             Binding
	ProposerPrincipalID identity.PrincipalID
	ProposerSessionID   accountsession.ID
	ApproverPrincipalID identity.PrincipalID
	ApproverSessionID   accountsession.ID
	RequestVersion      int64
	EvidenceVersion     int64
	ApprovedAt          time.Time
	ExpiresAt           time.Time
}

// Result is immutable evidence eligible for one atomic publication.
type Result struct {
	evidenceID          EvidenceID
	requestID           RequestID
	binding             Binding
	proposerPrincipalID identity.PrincipalID
	proposerSessionID   accountsession.ID
	approverPrincipalID identity.PrincipalID
	approverSessionID   accountsession.ID
	requestVersion      int64
	evidenceVersion     int64
	approvedAt          time.Time
	expiresAt           time.Time
}

// NewResult validates committed approval evidence.
func NewResult(params ResultParams) (Result, error) {
	result := Result{
		evidenceID: params.EvidenceID, requestID: params.RequestID,
		binding: params.Binding, proposerPrincipalID: params.ProposerPrincipalID,
		proposerSessionID:   params.ProposerSessionID,
		approverPrincipalID: params.ApproverPrincipalID,
		approverSessionID:   params.ApproverSessionID,
		requestVersion:      params.RequestVersion, evidenceVersion: params.EvidenceVersion,
		approvedAt: params.ApprovedAt.UTC(), expiresAt: params.ExpiresAt.UTC(),
	}
	if !result.IsValid() {
		return Result{}, ErrInvalidApprovalResult
	}
	return result, nil
}

// EvidenceID returns the immutable approval artifact identity.
func (result Result) EvidenceID() EvidenceID { return result.evidenceID }

// RequestID returns the approved proposal identity.
func (result Result) RequestID() RequestID { return result.requestID }

// Binding returns exact candidate, vector, and impact evidence.
func (result Result) Binding() Binding { return result.binding }

// Scope returns the exact Network boundary.
func (result Result) Scope() network.Scope { return result.binding.Scope() }

// ProposerPrincipalID returns the authenticated proposing human.
func (result Result) ProposerPrincipalID() identity.PrincipalID {
	return result.proposerPrincipalID
}

// ProposerSessionID returns the proposing Account Session.
func (result Result) ProposerSessionID() accountsession.ID {
	return result.proposerSessionID
}

// ApproverPrincipalID returns the distinct authenticated approving human.
func (result Result) ApproverPrincipalID() identity.PrincipalID {
	return result.approverPrincipalID
}

// ApproverSessionID returns the distinct approving Account Session.
func (result Result) ApproverSessionID() accountsession.ID {
	return result.approverSessionID
}

// RequestVersion returns the approved-request CAS version.
func (result Result) RequestVersion() int64 { return result.requestVersion }

// EvidenceVersion returns the immutable approval-artifact version.
func (result Result) EvidenceVersion() int64 { return result.evidenceVersion }

// State returns the durable lifecycle state.
func (Result) State() State { return StateApproved }

// ApprovedAt returns the committed human-decision time.
func (result Result) ApprovedAt() time.Time { return result.approvedAt }

// ExpiresAt returns the exclusive publication deadline inherited from the request.
func (result Result) ExpiresAt() time.Time { return result.expiresAt }

// Equal reports exact committed approval equality.
func (result Result) Equal(other Result) bool {
	return result.IsValid() && other.IsValid() && result.evidenceID == other.evidenceID &&
		result.requestID == other.requestID && result.binding.Equal(other.binding) &&
		result.proposerPrincipalID == other.proposerPrincipalID &&
		result.proposerSessionID == other.proposerSessionID &&
		result.approverPrincipalID == other.approverPrincipalID &&
		result.approverSessionID == other.approverSessionID &&
		result.requestVersion == other.requestVersion &&
		result.evidenceVersion == other.evidenceVersion &&
		result.approvedAt.Equal(other.approvedAt) && result.expiresAt.Equal(other.expiresAt)
}

// IsValid reports whether committed approval evidence is complete and independent.
func (result Result) IsValid() bool {
	return result.evidenceID.IsValid() && result.requestID.IsValid() && result.binding.IsValid() &&
		result.proposerPrincipalID.IsValid() && result.proposerSessionID.IsValid() &&
		result.approverPrincipalID.IsValid() && result.approverSessionID.IsValid() &&
		result.proposerPrincipalID != result.approverPrincipalID &&
		result.proposerSessionID != result.approverSessionID &&
		result.requestVersion == 2 && result.evidenceVersion == 1 &&
		!result.approvedAt.IsZero() && result.approvedAt.Before(result.expiresAt)
}
