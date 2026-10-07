package publication

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
)

const maximumAuditReasonBytes = 512

var (
	// ErrInvalidAuditReason reports an absent, malformed, or excessive audit reason.
	ErrInvalidAuditReason = errors.New("policy publication: invalid audit reason")
	// ErrInvalidCommand reports an incomplete or inconsistent publication request.
	ErrInvalidCommand = errors.New("policy publication: invalid command")
	// ErrInvalidResolution reports inconsistent authoritative state returned under lock.
	ErrInvalidResolution = errors.New("policy publication: invalid resolution")
	// ErrInvalidChange reports an incomplete atomic publication decision.
	ErrInvalidChange = errors.New("policy publication: invalid change")
	// ErrInvalidResult reports an inconsistent committed publication outcome.
	ErrInvalidResult = errors.New("policy publication: invalid result")
	// ErrConflict reports that active policy changed after the caller compiled its candidate.
	ErrConflict = errors.New("policy publication: stale base revision")
	// ErrForbidden hides which Account Session or policy.publish authority check failed.
	ErrForbidden = errors.New("policy publication: forbidden")
)

// AuditReason is a bounded human explanation for one authority change.
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

// IsValid reports whether the normalized reason satisfies its safety bound.
func (reason AuditReason) IsValid() bool {
	return reason.value != "" && reason.value == strings.TrimSpace(reason.value) &&
		len(reason.value) <= maximumAuditReasonBytes && utf8.ValidString(reason.value)
}

// CommandParams contains a fully compiled candidate and its activation authority.
type CommandParams struct {
	Candidate          Candidate
	BasePolicyRevision int64
	ActorPrincipalID   identity.PrincipalID
	AuditReason        AuditReason
}

// ManagementCommandParams contains one SSO-authenticated policy publication request.
type ManagementCommandParams struct {
	Candidate          Candidate
	BasePolicyRevision int64
	AccountSession     accountsession.Session
	ApprovalEvidenceID ApprovalEvidenceID
	AuditReason        AuditReason
}

// Command is a server-scoped request to activate one immutable compiled release.
type Command struct {
	candidate          Candidate
	basePolicyRevision int64
	actorPrincipalID   identity.PrincipalID
	accountSession     accountsession.Session
	approvalEvidenceID ApprovalEvidenceID
	auditReason        AuditReason
}

// NewCommand validates a publication request before any transaction starts.
func NewCommand(params CommandParams) (Command, error) {
	command := Command{
		candidate:          params.Candidate,
		basePolicyRevision: params.BasePolicyRevision,
		actorPrincipalID:   params.ActorPrincipalID,
		auditReason:        params.AuditReason,
	}
	if !command.IsValid() {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

// NewManagementCommand binds publication authority to one authenticated Account Session.
func NewManagementCommand(params ManagementCommandParams) (Command, error) {
	command := Command{
		candidate:          params.Candidate,
		basePolicyRevision: params.BasePolicyRevision,
		actorPrincipalID:   params.AccountSession.PrincipalID(),
		accountSession:     params.AccountSession,
		approvalEvidenceID: params.ApprovalEvidenceID,
		auditReason:        params.AuditReason,
	}
	if !command.IsValid() || !command.HasAccountSession() {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

// NewApprovedManagementCommand requires one immutable approval Evidence identity.
func NewApprovedManagementCommand(params ManagementCommandParams) (Command, error) {
	command, err := NewManagementCommand(params)
	if err != nil || !command.HasApprovalEvidence() {
		return Command{}, ErrInvalidCommand
	}
	return command, nil
}

// Candidate returns the immutable compiled artifact.
func (command Command) Candidate() Candidate { return command.candidate }

// BasePolicyRevision returns the CAS revision used to compile this candidate.
func (command Command) BasePolicyRevision() int64 { return command.basePolicyRevision }

// ActorPrincipalID returns the authorized human or service principal.
func (command Command) ActorPrincipalID() identity.PrincipalID { return command.actorPrincipalID }

// AccountSession returns the SSO authority bound to a management command.
func (command Command) AccountSession() accountsession.Session { return command.accountSession }

// HasAccountSession reports whether publication must prove live management authority.
func (command Command) HasAccountSession() bool { return command.accountSession.IsValid() }

// ApprovalEvidenceID returns the immutable decision selected for single-use consumption.
func (command Command) ApprovalEvidenceID() ApprovalEvidenceID { return command.approvalEvidenceID }

// HasApprovalEvidence reports whether publication must enforce the durable approval gate.
func (command Command) HasApprovalEvidence() bool { return command.approvalEvidenceID.IsValid() }

// AuditReason returns the explicit normalized publication reason.
func (command Command) AuditReason() AuditReason { return command.auditReason }

// IsValid reports whether the candidate is exactly the successor of its CAS base.
func (command Command) IsValid() bool {
	if !command.candidate.IsValid() || command.basePolicyRevision <= 0 ||
		command.basePolicyRevision >= int64(^uint64(0)>>1) ||
		command.candidate.Snapshot().Revision() != command.basePolicyRevision+1 ||
		!command.actorPrincipalID.IsValid() || !command.auditReason.IsValid() {
		return false
	}
	if command.approvalEvidenceID != (ApprovalEvidenceID{}) &&
		!command.approvalEvidenceID.IsValid() {
		return false
	}
	if !command.accountSession.IsValid() {
		return !command.approvalEvidenceID.IsValid()
	}
	return command.accountSession.PrincipalID() == command.actorPrincipalID
}

// ResolutionParams contains active authority read with required publication locks.
type ResolutionParams struct {
	Scope              network.Scope
	AuthorityVector    AuthorityVector
	ActiveReleaseID    ReleaseID
	ActiveSemanticHash SemanticHash
	ApprovalGate       ApprovalGate
}

// Resolution is active policy authority observed under the transaction locks.
type Resolution struct {
	scope              network.Scope
	authorityVector    AuthorityVector
	activeReleaseID    ReleaseID
	activeSemanticHash SemanticHash
	approvalGate       ApprovalGate
}

// NewResolution validates locked publication authority.
func NewResolution(params ResolutionParams) (Resolution, error) {
	resolution := Resolution{
		scope:              params.Scope,
		authorityVector:    params.AuthorityVector,
		activeReleaseID:    params.ActiveReleaseID,
		activeSemanticHash: params.ActiveSemanticHash,
		approvalGate:       params.ApprovalGate,
	}
	if !resolution.IsValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// Scope returns the exact locked Network scope.
func (resolution Resolution) Scope() network.Scope { return resolution.scope }

// NetworkRevision returns the current client-visible revision.
func (resolution Resolution) NetworkRevision() int64 {
	return resolution.authorityVector.NetworkRevision()
}

// PolicyRevision returns the current active packet-policy revision.
func (resolution Resolution) PolicyRevision() int64 {
	return resolution.authorityVector.PolicyRevision()
}

// AuthorityVector returns the complete locked Access Graph revision boundary.
func (resolution Resolution) AuthorityVector() AuthorityVector { return resolution.authorityVector }

// ApprovalGate returns the locked approval proof, when this is an approved management publication.
func (resolution Resolution) ApprovalGate() ApprovalGate { return resolution.approvalGate }

// ActiveRelease returns the active release evidence and whether it exists.
func (resolution Resolution) ActiveRelease() (ReleaseID, SemanticHash, bool) {
	found := resolution.activeReleaseID.IsValid() && resolution.activeSemanticHash.IsValid()
	return resolution.activeReleaseID, resolution.activeSemanticHash, found
}

// IsValid reports whether revision and optional bootstrap evidence are consistent.
func (resolution Resolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.authorityVector.IsValid() {
		return false
	}
	hasID := resolution.activeReleaseID.IsValid()
	hasHash := resolution.activeSemanticHash.IsValid()
	if hasID != hasHash {
		return false
	}
	validApprovalGate := resolution.approvalGate == (ApprovalGate{}) ||
		(resolution.approvalGate.IsValid() && resolution.approvalGate.scope == resolution.scope)
	return (resolution.PolicyRevision() == 1 || hasID) && validApprovalGate
}

// ChangeParams contains one complete publication decision for persistence.
type ChangeParams struct {
	Command     Command
	Resolution  Resolution
	MutationIDs MutationIDs
	OccurredAt  time.Time
}

// Change is one validated, replayable atomic Policy Release mutation.
type Change struct {
	command     Command
	resolution  Resolution
	mutationIDs MutationIDs
	occurredAt  time.Time
}

// NewChange validates the CAS decision, stable IDs, and decision time.
func NewChange(params ChangeParams) (Change, error) {
	change := Change{
		command:     params.Command,
		resolution:  params.Resolution,
		mutationIDs: params.MutationIDs,
		occurredAt:  params.OccurredAt.UTC(),
	}
	if !change.IsValid() {
		return Change{}, ErrInvalidChange
	}
	return change, nil
}

// Command returns the immutable publication request.
func (change Change) Command() Command { return change.command }

// Resolution returns the active authority locked for this decision.
func (change Change) Resolution() Resolution { return change.resolution }

// MutationIDs returns the stable durable identities for this change.
func (change Change) MutationIDs() MutationIDs { return change.mutationIDs }

// OccurredAt returns the stable decision time shared across retries.
func (change Change) OccurredAt() time.Time { return change.occurredAt }

// IsValid reports whether all atomic publication facts agree.
func (change Change) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() && change.mutationIDs.IsValid() &&
		change.command.candidate.Snapshot().Scope() == change.resolution.scope &&
		change.command.basePolicyRevision == change.resolution.PolicyRevision() &&
		len(change.mutationIDs.projectionIDs) == change.command.candidate.ProjectionCount() &&
		!change.occurredAt.IsZero() &&
		approvalGateMatchesCommand(change.command, change.resolution, change.occurredAt)
}

func approvalGateMatchesCommand(command Command, resolution Resolution, evaluatedAt time.Time) bool {
	gate := resolution.approvalGate
	if !command.HasApprovalEvidence() {
		return gate == (ApprovalGate{})
	}
	return gate.IsValid() && gate.evidenceID == command.approvalEvidenceID &&
		gate.scope == command.candidate.Snapshot().Scope() &&
		gate.baselineVector.Equal(resolution.authorityVector) &&
		gate.candidateSemanticHash == command.candidate.SemanticHash() &&
		gate.compilerFormatVersion == command.candidate.CompilerFormatVersion() &&
		!evaluatedAt.Before(gate.approvedAt) && gate.expiresAt.After(evaluatedAt)
}

// ResultParams contains a safe committed Policy Release outcome.
type ResultParams struct {
	ReleaseID       ReleaseID
	Scope           network.Scope
	NetworkRevision int64
	PolicyRevision  int64
	SemanticHash    SemanticHash
}

// Result is the safe committed outcome returned by publication and replay.
type Result struct {
	releaseID       ReleaseID
	scope           network.Scope
	networkRevision int64
	policyRevision  int64
	semanticHash    SemanticHash
}

// NewResult validates committed Policy Release authority.
func NewResult(params ResultParams) (Result, error) {
	result := Result{
		releaseID:       params.ReleaseID,
		scope:           params.Scope,
		networkRevision: params.NetworkRevision,
		policyRevision:  params.PolicyRevision,
		semanticHash:    params.SemanticHash,
	}
	if !result.IsValid() {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}

// ReleaseID returns the activated immutable Policy Release identity.
func (result Result) ReleaseID() ReleaseID { return result.releaseID }

// Scope returns the exact committed Network scope.
func (result Result) Scope() network.Scope { return result.scope }

// NetworkRevision returns the committed client-visible revision.
func (result Result) NetworkRevision() int64 { return result.networkRevision }

// PolicyRevision returns the committed packet-policy revision.
func (result Result) PolicyRevision() int64 { return result.policyRevision }

// SemanticHash returns the committed compiled semantics digest.
func (result Result) SemanticHash() SemanticHash { return result.semanticHash }

// IsValid reports whether this is safe committed release evidence.
func (result Result) IsValid() bool {
	return result.releaseID.IsValid() && result.scope.IsValid() &&
		result.networkRevision > 0 && result.policyRevision > 1 &&
		result.networkRevision >= result.policyRevision && result.semanticHash.IsValid()
}
