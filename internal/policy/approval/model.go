// Package approval owns durable, two-person policy approval workflow semantics.
// It binds a human decision to one compiler-identical Access Graph simulation
// without becoming packet-policy authority itself.
package approval

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	maximumAuditReasonBytes = 512

	// RequestLifetime is the exclusive interval in which a distinct human may
	// approve and publication may consume an unchanged request.
	RequestLifetime = 10 * time.Minute
	// RequiredApprovals is the v1 independent-human quorum.
	RequiredApprovals = 1
)

var (
	// ErrInvalidAuditReason reports an absent, malformed, or excessive explanation.
	ErrInvalidAuditReason = errors.New("policy approval: invalid audit reason")
	// ErrInvalidRequestID reports a malformed approval-request UUIDv7.
	ErrInvalidRequestID = errors.New("policy approval: invalid request id")
	// ErrInvalidEvidenceID reports a malformed immutable approval-evidence UUIDv7.
	ErrInvalidEvidenceID = errors.New("policy approval: invalid evidence id")
	// ErrInvalidBinding reports incomplete or causally inconsistent simulation evidence.
	ErrInvalidBinding = errors.New("policy approval: invalid simulation binding")
	// ErrInvalidState reports an unknown approval workflow state.
	ErrInvalidState = errors.New("policy approval: invalid state")
	// ErrForbidden conceals absent Account Session or exact-scope permission authority.
	ErrForbidden = errors.New("policy approval: forbidden")
	// ErrImpactChanged reports that acknowledged simulation evidence no longer matches.
	ErrImpactChanged = errors.New("policy approval: impact changed")
	// ErrCandidateChanged reports that acknowledged compiled semantics no longer match.
	ErrCandidateChanged = errors.New("policy approval: candidate changed")
	// ErrRequestVersionConflict reports a stale approval-request precondition.
	ErrRequestVersionConflict = errors.New("policy approval: stale request version")
	// ErrRequestStateConflict reports an approval request that is no longer pending.
	ErrRequestStateConflict = errors.New("policy approval: request state conflict")
	// ErrRequestExpired reports that the exclusive human-decision deadline elapsed.
	ErrRequestExpired = errors.New("policy approval: request expired")
	// ErrIndependentApproverRequired rejects proposer self-approval.
	ErrIndependentApproverRequired = errors.New("policy approval: independent approver required")
)

// AuditReason is a bounded human explanation for a proposal or decision.
type AuditReason struct{ value string }

// NewAuditReason trims surrounding whitespace and validates an explicit reason.
func NewAuditReason(value string) (AuditReason, error) {
	value = strings.TrimSpace(value)
	reason := AuditReason{value: value}
	if !reason.IsValid() {
		return AuditReason{}, ErrInvalidAuditReason
	}
	return reason, nil
}

// String returns the normalized reason.
func (reason AuditReason) String() string { return reason.value }

// IsValid reports whether the normalized reason satisfies its safety bound.
func (reason AuditReason) IsValid() bool {
	return reason.value != "" && reason.value == strings.TrimSpace(reason.value) &&
		len(reason.value) <= maximumAuditReasonBytes && utf8.ValidString(reason.value)
}

// RequestID is a validated policy approval-request UUIDv7.
type RequestID publicid.ID

// ParseRequestID validates a canonical request UUIDv7.
func ParseRequestID(value string) (RequestID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return RequestID{}, ErrInvalidRequestID
	}
	return RequestID(id), nil
}

// String returns the canonical public ID.
func (id RequestID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the request ID is a UUIDv7.
func (id RequestID) IsValid() bool { return publicid.ID(id).IsValid() }

// EvidenceID is a validated immutable approval-decision UUIDv7.
type EvidenceID publicid.ID

// ParseEvidenceID validates a canonical evidence UUIDv7.
func ParseEvidenceID(value string) (EvidenceID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return EvidenceID{}, ErrInvalidEvidenceID
	}
	return EvidenceID(id), nil
}

// String returns the canonical public ID.
func (id EvidenceID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the evidence ID is a UUIDv7.
func (id EvidenceID) IsValid() bool { return publicid.ID(id).IsValid() }

// State identifies the durable request lifecycle.
type State uint8

const (
	// StateUnknown is the invalid zero value.
	StateUnknown State = iota
	// StatePending awaits a distinct authorized human decision.
	StatePending
	// StateApproved has immutable decision evidence and may be consumed once.
	StateApproved
	// StateConsumed was atomically used by one policy publication.
	StateConsumed
)

// String returns the stable persistence and wire spelling.
func (state State) String() string {
	switch state {
	case StatePending:
		return "pending"
	case StateApproved:
		return "approved"
	case StateConsumed:
		return "consumed"
	default:
		return "unknown"
	}
}

// ParseState validates a persistence boundary value.
func ParseState(value string) (State, error) {
	switch value {
	case "pending":
		return StatePending, nil
	case "approved":
		return StateApproved, nil
	case "consumed":
		return StateConsumed, nil
	default:
		return StateUnknown, ErrInvalidState
	}
}

// BindingParams contains the exact compiler-identical evidence a human approves.
type BindingParams struct {
	Scope                 network.Scope
	BaselineVector        accessgraph.RevisionVector
	ProposedVector        accessgraph.RevisionVector
	CandidateSemanticHash publication.SemanticHash
	CompilerFormatVersion int
	ImpactHash            simulation.ImpactHash
}

// Binding is the immutable publication gate contract. Its complete vector
// prevents an approval from surviving changes to any authority input.
type Binding struct {
	scope                 network.Scope
	baselineVector        accessgraph.RevisionVector
	proposedVector        accessgraph.RevisionVector
	candidateSemanticHash publication.SemanticHash
	compilerFormatVersion int
	impactHash            simulation.ImpactHash
}

// NewBinding validates durable simulation evidence loaded at a boundary.
func NewBinding(params BindingParams) (Binding, error) {
	binding := Binding{
		scope: params.Scope, baselineVector: params.BaselineVector,
		proposedVector:        params.ProposedVector,
		candidateSemanticHash: params.CandidateSemanticHash,
		compilerFormatVersion: params.CompilerFormatVersion,
		impactHash:            params.ImpactHash,
	}
	if !binding.IsValid() {
		return Binding{}, ErrInvalidBinding
	}
	return binding, nil
}

// NewBindingFromSimulation derives an approval contract from a verified result.
func NewBindingFromSimulation(result simulation.Result) (Binding, error) {
	if !result.IsValid() {
		return Binding{}, ErrInvalidBinding
	}
	candidate := result.ProposedCandidate()
	return NewBinding(BindingParams{
		Scope:                 result.Baseline().Scope(),
		BaselineVector:        result.Baseline().RevisionVector(),
		ProposedVector:        result.ProposedRevisionVector(),
		CandidateSemanticHash: candidate.SemanticHash(),
		CompilerFormatVersion: candidate.CompilerFormatVersion(),
		ImpactHash:            result.ImpactHash(),
	})
}

// Scope returns the exact Workspace-qualified Network boundary.
func (binding Binding) Scope() network.Scope { return binding.scope }

// BaselineVector returns the complete pre-publication authority vector.
func (binding Binding) BaselineVector() accessgraph.RevisionVector {
	return binding.baselineVector
}

// ProposedVector returns the only accepted post-publication authority vector.
func (binding Binding) ProposedVector() accessgraph.RevisionVector {
	return binding.proposedVector
}

// CandidateSemanticHash returns the exact compiled packet semantics digest.
func (binding Binding) CandidateSemanticHash() publication.SemanticHash {
	return binding.candidateSemanticHash
}

// CompilerFormatVersion returns the exact compiler representation version.
func (binding Binding) CompilerFormatVersion() int {
	return binding.compilerFormatVersion
}

// ImpactHash returns the complete untruncated simulation evidence digest.
func (binding Binding) ImpactHash() simulation.ImpactHash { return binding.impactHash }

// Equal reports exact immutable approval-binding equality.
func (binding Binding) Equal(other Binding) bool {
	return binding.IsValid() && other.IsValid() && binding.scope == other.scope &&
		binding.baselineVector.Equal(other.baselineVector) &&
		binding.proposedVector.Equal(other.proposedVector) &&
		binding.candidateSemanticHash == other.candidateSemanticHash &&
		binding.compilerFormatVersion == other.compilerFormatVersion &&
		binding.impactHash == other.impactHash
}

// IsValid reports whether the evidence represents exactly one policy advance.
func (binding Binding) IsValid() bool {
	if !binding.scope.IsValid() || !binding.baselineVector.IsValid() ||
		!binding.proposedVector.IsValid() || !binding.candidateSemanticHash.IsValid() ||
		binding.compilerFormatVersion <= 0 ||
		binding.compilerFormatVersion > publication.MaximumCompilerFormatVersion ||
		!binding.impactHash.IsValid() {
		return false
	}
	expected, err := binding.baselineVector.NextPolicy()
	return err == nil && expected.Equal(binding.proposedVector)
}
