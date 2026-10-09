package publication

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

var (
	// ErrInvalidApprovalEvidenceID reports a malformed approval-evidence UUIDv7.
	ErrInvalidApprovalEvidenceID = errors.New("policy publication: invalid approval evidence id")
	// ErrInvalidApprovalRequestID reports a malformed approval-request UUIDv7.
	ErrInvalidApprovalRequestID = errors.New("policy publication: invalid approval request id")
	// ErrInvalidAuthorityVector reports incomplete publication authority revisions.
	ErrInvalidAuthorityVector = errors.New("policy publication: invalid authority vector")
	// ErrInvalidApprovalGate reports malformed or causally inconsistent approval evidence.
	ErrInvalidApprovalGate = errors.New("policy publication: invalid approval gate")
	// ErrApprovalRequired reports that a management publication omitted durable approval evidence.
	ErrApprovalRequired = errors.New("policy publication: approval evidence required")
	// ErrEdgeBudget reports a release that would give one Device more rule
	// edges than its map can carry.
	ErrEdgeBudget = errors.New("policy publication: a Device would exceed its rule edge limit")
	// ErrApprovalUnavailable conceals stale, expired, consumed, or unauthorized approval evidence.
	ErrApprovalUnavailable = errors.New("policy publication: approval evidence unavailable")
)

// ApprovalEvidenceID identifies one immutable independent-human decision.
type ApprovalEvidenceID publicid.ID

// ParseApprovalEvidenceID validates a canonical approval-evidence UUIDv7.
func ParseApprovalEvidenceID(value string) (ApprovalEvidenceID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ApprovalEvidenceID{}, ErrInvalidApprovalEvidenceID
	}
	return ApprovalEvidenceID(id), nil
}

// String returns the canonical public identity.
func (id ApprovalEvidenceID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the identity is a UUIDv7.
func (id ApprovalEvidenceID) IsValid() bool { return publicid.ID(id).IsValid() }

// ApprovalRequestID identifies the retained request consumed by a publication.
type ApprovalRequestID publicid.ID

// ParseApprovalRequestID validates a canonical approval-request UUIDv7.
func ParseApprovalRequestID(value string) (ApprovalRequestID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ApprovalRequestID{}, ErrInvalidApprovalRequestID
	}
	return ApprovalRequestID(id), nil
}

// String returns the canonical public identity.
func (id ApprovalRequestID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the identity is a UUIDv7.
func (id ApprovalRequestID) IsValid() bool { return publicid.ID(id).IsValid() }

// ApprovalImpactHash is the complete, untruncated simulation evidence digest.
type ApprovalImpactHash [sha256.Size]byte

// NewApprovalImpactHash validates a non-zero impact digest loaded at a boundary.
func NewApprovalImpactHash(value [sha256.Size]byte) (ApprovalImpactHash, error) {
	hash := ApprovalImpactHash(value)
	if !hash.IsValid() {
		return ApprovalImpactHash{}, ErrInvalidApprovalGate
	}
	return hash, nil
}

// Bytes returns a copy of the digest.
func (hash ApprovalImpactHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether the digest is non-zero.
func (hash ApprovalImpactHash) IsValid() bool { return hash != ApprovalImpactHash{} }

// AuthorityVectorParams contains every revision that can affect one Access Graph.
type AuthorityVectorParams struct {
	NetworkRevision     int64
	InventoryRevision   int64
	GroupRevision       int64
	PolicyRevision      int64
	DNSRevision         int64
	RouteRevision       int64
	SharingRevision     int64
	IsolationGeneration int64
}

// AuthorityVector is the complete publication-time compare-and-swap boundary.
type AuthorityVector struct {
	networkRevision     int64
	inventoryRevision   int64
	groupRevision       int64
	policyRevision      int64
	dnsRevision         int64
	routeRevision       int64
	sharingRevision     int64
	isolationGeneration int64
}

// NewAuthorityVector validates one complete authority state.
func NewAuthorityVector(params AuthorityVectorParams) (AuthorityVector, error) {
	vector := AuthorityVector{
		networkRevision: params.NetworkRevision, inventoryRevision: params.InventoryRevision,
		groupRevision: params.GroupRevision, policyRevision: params.PolicyRevision,
		dnsRevision: params.DNSRevision, routeRevision: params.RouteRevision,
		sharingRevision: params.SharingRevision, isolationGeneration: params.IsolationGeneration,
	}
	if !vector.IsValid() {
		return AuthorityVector{}, ErrInvalidAuthorityVector
	}
	return vector, nil
}

// NetworkRevision returns the aggregate client-visible revision.
func (vector AuthorityVector) NetworkRevision() int64 { return vector.networkRevision }

// InventoryRevision returns the Resource collection revision.
func (vector AuthorityVector) InventoryRevision() int64 { return vector.inventoryRevision }

// GroupRevision returns the Resource Group collection revision.
func (vector AuthorityVector) GroupRevision() int64 { return vector.groupRevision }

// PolicyRevision returns the packet-policy authority revision.
func (vector AuthorityVector) PolicyRevision() int64 { return vector.policyRevision }

// DNSRevision returns the DNS authority revision.
func (vector AuthorityVector) DNSRevision() int64 { return vector.dnsRevision }

// RouteRevision returns the route authority revision.
func (vector AuthorityVector) RouteRevision() int64 { return vector.routeRevision }

// SharingRevision returns the sharing authority revision.
func (vector AuthorityVector) SharingRevision() int64 { return vector.sharingRevision }

// IsolationGeneration returns the fail-closed isolation generation.
func (vector AuthorityVector) IsolationGeneration() int64 { return vector.isolationGeneration }

// IsValid reports whether every subsystem revision belongs to the aggregate revision.
func (vector AuthorityVector) IsValid() bool {
	return vector.networkRevision > 0 && vector.inventoryRevision > 0 &&
		vector.groupRevision > 0 && vector.policyRevision > 0 && vector.dnsRevision > 0 &&
		vector.routeRevision > 0 && vector.sharingRevision > 0 &&
		vector.isolationGeneration > 0 && vector.networkRevision >= vector.inventoryRevision &&
		vector.networkRevision >= vector.groupRevision &&
		vector.networkRevision >= vector.policyRevision &&
		vector.networkRevision >= vector.dnsRevision &&
		vector.networkRevision >= vector.routeRevision &&
		vector.networkRevision >= vector.sharingRevision
}

// Equal reports exact complete-vector equality.
func (vector AuthorityVector) Equal(other AuthorityVector) bool {
	return vector.IsValid() && other.IsValid() && vector == other
}

// NextPolicy returns the only valid vector after one packet-policy publication.
func (vector AuthorityVector) NextPolicy() (AuthorityVector, error) {
	const maximumInt64 = int64(^uint64(0) >> 1)
	if !vector.IsValid() || vector.networkRevision == maximumInt64 ||
		vector.policyRevision == maximumInt64 {
		return AuthorityVector{}, ErrInvalidAuthorityVector
	}
	vector.networkRevision++
	vector.policyRevision++
	if !vector.IsValid() {
		return AuthorityVector{}, ErrInvalidAuthorityVector
	}
	return vector, nil
}

// ApprovalGateParams contains immutable decision evidence locked for publication.
type ApprovalGateParams struct {
	Scope                 network.Scope
	RequestID             ApprovalRequestID
	EvidenceID            ApprovalEvidenceID
	BaselineVector        AuthorityVector
	ProposedVector        AuthorityVector
	CandidateSemanticHash SemanticHash
	CompilerFormatVersion int
	ImpactHash            ApprovalImpactHash
	RequestVersion        int64
	EvidenceVersion       int64
	ApprovedAt            time.Time
	ExpiresAt             time.Time
}

// ApprovalGate is the exact, single-use approval proof held under transaction locks.
type ApprovalGate struct {
	scope                 network.Scope
	requestID             ApprovalRequestID
	evidenceID            ApprovalEvidenceID
	baselineVector        AuthorityVector
	proposedVector        AuthorityVector
	candidateSemanticHash SemanticHash
	compilerFormatVersion int
	impactHash            ApprovalImpactHash
	requestVersion        int64
	evidenceVersion       int64
	approvedAt            time.Time
	expiresAt             time.Time
}

// NewApprovalGate validates durable approval evidence loaded under lock.
func NewApprovalGate(params ApprovalGateParams) (ApprovalGate, error) {
	gate := ApprovalGate{
		scope: params.Scope, requestID: params.RequestID, evidenceID: params.EvidenceID,
		baselineVector: params.BaselineVector, proposedVector: params.ProposedVector,
		candidateSemanticHash: params.CandidateSemanticHash,
		compilerFormatVersion: params.CompilerFormatVersion, impactHash: params.ImpactHash,
		requestVersion: params.RequestVersion, evidenceVersion: params.EvidenceVersion,
		approvedAt: params.ApprovedAt.UTC(), expiresAt: params.ExpiresAt.UTC(),
	}
	if !gate.IsValid() {
		return ApprovalGate{}, ErrInvalidApprovalGate
	}
	return gate, nil
}

// Scope returns the exact Workspace-qualified Network boundary.
func (gate ApprovalGate) Scope() network.Scope { return gate.scope }

// RequestID returns the retained request consumed by this publication.
func (gate ApprovalGate) RequestID() ApprovalRequestID { return gate.requestID }

// EvidenceID returns the immutable human-decision identity.
func (gate ApprovalGate) EvidenceID() ApprovalEvidenceID { return gate.evidenceID }

// BaselineVector returns the exact pre-publication authority state.
func (gate ApprovalGate) BaselineVector() AuthorityVector { return gate.baselineVector }

// ProposedVector returns the only accepted post-publication authority state.
func (gate ApprovalGate) ProposedVector() AuthorityVector { return gate.proposedVector }

// CandidateSemanticHash returns the approved compiled packet semantics.
func (gate ApprovalGate) CandidateSemanticHash() SemanticHash { return gate.candidateSemanticHash }

// CompilerFormatVersion returns the approved compiler representation version.
func (gate ApprovalGate) CompilerFormatVersion() int { return gate.compilerFormatVersion }

// ImpactHash returns the approved complete simulation digest.
func (gate ApprovalGate) ImpactHash() ApprovalImpactHash { return gate.impactHash }

// RequestVersion returns the approved request version.
func (gate ApprovalGate) RequestVersion() int64 { return gate.requestVersion }

// EvidenceVersion returns the immutable evidence version.
func (gate ApprovalGate) EvidenceVersion() int64 { return gate.evidenceVersion }

// ApprovedAt returns the independent decision time.
func (gate ApprovalGate) ApprovedAt() time.Time { return gate.approvedAt }

// ExpiresAt returns the exclusive publication deadline.
func (gate ApprovalGate) ExpiresAt() time.Time { return gate.expiresAt }

// IsValid reports whether the proof binds exactly one policy revision advance.
func (gate ApprovalGate) IsValid() bool {
	if !gate.scope.IsValid() || !gate.requestID.IsValid() || !gate.evidenceID.IsValid() ||
		!gate.baselineVector.IsValid() || !gate.proposedVector.IsValid() ||
		!gate.candidateSemanticHash.IsValid() || gate.compilerFormatVersion <= 0 ||
		gate.compilerFormatVersion > MaximumCompilerFormatVersion || !gate.impactHash.IsValid() ||
		gate.requestVersion != 2 || gate.evidenceVersion != 1 || gate.approvedAt.IsZero() ||
		!gate.expiresAt.After(gate.approvedAt) {
		return false
	}
	expected, err := gate.baselineVector.NextPolicy()
	return err == nil && expected.Equal(gate.proposedVector)
}
