package approval

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
)

// MaximumCatalogPageSize bounds one approval catalog request.
const MaximumCatalogPageSize = 100

var (
	// ErrInvalidCatalogRequest reports malformed catalog input or dependencies.
	ErrInvalidCatalogRequest = errors.New("policy approval: invalid catalog request")
	// ErrInvalidCatalogResult reports malformed or out-of-scope durable evidence.
	ErrInvalidCatalogResult = errors.New("policy approval: invalid catalog result")
	// ErrRequestNotFound conceals absent and out-of-scope approval requests.
	ErrRequestNotFound = errors.New("policy approval: request not found")
	// ErrCatalogUnavailable reports an unavailable approval read dependency.
	ErrCatalogUnavailable = errors.New("policy approval: catalog unavailable")
)

// DecisionSnapshot is immutable approval evidence attached to an approved request.
type DecisionSnapshot struct {
	evidenceID        EvidenceID
	approverPrincipal identity.PrincipalID
	reason            AuditReason
	evidenceVersion   int64
	approvedAt        time.Time
}

// NewDecisionSnapshot validates immutable approval evidence returned by the catalog.
func NewDecisionSnapshot(
	evidenceID EvidenceID,
	approver identity.PrincipalID,
	reason AuditReason,
	version int64,
	approvedAt time.Time,
) (DecisionSnapshot, error) {
	value := DecisionSnapshot{
		evidenceID: evidenceID, approverPrincipal: approver, reason: reason,
		evidenceVersion: version, approvedAt: approvedAt.UTC(),
	}
	if !value.IsValid() {
		return DecisionSnapshot{}, ErrInvalidCatalogResult
	}
	return value, nil
}

// EvidenceID returns the immutable approval evidence identity.
func (value DecisionSnapshot) EvidenceID() EvidenceID { return value.evidenceID }

// ApproverPrincipalID returns the independent approving Principal.
func (value DecisionSnapshot) ApproverPrincipalID() identity.PrincipalID {
	return value.approverPrincipal
}

// Reason returns the retained approval reason.
func (value DecisionSnapshot) Reason() AuditReason { return value.reason }

// EvidenceVersion returns the immutable evidence version.
func (value DecisionSnapshot) EvidenceVersion() int64 { return value.evidenceVersion }

// ApprovedAt returns the approval decision time.
func (value DecisionSnapshot) ApprovedAt() time.Time { return value.approvedAt }

// IsValid reports whether the decision is complete and immutable.
func (value DecisionSnapshot) IsValid() bool {
	return value.evidenceID.IsValid() && value.approverPrincipal.IsValid() &&
		value.reason.IsValid() && value.evidenceVersion == 1 && !value.approvedAt.IsZero()
}

// ConsumptionSnapshot identifies the release that atomically consumed approval evidence.
type ConsumptionSnapshot struct {
	releaseID      publication.ReleaseID
	policyRevision int64
	consumedAt     time.Time
}

// NewConsumptionSnapshot validates consumed approval evidence.
func NewConsumptionSnapshot(
	releaseID publication.ReleaseID,
	policyRevision int64,
	consumedAt time.Time,
) (ConsumptionSnapshot, error) {
	value := ConsumptionSnapshot{
		releaseID: releaseID, policyRevision: policyRevision, consumedAt: consumedAt.UTC(),
	}
	if !value.IsValid() {
		return ConsumptionSnapshot{}, ErrInvalidCatalogResult
	}
	return value, nil
}

// ReleaseID returns the Policy Release that consumed the evidence.
func (value ConsumptionSnapshot) ReleaseID() publication.ReleaseID { return value.releaseID }

// PolicyRevision returns the consumed Policy revision.
func (value ConsumptionSnapshot) PolicyRevision() int64 { return value.policyRevision }

// ConsumedAt returns the atomic publication-consumption time.
func (value ConsumptionSnapshot) ConsumedAt() time.Time { return value.consumedAt }

// IsValid reports whether the consumption projection is complete.
func (value ConsumptionSnapshot) IsValid() bool {
	return value.releaseID.IsValid() && value.policyRevision > 0 && !value.consumedAt.IsZero()
}

// SnapshotParams contains one safe approval-workflow read projection.
type SnapshotParams struct {
	RequestID           RequestID
	Binding             Binding
	ProposerPrincipalID identity.PrincipalID
	ProposalReason      AuditReason
	State               State
	RequestVersion      int64
	CreatedAt           time.Time
	ExpiresAt           time.Time
	UpdatedAt           time.Time
	Decision            DecisionSnapshot
	Consumption         ConsumptionSnapshot
}

// Snapshot is one exact-scope workflow projection without Account Session identifiers.
type Snapshot struct {
	requestID           RequestID
	binding             Binding
	proposerPrincipalID identity.PrincipalID
	proposalReason      AuditReason
	state               State
	requestVersion      int64
	createdAt           time.Time
	expiresAt           time.Time
	updatedAt           time.Time
	decision            DecisionSnapshot
	consumption         ConsumptionSnapshot
}

// NewSnapshot validates a retained approval request and its optional terminal evidence.
func NewSnapshot(params SnapshotParams) (Snapshot, error) {
	value := Snapshot{
		requestID: params.RequestID, binding: params.Binding,
		proposerPrincipalID: params.ProposerPrincipalID, proposalReason: params.ProposalReason,
		state: params.State, requestVersion: params.RequestVersion,
		createdAt: params.CreatedAt.UTC(), expiresAt: params.ExpiresAt.UTC(),
		updatedAt: params.UpdatedAt.UTC(), decision: params.Decision,
		consumption: params.Consumption,
	}
	if !value.IsValid() {
		return Snapshot{}, ErrInvalidCatalogResult
	}
	return value, nil
}

// RequestID returns the retained approval request identity.
func (value Snapshot) RequestID() RequestID { return value.requestID }

// Binding returns the exact candidate and impact evidence.
func (value Snapshot) Binding() Binding { return value.binding }

// Scope returns the exact Workspace and Network scope.
func (value Snapshot) Scope() network.Scope { return value.binding.Scope() }

// ProposerPrincipalID returns the proposing Principal without Session identity.
func (value Snapshot) ProposerPrincipalID() identity.PrincipalID {
	return value.proposerPrincipalID
}

// ProposalReason returns the retained proposal reason.
func (value Snapshot) ProposalReason() AuditReason { return value.proposalReason }

// State returns the request lifecycle state.
func (value Snapshot) State() State { return value.state }

// RequestVersion returns the lifecycle version used by strong ETags.
func (value Snapshot) RequestVersion() int64 { return value.requestVersion }

// CreatedAt returns the proposal creation time.
func (value Snapshot) CreatedAt() time.Time { return value.createdAt }

// ExpiresAt returns the exclusive approval deadline.
func (value Snapshot) ExpiresAt() time.Time { return value.expiresAt }

// UpdatedAt returns the last lifecycle transition time.
func (value Snapshot) UpdatedAt() time.Time { return value.updatedAt }

// Decision returns immutable decision evidence when the request was approved.
func (value Snapshot) Decision() (DecisionSnapshot, bool) {
	return value.decision, value.decision.IsValid()
}

// Consumption returns publication evidence when the request was consumed.
func (value Snapshot) Consumption() (ConsumptionSnapshot, bool) {
	return value.consumption, value.consumption.IsValid()
}

// IsValid reports whether the complete lifecycle projection is internally consistent.
func (value Snapshot) IsValid() bool {
	if !value.requestID.IsValid() || !value.binding.IsValid() ||
		!value.proposerPrincipalID.IsValid() || !value.proposalReason.IsValid() ||
		value.createdAt.IsZero() || !value.expiresAt.Equal(value.createdAt.Add(RequestLifetime)) ||
		value.updatedAt.Before(value.createdAt) {
		return false
	}
	decisionValid := value.decision.IsValid()
	consumptionValid := value.consumption.IsValid()
	switch value.state {
	case StatePending:
		return value.requestVersion == 1 && !decisionValid && !consumptionValid &&
			value.updatedAt.Equal(value.createdAt)
	case StateApproved:
		return value.requestVersion == 2 && decisionValid && !consumptionValid &&
			value.decision.approverPrincipal != value.proposerPrincipalID &&
			value.decision.approvedAt.Before(value.expiresAt) &&
			value.updatedAt.Equal(value.decision.approvedAt)
	case StateConsumed:
		return value.requestVersion == 3 && decisionValid && consumptionValid &&
			value.decision.approverPrincipal != value.proposerPrincipalID &&
			value.decision.approvedAt.Before(value.expiresAt) &&
			!value.consumption.consumedAt.Before(value.decision.approvedAt) &&
			value.consumption.consumedAt.Before(value.expiresAt) &&
			value.updatedAt.Equal(value.consumption.consumedAt)
	default:
		return false
	}
}

// CatalogReader performs one freshly authorized exact-scope read.
type CatalogReader interface {
	ReadApprovalRequest(context.Context, accountsession.Session, network.Scope, RequestID, time.Time) (Snapshot, error)
	ListApprovalRequests(context.Context, accountsession.Session, network.Scope, State, RequestID, int, time.Time) ([]Snapshot, error)
}

// CatalogPage is one deterministic UUIDv7-keyset page.
type CatalogPage struct {
	Items []Snapshot
	Next  RequestID
}

// CatalogService validates workflow reads around the PostgreSQL authority adapter.
type CatalogService struct {
	reader CatalogReader
	clock  Clock
}

// NewCatalogService constructs a validating approval catalog service.
func NewCatalogService(reader CatalogReader, clock Clock) (*CatalogService, error) {
	if reader == nil || clock == nil {
		return nil, ErrInvalidCatalogRequest
	}
	return &CatalogService{reader: reader, clock: clock}, nil
}

// Get returns one freshly authorized exact-scope approval request.
func (service *CatalogService) Get(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	id RequestID,
) (Snapshot, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return Snapshot{}, ErrInvalidCatalogRequest
	}
	value, err := service.reader.ReadApprovalRequest(ctx, session, scope, id, service.clock.Now().UTC())
	if err != nil {
		return Snapshot{}, err
	}
	if !value.IsValid() || value.Scope() != scope || value.RequestID() != id {
		return Snapshot{}, ErrInvalidCatalogResult
	}
	return value, nil
}

// List returns one validated deterministic keyset page.
func (service *CatalogService) List(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	state State,
	limit int,
	after RequestID,
) (CatalogPage, error) {
	validState := state == StateUnknown || state == StatePending || state == StateApproved || state == StateConsumed
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || !validState || limit < 1 ||
		limit > MaximumCatalogPageSize || (!after.IsValid() && after != (RequestID{})) {
		return CatalogPage{}, ErrInvalidCatalogRequest
	}
	values, err := service.reader.ListApprovalRequests(
		ctx, session, scope, state, after, limit+1, service.clock.Now().UTC(),
	)
	if err != nil {
		return CatalogPage{}, err
	}
	if len(values) > limit+1 {
		return CatalogPage{}, ErrInvalidCatalogResult
	}
	for index, value := range values {
		if !value.IsValid() || value.Scope() != scope ||
			(state != StateUnknown && value.State() != state) ||
			(index > 0 && values[index-1].RequestID().String() >= value.RequestID().String()) ||
			(after.IsValid() && value.RequestID().String() <= after.String()) {
			return CatalogPage{}, ErrInvalidCatalogResult
		}
	}
	page := CatalogPage{Items: values}
	if len(values) > limit {
		page.Items = values[:limit]
		page.Next = page.Items[len(page.Items)-1].RequestID()
	}
	return page, nil
}
