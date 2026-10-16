package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	approval "meshtransit.net/core/internal/domain/policy/approval"
	"meshtransit.net/core/internal/domain/policy/publication"
)

var _ approval.CatalogReader = (*PolicyApprovalStore)(nil)

// ReadApprovalRequest returns one freshly authorized exact-scope workflow projection.
func (store *PolicyApprovalStore) ReadApprovalRequest(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	id approval.RequestID,
) (_ approval.Snapshot, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationPolicyApprovalCatalogRead, startedAt, resultErr) }()
	if ctx == nil || store == nil || !session.IsValid() || !scope.IsValid() ||
		!id.IsValid() {
		return approval.Snapshot{}, approval.ErrInvalidCatalogRequest
	}
	// Fresh permission resolution takes share locks on mutable authority rows,
	// so this read projection needs a read-write transaction even though the
	// catalog itself performs no mutation.
	database, evaluatedAt, err := store.begin(ctx, scope)
	if err != nil {
		return approval.Snapshot{}, errors.Join(approval.ErrCatalogUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, catalogRollback(database))
		}
	}()
	if err := authorizePolicyApprovalCatalog(ctx, database, session, scope, evaluatedAt); err != nil {
		return approval.Snapshot{}, err
	}
	var encoded string
	err = database.QueryRow(ctx, readPolicyApprovalCatalogSQL, id.String()).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) || encoded == "" {
		return approval.Snapshot{}, approval.ErrRequestNotFound
	}
	if err != nil {
		return approval.Snapshot{}, errors.Join(
			approval.ErrCatalogUnavailable,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	var record policyApprovalCatalogRecord
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		return approval.Snapshot{}, approval.ErrInvalidCatalogResult
	}
	value, err := record.snapshot(scope)
	if err != nil || value.RequestID() != id {
		return approval.Snapshot{}, approval.ErrInvalidCatalogResult
	}
	if err := database.Commit(ctx); err != nil {
		return approval.Snapshot{}, errors.Join(
			approval.ErrCatalogUnavailable,
			classifyPolicyApprovalCommitError(ctx, err),
		)
	}
	closed = true
	return value, nil
}

// ListApprovalRequests returns one freshly authorized deterministic keyset page.
func (store *PolicyApprovalStore) ListApprovalRequests(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	state approval.State,
	after approval.RequestID,
	limit int,
) (_ []approval.Snapshot, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationPolicyApprovalCatalogList, startedAt, resultErr) }()
	validState := state == approval.StateUnknown || state == approval.StatePending ||
		state == approval.StateApproved || state == approval.StateConsumed
	if ctx == nil || store == nil || !session.IsValid() || !scope.IsValid() ||
		!validState || limit < 1 || limit > approval.MaximumCatalogPageSize+1 ||
		(!after.IsValid() && after != (approval.RequestID{})) {
		return nil, approval.ErrInvalidCatalogRequest
	}
	// The permission resolver fences mutable authority with share locks and
	// therefore cannot run inside a PostgreSQL read-only transaction.
	database, evaluatedAt, err := store.begin(ctx, scope)
	if err != nil {
		return nil, errors.Join(approval.ErrCatalogUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, catalogRollback(database))
		}
	}()
	if err := authorizePolicyApprovalCatalog(ctx, database, session, scope, evaluatedAt); err != nil {
		return nil, err
	}
	var afterValue any
	if after.IsValid() {
		afterValue = after.String()
	}
	var stateValue any
	if state != approval.StateUnknown {
		stateValue = state.String()
	}
	var encoded string
	if err := database.QueryRow(
		ctx, listPolicyApprovalCatalogSQL, afterValue, stateValue, limit,
	).Scan(&encoded); err != nil {
		return nil, errors.Join(
			approval.ErrCatalogUnavailable,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	var records []policyApprovalCatalogRecord
	if err := json.Unmarshal([]byte(encoded), &records); err != nil {
		return nil, approval.ErrInvalidCatalogResult
	}
	values := make([]approval.Snapshot, len(records))
	for index, record := range records {
		value, err := record.snapshot(scope)
		if err != nil {
			return nil, approval.ErrInvalidCatalogResult
		}
		values[index] = value
	}
	if err := database.Commit(ctx); err != nil {
		return nil, errors.Join(
			approval.ErrCatalogUnavailable,
			classifyPolicyApprovalCommitError(ctx, err),
		)
	}
	closed = true
	return values, nil
}

func authorizePolicyApprovalCatalog(
	ctx context.Context,
	database policyApprovalDatabaseTransaction,
	session accountsession.Session,
	scope network.Scope,
	evaluatedAt time.Time,
) error {
	var bindingID, roleID string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var ownerGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := database.QueryRow(
		ctx,
		authorizePolicyApprovalSQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
		string(authorization.PermissionPolicyApprove),
		evaluatedAt,
	).Scan(
		&bindingID,
		&roleID,
		&scopeGeneration,
		&membershipGeneration,
		&bindingGeneration,
		&roleGeneration,
		&hasExpiry,
		&expiresAt,
		&ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.ErrForbidden
	}
	if err != nil {
		return errors.Join(approval.ErrCatalogUnavailable, classifyPolicyApprovalDatabaseError(ctx, err))
	}
	binding, role, authorityErr := parseNetworkPermissionAuthority(bindingID, roleID, ownerGeneration)
	if authorityErr != nil || scopeGeneration <= 0 || membershipGeneration <= 0 ||
		!validNetworkPermissionAuthority(binding, role, bindingGeneration, roleGeneration, ownerGeneration) ||
		(hasExpiry && !expiresAt.After(evaluatedAt)) {
		return approval.ErrForbidden
	}
	return nil
}

func catalogRollback(database policyApprovalDatabaseTransaction) error {
	if err := rollbackPolicyApprovalSetup(database); err != nil {
		return errors.Join(approval.ErrCatalogUnavailable, err)
	}
	return nil
}

type policyApprovalCatalogRecord struct {
	RequestID              string     `json:"request_id"`
	ProposerPrincipalID    string     `json:"proposer_principal_id"`
	ProposalReason         string     `json:"proposal_reason"`
	State                  string     `json:"state"`
	RequestVersion         int64      `json:"request_version"`
	Baseline               [8]int64   `json:"baseline"`
	Proposed               [8]int64   `json:"proposed"`
	CandidateSemanticHash  string     `json:"candidate_semantic_hash"`
	CompilerFormatVersion  int        `json:"compiler_format_version"`
	ImpactHash             string     `json:"impact_hash"`
	CreatedAt              time.Time  `json:"created_at"`
	ExpiresAt              time.Time  `json:"expires_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	EvidenceID             *string    `json:"evidence_id"`
	ApproverPrincipalID    *string    `json:"approver_principal_id"`
	DecisionReason         *string    `json:"decision_reason"`
	EvidenceVersion        *int64     `json:"evidence_version"`
	ApprovedAt             *time.Time `json:"approved_at"`
	ReleaseID              *string    `json:"release_id"`
	ConsumedPolicyRevision *int64     `json:"consumed_policy_revision"`
	ConsumedAt             *time.Time `json:"consumed_at"`
}

func (record policyApprovalCatalogRecord) snapshot(scope network.Scope) (approval.Snapshot, error) {
	requestID, err := approval.ParseRequestID(record.RequestID)
	if err != nil {
		return approval.Snapshot{}, err
	}
	proposer, err := identity.ParsePrincipalID(record.ProposerPrincipalID)
	if err != nil {
		return approval.Snapshot{}, err
	}
	reason, err := approval.NewAuditReason(record.ProposalReason)
	if err != nil {
		return approval.Snapshot{}, err
	}
	state, err := approval.ParseState(record.State)
	if err != nil {
		return approval.Snapshot{}, err
	}
	baseline, err := catalogApprovalVector(record.Baseline)
	if err != nil {
		return approval.Snapshot{}, err
	}
	proposed, err := catalogApprovalVector(record.Proposed)
	if err != nil {
		return approval.Snapshot{}, err
	}
	candidate, err := catalogApprovalSemanticHash(record.CandidateSemanticHash)
	if err != nil {
		return approval.Snapshot{}, err
	}
	impact, err := catalogApprovalImpactHash(record.ImpactHash)
	if err != nil {
		return approval.Snapshot{}, err
	}
	binding, err := approval.NewBinding(approval.BindingParams{
		Scope: scope, BaselineVector: baseline, ProposedVector: proposed,
		CandidateSemanticHash: candidate, CompilerFormatVersion: record.CompilerFormatVersion,
		ImpactHash: impact,
	})
	if err != nil {
		return approval.Snapshot{}, err
	}
	decision, err := record.decision()
	if err != nil {
		return approval.Snapshot{}, err
	}
	consumption, err := record.consumption()
	if err != nil {
		return approval.Snapshot{}, err
	}
	return approval.NewSnapshot(approval.SnapshotParams{
		RequestID: requestID, Binding: binding, ProposerPrincipalID: proposer,
		ProposalReason: reason, State: state, RequestVersion: record.RequestVersion,
		CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt, UpdatedAt: record.UpdatedAt,
		Decision: decision, Consumption: consumption,
	})
}

func (record policyApprovalCatalogRecord) decision() (approval.DecisionSnapshot, error) {
	values := []bool{
		record.EvidenceID != nil, record.ApproverPrincipalID != nil,
		record.DecisionReason != nil, record.EvidenceVersion != nil, record.ApprovedAt != nil,
	}
	if !values[0] && !values[1] && !values[2] && !values[3] && !values[4] {
		return approval.DecisionSnapshot{}, nil
	}
	if !values[0] || !values[1] || !values[2] || !values[3] || !values[4] {
		return approval.DecisionSnapshot{}, approval.ErrInvalidCatalogResult
	}
	evidenceID, err := approval.ParseEvidenceID(*record.EvidenceID)
	if err != nil {
		return approval.DecisionSnapshot{}, err
	}
	approver, err := identity.ParsePrincipalID(*record.ApproverPrincipalID)
	if err != nil {
		return approval.DecisionSnapshot{}, err
	}
	reason, err := approval.NewAuditReason(*record.DecisionReason)
	if err != nil {
		return approval.DecisionSnapshot{}, err
	}
	return approval.NewDecisionSnapshot(evidenceID, approver, reason, *record.EvidenceVersion, *record.ApprovedAt)
}

func (record policyApprovalCatalogRecord) consumption() (approval.ConsumptionSnapshot, error) {
	values := []bool{
		record.ReleaseID != nil, record.ConsumedPolicyRevision != nil, record.ConsumedAt != nil,
	}
	if !values[0] && !values[1] && !values[2] {
		return approval.ConsumptionSnapshot{}, nil
	}
	if !values[0] || !values[1] || !values[2] {
		return approval.ConsumptionSnapshot{}, approval.ErrInvalidCatalogResult
	}
	releaseID, err := publication.ParseReleaseID(*record.ReleaseID)
	if err != nil {
		return approval.ConsumptionSnapshot{}, err
	}
	return approval.NewConsumptionSnapshot(releaseID, *record.ConsumedPolicyRevision, *record.ConsumedAt)
}

func catalogApprovalVector(values [8]int64) (accessgraph.RevisionVector, error) {
	return accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: values[0], InventoryRevision: values[1],
		GroupRevision: values[2], PolicyRevision: values[3], DNSRevision: values[4],
		RouteRevision: values[5], SharingRevision: values[6], IsolationGeneration: values[7],
	})
}

func catalogApprovalSemanticHash(value string) (publication.SemanticHash, error) {
	digest, err := catalogApprovalDigest(value)
	if err != nil {
		return publication.SemanticHash{}, err
	}
	return publication.NewSemanticHash(digest)
}

func catalogApprovalImpactHash(value string) (simulation.ImpactHash, error) {
	digest, err := catalogApprovalDigest(value)
	if err != nil {
		return simulation.ImpactHash{}, err
	}
	return simulation.NewImpactHash(digest)
}

func catalogApprovalDigest(value string) ([sha256.Size]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return [sha256.Size]byte{}, approval.ErrInvalidCatalogResult
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	if digest == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, approval.ErrInvalidCatalogResult
	}
	return digest, nil
}
