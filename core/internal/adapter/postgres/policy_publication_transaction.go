package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/network"
	publication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type policyPublicationTransactionState uint8

const (
	policyPublicationTransactionOpen policyPublicationTransactionState = iota
	policyPublicationTransactionResolved
	policyPublicationTransactionApplied
	policyPublicationTransactionClosed
)

type policyPublicationAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type policyPublicationAuthorizationEvidence struct {
	accountSessionID                  publicid.ID
	roleBindingID                     publicid.ID
	roleDefinitionID                  publicid.ID
	scopeAuthorityGeneration          int64
	membershipAuthorityGeneration     int64
	bindingAuthorityGeneration        int64
	roleAuthorityGeneration           int64
	workspaceOwnerAuthorityGeneration int64
}

func (evidence policyPublicationAuthorizationEvidence) isValid() bool {
	return evidence.accountSessionID.IsValid() && evidence.scopeAuthorityGeneration > 0 &&
		evidence.membershipAuthorityGeneration > 0 && validNetworkPermissionAuthority(
		evidence.roleBindingID, evidence.roleDefinitionID,
		evidence.bindingAuthorityGeneration, evidence.roleAuthorityGeneration,
		evidence.workspaceOwnerAuthorityGeneration,
	)
}

type policyPublicationTransaction struct {
	mu sync.Mutex

	database              policyPublicationDatabaseTransaction
	scope                 network.Scope
	metrics               *postgresPoolMetrics
	state                 policyPublicationTransactionState
	resolution            publication.Resolution
	audit                 policyPublicationAuditHead
	authorization         policyPublicationAuthorizationEvidence
	approvalAuthorization policyPublicationAuthorizationEvidence
	requireAccountSession bool
	requireApproval       bool
	// guardrailFindings are audit-mode guardrails this publication breaks.
	guardrailFindings []guardrail.Finding
}

var _ publication.Transaction = (*policyPublicationTransaction)(nil)

func (transaction *policyPublicationTransaction) Resolve(
	ctx context.Context,
	command publication.Command,
	evaluatedAt time.Time,
) (resolution publication.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationResolve, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !command.IsValid() || evaluatedAt.IsZero() {
		return publication.Resolution{}, ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != policyPublicationTransactionOpen ||
		command.Candidate().Snapshot().Scope() != transaction.scope {
		return publication.Resolution{}, ErrPolicyPublicationState
	}
	if transaction.requireAccountSession {
		authorizationEvidence, err := transaction.resolveAuthorization(ctx, command, evaluatedAt)
		if err != nil {
			return publication.Resolution{}, errors.Join(
				ErrResolvePolicyPublication,
				classifyPolicyPublicationDatabaseError(ctx, err),
			)
		}
		transaction.authorization = authorizationEvidence
	}
	if transaction.requireApproval && !command.HasApprovalEvidence() {
		return publication.Resolution{}, errors.Join(
			ErrResolvePolicyPublication,
			publication.ErrApprovalRequired,
		)
	}

	resolution, err := transaction.resolveLocked(ctx, command, evaluatedAt)
	if err != nil {
		return publication.Resolution{}, errors.Join(
			ErrResolvePolicyPublication,
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = policyPublicationTransactionResolved
	return resolution, nil
}

func (transaction *policyPublicationTransaction) resolveAuthorization(
	ctx context.Context,
	command publication.Command,
	evaluatedAt time.Time,
) (policyPublicationAuthorizationEvidence, error) {
	if !command.HasAccountSession() {
		return policyPublicationAuthorizationEvidence{}, publication.ErrForbidden
	}
	session := command.AccountSession()
	var bindingIDValue, roleIDValue string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var ownerGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := transaction.database.QueryRow(
		ctx,
		authorizePolicyPublicationSQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		command.Candidate().Snapshot().Scope().WorkspaceID().String(),
		command.Candidate().Snapshot().Scope().NetworkID().String(),
		string(authorization.PermissionPolicyPublish),
		evaluatedAt,
	).Scan(
		&bindingIDValue,
		&roleIDValue,
		&scopeGeneration,
		&membershipGeneration,
		&bindingGeneration,
		&roleGeneration,
		&hasExpiry,
		&expiresAt,
		&ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return policyPublicationAuthorizationEvidence{}, publication.ErrForbidden
	}
	if err != nil {
		return policyPublicationAuthorizationEvidence{}, fmt.Errorf("authorize policy.publish: %w", err)
	}
	if hasExpiry && !expiresAt.After(evaluatedAt) {
		return policyPublicationAuthorizationEvidence{}, publication.ErrForbidden
	}
	bindingID, roleID, err := parseNetworkPermissionAuthority(bindingIDValue, roleIDValue, ownerGeneration)
	if err != nil {
		return policyPublicationAuthorizationEvidence{}, ErrPolicyPublicationEvidence
	}
	evidence := policyPublicationAuthorizationEvidence{
		accountSessionID:                  publicid.ID(session.ID()),
		roleBindingID:                     bindingID,
		roleDefinitionID:                  roleID,
		scopeAuthorityGeneration:          scopeGeneration,
		membershipAuthorityGeneration:     membershipGeneration,
		bindingAuthorityGeneration:        bindingGeneration,
		roleAuthorityGeneration:           roleGeneration,
		workspaceOwnerAuthorityGeneration: ownerGeneration,
	}
	if !evidence.isValid() {
		return policyPublicationAuthorizationEvidence{}, ErrPolicyPublicationEvidence
	}
	return evidence, nil
}

func (transaction *policyPublicationTransaction) resolveLocked(
	ctx context.Context,
	command publication.Command,
	evaluatedAt time.Time,
) (publication.Resolution, error) {
	var networkRevision, inventoryRevision, groupRevision, policyRevision int64
	var dnsRevision, routeRevision, sharingRevision, isolationGeneration int64
	if err := transaction.database.QueryRow(ctx, lockPolicyPublicationRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
		&groupRevision,
		&policyRevision,
		&dnsRevision,
		&routeRevision,
		&sharingRevision,
		&isolationGeneration,
	); err != nil {
		return publication.Resolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if networkRevision <= 0 || inventoryRevision <= 0 || groupRevision <= 0 || policyRevision <= 0 ||
		dnsRevision <= 0 || routeRevision <= 0 || sharingRevision <= 0 || isolationGeneration <= 0 {
		return publication.Resolution{}, ErrPolicyPublicationEvidence
	}
	authorityVector, err := publication.NewAuthorityVector(publication.AuthorityVectorParams{
		NetworkRevision: networkRevision, InventoryRevision: inventoryRevision,
		GroupRevision: groupRevision, PolicyRevision: policyRevision,
		DNSRevision: dnsRevision, RouteRevision: routeRevision,
		SharingRevision: sharingRevision, IsolationGeneration: isolationGeneration,
	})
	if err != nil {
		return publication.Resolution{}, ErrPolicyPublicationEvidence
	}

	var activeReleaseValue string
	var activePolicyRevision int64
	var activeSemanticHashValue []byte
	err = transaction.database.QueryRow(
		ctx,
		lockActivePolicyReleaseSQL,
	).Scan(&activeReleaseValue, &activePolicyRevision, &activeSemanticHashValue)
	var activeReleaseID publication.ReleaseID
	var activeSemanticHash publication.SemanticHash
	if errors.Is(err, pgx.ErrNoRows) {
		if policyRevision != 1 {
			return publication.Resolution{}, ErrPolicyPublicationEvidence
		}
	} else if err != nil {
		return publication.Resolution{}, fmt.Errorf("lock active Policy Release: %w", err)
	} else {
		activeReleaseID, err = publication.ParseReleaseID(activeReleaseValue)
		if err != nil {
			return publication.Resolution{}, ErrPolicyPublicationEvidence
		}
		activeSemanticHash, err = policyPublicationSemanticHash(activeSemanticHashValue)
		if err != nil || activePolicyRevision != policyRevision {
			return publication.Resolution{}, ErrPolicyPublicationEvidence
		}
	}

	var approvalGate publication.ApprovalGate
	if command.HasApprovalEvidence() {
		approvalGate, err = transaction.resolveApprovalGate(ctx, command, evaluatedAt)
		if err != nil {
			return publication.Resolution{}, err
		}
	}

	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockPolicyPublicationAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return publication.Resolution{}, fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return publication.Resolution{}, ErrPolicyPublicationEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)

	resolution, err := publication.NewResolution(publication.ResolutionParams{
		Scope:              transaction.scope,
		AuthorityVector:    authorityVector,
		ActiveReleaseID:    activeReleaseID,
		ActiveSemanticHash: activeSemanticHash,
		ApprovalGate:       approvalGate,
	})
	if err != nil {
		return publication.Resolution{}, ErrPolicyPublicationEvidence
	}
	return resolution, nil
}

func (transaction *policyPublicationTransaction) Apply(
	ctx context.Context,
	change publication.Change,
) (result publication.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationApply, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !change.IsValid() {
		return publication.Result{}, ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != policyPublicationTransactionResolved ||
		change.Resolution() != transaction.resolution ||
		change.Command().Candidate().Snapshot().Scope() != transaction.scope {
		return publication.Result{}, ErrPolicyPublicationState
	}

	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return publication.Result{}, errors.Join(
			ErrApplyPolicyPublication,
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	transaction.state = policyPublicationTransactionApplied
	return result, nil
}

func (transaction *policyPublicationTransaction) applyLocked(
	ctx context.Context,
	change publication.Change,
) (publication.Result, error) {
	rules, err := encodePolicyPublicationRules(change)
	if err != nil {
		return publication.Result{}, err
	}
	if transaction.guardrailFindings, err = transaction.checkGuardrails(ctx, change); err != nil {
		return publication.Result{}, err
	}
	if err := transaction.database.Exec(
		ctx,
		setPolicyPublicationChangeSQL,
		change.MutationIDs().ChangeID().String(),
	); err != nil {
		return publication.Result{}, fmt.Errorf("set authority change context: %w", err)
	}

	command := change.Command()
	semanticHash := command.Candidate().SemanticHash().Bytes()
	var networkRevision, policyRevision, releaseVersion int64
	publishQuery := publishCompiledPolicySQL
	var scaled bool
	if err := transaction.database.QueryRow(ctx, scaledPolicyPublicationGrantedSQL).Scan(&scaled); err != nil {
		return publication.Result{}, fmt.Errorf("check policy publication function: %w", err)
	}
	if scaled {
		publishQuery = publishScaledCompiledPolicySQL
	}
	if err := transaction.database.QueryRow(
		ctx,
		publishQuery,
		change.MutationIDs().ReleaseID().String(),
		command.BasePolicyRevision(),
		semanticHash[:],
		command.Candidate().CompilerFormatVersion(),
		change.OccurredAt(),
		rules,
	).Scan(&networkRevision, &policyRevision, &releaseVersion); err != nil {
		return publication.Result{}, fmt.Errorf("publish compiled policy: %w", err)
	}
	if networkRevision != transaction.resolution.NetworkRevision()+1 ||
		policyRevision != command.Candidate().Snapshot().Revision() || releaseVersion != 1 {
		return publication.Result{}, ErrPolicyPublicationEvidence
	}
	resourceDestinations := command.Candidate().ResourceDestinations()
	if len(resourceDestinations) > 0 {
		var attachedCount int
		if err := transaction.database.QueryRow(
			ctx,
			attachPolicyResourceDestinationsSQL,
			change.MutationIDs().ReleaseID().String(),
			change.OccurredAt(),
			rules,
		).Scan(&attachedCount); err != nil {
			return publication.Result{}, fmt.Errorf("attach policy Resource destinations: %w", err)
		}
		if attachedCount != len(resourceDestinations) {
			return publication.Result{}, ErrPolicyPublicationEvidence
		}
	}
	resourceGroupDestinations := command.Candidate().ResourceGroupDestinations()
	if len(resourceGroupDestinations) > 0 {
		expectedMembers := 0
		for _, destination := range resourceGroupDestinations {
			expectedMembers += len(destination.Members())
		}
		var attachedCount int
		if err := transaction.database.QueryRow(
			ctx,
			attachPolicyResourceGroupDestinationsSQL,
			change.MutationIDs().ReleaseID().String(),
			change.OccurredAt(),
			rules,
		).Scan(&attachedCount); err != nil {
			return publication.Result{}, fmt.Errorf("attach policy Resource Group destinations: %w", err)
		}
		if attachedCount != expectedMembers {
			return publication.Result{}, ErrPolicyPublicationEvidence
		}
	}
	if groupRules, err := encodePolicyGroupRules(change); err != nil {
		return publication.Result{}, err
	} else if groupRules != nil {
		var attachedCount int
		if err := transaction.database.QueryRow(
			ctx,
			attachPolicyGroupRulesSQL,
			change.MutationIDs().ReleaseID().String(),
			change.OccurredAt(),
			groupRules,
		).Scan(&attachedCount); err != nil {
			return publication.Result{}, fmt.Errorf("attach policy group rules: %w", err)
		}
		if attachedCount != len(command.Candidate().GroupRules()) {
			return publication.Result{}, ErrPolicyPublicationEvidence
		}
	}
	if command.HasApprovalEvidence() {
		impactHash := change.Resolution().ApprovalGate().ImpactHash().Bytes()
		var consumedRequestVersion int64
		if err := transaction.database.QueryRow(
			ctx,
			consumePolicyPublicationApprovalSQL,
			command.ApprovalEvidenceID().String(),
			change.MutationIDs().ReleaseID().String(),
			semanticHash[:],
			command.Candidate().CompilerFormatVersion(),
			impactHash[:],
			change.OccurredAt(),
		).Scan(&consumedRequestVersion); err != nil {
			return publication.Result{}, fmt.Errorf("consume Policy approval evidence: %w", err)
		}
		if consumedRequestVersion != 3 {
			return publication.Result{}, ErrPolicyPublicationEvidence
		}
	}
	if err := transaction.appendPolicyPublicationEvidence(
		ctx,
		change,
		releaseVersion,
		networkRevision,
	); err != nil {
		return publication.Result{}, err
	}
	result, err := publication.NewResult(publication.ResultParams{
		ReleaseID:       change.MutationIDs().ReleaseID(),
		Scope:           transaction.scope,
		NetworkRevision: networkRevision,
		PolicyRevision:  policyRevision,
		SemanticHash:    command.Candidate().SemanticHash(),
	})
	if err != nil {
		return publication.Result{}, ErrPolicyPublicationEvidence
	}
	return result, nil
}

func (transaction *policyPublicationTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationCommit, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != policyPublicationTransactionApplied {
		return ErrPolicyPublicationState
	}
	transaction.state = policyPublicationTransactionClosed
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(
			ErrCommitPolicyPublication,
			classifyPolicyPublicationCommitError(ctx, err),
		)
	}
	return nil
}

func (transaction *policyPublicationTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyPublicationRollback, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrPolicyPublicationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrPolicyPublicationState
	}
	if transaction.state == policyPublicationTransactionClosed {
		return nil
	}
	transaction.state = policyPublicationTransactionClosed
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(
			ErrRollbackPolicyPublication,
			fmt.Errorf("roll back database transaction: %w", err),
		)
	}
	return nil
}

func (transaction *policyPublicationTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction == nil {
		return
	}
	transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
}

func policyPublicationSemanticHash(value []byte) (publication.SemanticHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return publication.SemanticHash{}, ErrPolicyPublicationEvidence
	}
	copy(fixed[:], value)
	hash, err := publication.NewSemanticHash(fixed)
	if err != nil {
		return publication.SemanticHash{}, ErrPolicyPublicationEvidence
	}
	return hash, nil
}

// checkGuardrails evaluates every rule that reaches a shared Device against
// the Workspace's guardrails, under the publication locks, so a guardrail
// added concurrently cannot be missed. Rules between Devices of this Network
// cross no Network and are not affected. An enforced guardrail blocks only
// paths the active release does not already open, returning
// *guardrail.ViolationError: guardrails are not retroactive. Every finding,
// including those on existing paths, comes back for the evidence.
func (transaction *policyPublicationTransaction) checkGuardrails(
	ctx context.Context,
	change publication.Change,
) ([]guardrail.Finding, error) {
	destinations := change.Command().Candidate().ImportedResourceDestinations()
	if len(destinations) == 0 {
		return nil, nil
	}
	var encoded string
	if err := transaction.database.QueryRow(ctx, activeWorkspaceGuardrailsSQL).Scan(&encoded); err != nil {
		return nil, fmt.Errorf("read guardrails: %w", err)
	}
	guardrails, err := decodeActiveGuardrails(encoded)
	if err != nil {
		return nil, fmt.Errorf("read guardrails: %w", err)
	}
	type pathFinding struct {
		finding guardrail.Finding
		path    string
	}
	var raised []pathFinding
	for _, destination := range destinations {
		edge := guardrail.ShareEdge{Provider: destination.Resolution().ProviderScope(), Consumer: transaction.scope}
		path := destination.SourceNodeID().String() + ":" + destination.Resolution().ImportedResourceID().String()
		for _, finding := range guardrail.Evaluate(guardrails, transaction.scope.WorkspaceID(), edge) {
			raised = append(raised, pathFinding{finding: finding, path: path})
		}
	}
	var existing map[string]bool
	for _, item := range raised {
		if item.finding.Mode == guardrail.ModeEnforce {
			if existing, err = transaction.activeImportedPaths(ctx); err != nil {
				return nil, err
			}
			break
		}
	}
	findings := []guardrail.Finding{}
	blocking := []guardrail.Finding{}
	seen, blocked := map[publicid.ID]bool{}, map[publicid.ID]bool{}
	for _, item := range raised {
		if !seen[item.finding.GuardrailID] {
			seen[item.finding.GuardrailID] = true
			findings = append(findings, item.finding)
		}
		if item.finding.Mode == guardrail.ModeEnforce && !existing[item.path] && !blocked[item.finding.GuardrailID] {
			blocked[item.finding.GuardrailID] = true
			blocking = append(blocking, item.finding)
		}
	}
	if len(blocking) > 0 {
		return findings, &guardrail.ViolationError{Findings: blocking}
	}
	if err := transaction.checkProviderGuardrails(ctx, destinations, existing); err != nil {
		return nil, err
	}
	return findings, nil
}

// importedResourceProviderGuardrailsSQL reads the guardrails of each other
// Workspace that provides an Imported Resource of this Network (schema 163).
const importedResourceProviderGuardrailsSQL = `SELECT mesh_ops.imported_resource_provider_guardrails_v1()::TEXT`

type providerGuardrailsDocument struct {
	WorkspaceID string          `json:"workspace_id"`
	Guardrails  json.RawMessage `json:"guardrails"`
}

// checkProviderGuardrails blocks a new path to an Imported Resource that an
// enforced guardrail of its provider's Workspace forbids, with
// *guardrail.CounterpartViolationError, which names nothing of the provider.
// Paths the active release already opens are not blocked: guardrails are not
// retroactive. The provider's findings are never recorded in this Network's
// evidence.
func (transaction *policyPublicationTransaction) checkProviderGuardrails(ctx context.Context,
	destinations []publication.ImportedResourceDestination, existing map[string]bool) error {
	local := transaction.scope.WorkspaceID()
	external := false
	for _, destination := range destinations {
		if destination.Resolution().ProviderScope().WorkspaceID() != local {
			external = true
			break
		}
	}
	if !external {
		return nil
	}
	var encoded string
	if err := transaction.database.QueryRow(ctx, importedResourceProviderGuardrailsSQL).Scan(&encoded); err != nil {
		return fmt.Errorf("read provider guardrails: %w", err)
	}
	var documents []providerGuardrailsDocument
	if err := strictJSON([]byte(encoded), &documents); err != nil || documents == nil {
		return fmt.Errorf("read provider guardrails: %w", guardrail.ErrInvalid)
	}
	providers := make(map[workspace.ID][]guardrail.Guardrail, len(documents))
	for _, document := range documents {
		id, err := workspace.ParseID(document.WorkspaceID)
		if err != nil {
			return fmt.Errorf("read provider guardrails: %w", guardrail.ErrInvalid)
		}
		guardrails, err := decodeActiveGuardrails(string(document.Guardrails))
		if err != nil {
			return fmt.Errorf("read provider guardrails: %w", err)
		}
		providers[id] = guardrails
	}
	for _, destination := range destinations {
		provider := destination.Resolution().ProviderScope()
		if provider.WorkspaceID() == local {
			continue
		}
		// Fail closed: a provider the reader does not know is never assumed
		// to have no guardrail.
		guardrails, known := providers[provider.WorkspaceID()]
		if !known {
			return fmt.Errorf("read provider guardrails: %w", guardrail.ErrInvalid)
		}
		if len(guardrails) == 0 {
			continue
		}
		edge := guardrail.ShareEdge{Provider: provider, Consumer: transaction.scope}
		if len(guardrail.Blocking(guardrail.Evaluate(guardrails, provider.WorkspaceID(), edge))) == 0 {
			continue
		}
		if existing == nil {
			var err error
			if existing, err = transaction.activeImportedPaths(ctx); err != nil {
				return err
			}
		}
		path := destination.SourceNodeID().String() + ":" + destination.Resolution().ImportedResourceID().String()
		if !existing[path] {
			return &guardrail.CounterpartViolationError{}
		}
	}
	return nil
}

// activeImportedPaths reads the source-Device-to-Imported-Resource paths the
// Network's active release already opens.
func (transaction *policyPublicationTransaction) activeImportedPaths(ctx context.Context) (map[string]bool, error) {
	var encoded string
	if err := transaction.database.QueryRow(ctx, activeReleaseImportedPathsSQL).Scan(&encoded); err != nil {
		return nil, fmt.Errorf("read active paths: %w", err)
	}
	var paths []string
	if err := strictJSON([]byte(encoded), &paths); err != nil || paths == nil {
		return nil, fmt.Errorf("read active paths: %w", ErrPolicyPublicationEvidence)
	}
	existing := make(map[string]bool, len(paths))
	for _, path := range paths {
		existing[path] = true
	}
	return existing, nil
}
