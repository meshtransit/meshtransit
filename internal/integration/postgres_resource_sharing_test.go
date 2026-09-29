//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

func assertPostgreSQLResourceSharing(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	store := newIntegrationResourceSharingStore(t, runtimePool)
	service, err := sharing.NewService(store, sharing.SystemClock{})
	if err != nil {
		t.Fatalf("sharing.NewService() error = %v", err)
	}
	session := managementRBACAccountSessionFixture(t)
	providerScope := resourceAuthorityScope(t, 103, 203)
	consumerScope := resourceAuthorityScope(t, 103, 204)
	resourceID := activeIntegrationResourceID(ctx, t, admin, 103, 203)
	maximumTraffic := integrationSharingTraffic(t)
	reason, err := sharing.NewAuditReason("share production Resource with an exact consumer Network")
	if err != nil {
		t.Fatalf("sharing.NewAuditReason() error = %v", err)
	}
	createCommand, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: time.Now().UTC().Add(time.Hour), AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 111),
	})
	if err != nil {
		t.Fatalf("sharing.NewCreateOffer() error = %v", err)
	}
	created, err := service.CreateOffer(ctx, createCommand)
	if err != nil {
		t.Fatalf("Resource Sharing CreateOffer() error = %v", err)
	}
	createdOffer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken || !token.IsValid() ||
		createdOffer.Offer().State() != sharing.OfferStateOffered ||
		createdOffer.Resource().ResourceID() != resourceID {
		t.Fatalf("Resource Sharing create result = %+v", created)
	}
	replayedCreate, err := service.CreateOffer(ctx, createCommand)
	if err != nil {
		t.Fatalf("Resource Sharing CreateOffer() replay error = %v", err)
	}
	replayedToken, replayedHasToken := replayedCreate.Token()
	if !replayedHasToken || replayedToken != token ||
		replayedCreate.ProviderSharingRevision() != created.ProviderSharingRevision() ||
		replayedCreate.ConsumerSharingRevision() != created.ConsumerSharingRevision() {
		t.Fatalf("Resource Sharing create replay = %+v", replayedCreate)
	}
	outgoing, err := service.ListOffers(
		ctx, session, providerScope, sharing.DirectionOutgoing,
		sharing.OfferStateOffered, 10, sharing.EmptyPageCursor(),
	)
	if err != nil || len(outgoing.Items()) != 1 ||
		outgoing.Items()[0].Offer().ID() != createdOffer.Offer().ID() {
		t.Fatalf("Resource Sharing outgoing page = %+v, error = %v", outgoing, err)
	}
	incoming, err := service.ListOffers(
		ctx, session, consumerScope, sharing.DirectionIncoming,
		sharing.OfferStateOffered, 10, sharing.EmptyPageCursor(),
	)
	if err != nil || len(incoming.Items()) != 1 ||
		incoming.Items()[0].Offer().ID() != createdOffer.Offer().ID() {
		t.Fatalf("Resource Sharing incoming page = %+v, error = %v", incoming, err)
	}
	importedName, err := resource.ParseDisplayName("Imported production Resource")
	if err != nil {
		t.Fatalf("resource.ParseDisplayName() error = %v", err)
	}
	acceptCommand, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: createdOffer.Offer().ID(), ExpectedOfferVersion: 1,
		Token: token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 112),
	})
	if err != nil {
		t.Fatalf("sharing.NewDecideOffer() error = %v", err)
	}
	accepted, err := service.DecideOffer(ctx, acceptCommand)
	if err != nil {
		t.Fatalf("Resource Sharing DecideOffer() error = %v", err)
	}
	acceptedOffer, hasOffer := accepted.Offer()
	contract, hasContract := accepted.Contract()
	if !hasOffer || !hasContract || acceptedOffer.Offer().State() != sharing.OfferStateAccepted ||
		contract.State() != sharing.ContractStateActivating ||
		contract.ProviderScope() != providerScope || contract.ConsumerScope() != consumerScope {
		t.Fatalf("Resource Sharing accept result = %+v", accepted)
	}
	replayedAccept, err := service.DecideOffer(ctx, acceptCommand)
	if err != nil {
		t.Fatalf("Resource Sharing DecideOffer() replay error = %v", err)
	}
	replayedContract, replayedHasContract := replayedAccept.Contract()
	if !replayedHasContract || replayedContract.ID() != contract.ID() ||
		replayedAccept.ConsumerSharingRevision() != accepted.ConsumerSharingRevision() {
		t.Fatalf("Resource Sharing accept replay = %+v", replayedAccept)
	}
	activateCommand, err := sharing.NewActivateContract(sharing.ActivateContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: contract.ID(), ExpectedContractVersion: contract.Version(),
		AccountSession: session, Reason: reason, Idempotency: resourceAuthorityProof(t, 113),
	})
	if err != nil {
		t.Fatalf("sharing.NewActivateContract() error = %v", err)
	}
	activated, err := service.ActivateContract(ctx, activateCommand)
	if err != nil {
		t.Fatalf("Resource Sharing ActivateContract() error = %v", err)
	}
	activeContract, hasContract := activated.Contract()
	if !hasContract || activeContract.State() != sharing.ContractStateActive ||
		activeContract.Version() != contract.Version()+1 || activated.ImportedResourceVersion() != 2 {
		t.Fatalf("Resource Sharing activate result = %+v", activated)
	}
	replayedActivation, err := service.ActivateContract(ctx, activateCommand)
	if err != nil {
		t.Fatalf("Resource Sharing ActivateContract() replay error = %v", err)
	}
	replayedActiveContract, replayedHasContract := replayedActivation.Contract()
	if !replayedHasContract || replayedActiveContract.ID() != activeContract.ID() ||
		replayedActiveContract.Version() != activeContract.Version() ||
		replayedActivation.ConsumerSharingRevision() != activated.ConsumerSharingRevision() {
		t.Fatalf("Resource Sharing activate replay = %+v", replayedActivation)
	}
	resolved, err := store.ResolveImportedPolicyDestinations(
		ctx,
		session,
		consumerScope,
		[]sharing.ImportedResourceID{activeContract.ImportedResourceID()},
	)
	if err != nil || len(resolved) != 1 ||
		resolved[0].ImportedResourceID() != activeContract.ImportedResourceID() ||
		resolved[0].ImportedResourceVersion() != 2 ||
		resolved[0].Contract().ID() != activeContract.ID() ||
		resolved[0].Contract().State() != sharing.ContractStateActive {
		t.Fatalf("ResolveImportedPolicyDestinations() = %+v, error = %v", resolved, err)
	}
	assertAtomicImportedPolicyPublication(ctx, t, admin, resolved[0])
	revokeCommand, err := sharing.NewRevokeContract(sharing.RevokeContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: activeContract.ID(), ExpectedContractVersion: activeContract.Version(),
		LocalScope: consumerScope, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 114),
	})
	if err != nil {
		t.Fatalf("sharing.NewRevokeContract() error = %v", err)
	}
	revoked, err := service.RevokeContract(ctx, revokeCommand)
	if err != nil {
		t.Fatalf("Resource Sharing RevokeContract() error = %v", err)
	}
	revokedContract, hasContract := revoked.Contract()
	if !hasContract || revokedContract.State() != sharing.ContractStateRevoked ||
		revokedContract.Version() != activeContract.Version()+1 ||
		revoked.ImportedResourceVersion() != 3 {
		t.Fatalf("Resource Sharing revoke result = %+v", revoked)
	}
	if _, err := store.ResolveImportedPolicyDestinations(
		ctx,
		session,
		consumerScope,
		[]sharing.ImportedResourceID{activeContract.ImportedResourceID()},
	); !errors.Is(err, sharing.ErrConflict) {
		t.Fatalf("ResolveImportedPolicyDestinations() after revoke error = %v, want conflict", err)
	}
	readBack, err := service.GetOffer(ctx, session, providerScope, createdOffer.Offer().ID())
	if err != nil || readBack.Offer().State() != sharing.OfferStateAccepted {
		t.Fatalf("Resource Sharing GetOffer() = %+v, error = %v", readBack, err)
	}
	foreignScope := resourceAuthorityScope(t, 102, 202)
	if _, err := service.ListOffers(
		ctx, session, foreignScope, sharing.DirectionOutgoing,
		sharing.OfferStateUnknown, 10, sharing.EmptyPageCursor(),
	); !errors.Is(err, sharing.ErrForbidden) {
		t.Fatalf("cross-Workspace Resource Sharing list error = %v, want forbidden", err)
	}
	assertCommittedResourceSharingEvidence(ctx, t, admin, createdOffer.Offer().ID(), contract.ID())
}

func assertAtomicImportedPolicyPublication(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	destination sharing.PolicyDestination,
) {
	t.Helper()
	const (
		releaseID     = "01890f93-0000-7000-8000-000000000001"
		projectionID  = "01890f93-0000-7000-8000-000000000002"
		ruleID        = "01890f93-0000-7000-8000-000000000003"
		changeID      = "01890f93-0000-7000-8000-000000000004"
		staleChangeID = "01890f93-0000-7000-8000-000000000005"
	)
	var sourceNodeID string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT
FROM mesh.device AS device
WHERE device.workspace_id = 103
  AND device.network_id = 204
  AND device.state = 'active'
  AND pg_catalog.transaction_timestamp() < device.expires_at
ORDER BY device.id
LIMIT 1`).Scan(&sourceNodeID); err != nil {
		t.Fatalf("query active consumer Device: %v", err)
	}
	contract := destination.Contract()
	binding := contract.Resource()
	resourceHash := binding.SemanticHash().Bytes()
	constraintHash := contract.MaximumTraffic().Hash()
	publicationRule := map[string]any{
		"projection_public_id":                        projectionID,
		"access_rule_public_id":                       ruleID,
		"source_node_public_id":                       sourceNodeID,
		"protocol":                                    "tcp",
		"port_range_first":                            []int{443},
		"port_range_last":                             []int{443},
		"destination_imported_resource_public_id":     destination.ImportedResourceID().String(),
		"destination_imported_resource_version":       destination.ImportedResourceVersion(),
		"destination_trust_contract_public_id":        contract.ID().String(),
		"destination_trust_contract_version":          contract.Version(),
		"destination_resource_export_public_id":       contract.ExportID().String(),
		"destination_resource_export_version":         destination.ExportVersion(),
		"destination_provider_workspace_public_id":    destination.ProviderScope().WorkspaceID().String(),
		"destination_provider_network_public_id":      destination.ProviderScope().NetworkID().String(),
		"destination_provider_resource_public_id":     binding.ResourceID().String(),
		"destination_provider_resource_version":       binding.ResourceVersion(),
		"destination_provider_target_generation":      binding.TargetGeneration(),
		"destination_provider_resource_semantic_hash": hex.EncodeToString(resourceHash[:]),
		"destination_provider_inventory_revision":     destination.ProviderInventoryRevision(),
		"destination_provider_sharing_revision":       destination.ProviderSharingRevision(),
		"destination_consumer_sharing_revision":       destination.ConsumerSharingRevision(),
		"destination_provider_authority_generation":   contract.ProviderAuthorityGeneration(),
		"destination_consumer_authority_generation":   contract.ConsumerAuthorityGeneration(),
		"destination_recovery_epoch":                  contract.RecoveryEpoch(),
		"destination_contract_expires_at":             contract.ExpiresAt().UTC().Format(time.RFC3339Nano),
		"destination_constraint_hash":                 hex.EncodeToString(constraintHash[:]),
	}
	payload, err := json.Marshal([]map[string]any{publicationRule})
	if err != nil {
		t.Fatalf("encode Imported Resource publication fixture: %v", err)
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Imported Resource publication transaction: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationScope(ctx, t, transaction, 103, 204)
	setIntegrationChange(ctx, t, transaction, changeID)
	var baseNetworkRevision, basePolicyRevision int64
	if err := transaction.QueryRow(ctx, `SELECT network_revision, policy_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 204`).Scan(
		&baseNetworkRevision, &basePolicyRevision,
	); err != nil {
		t.Fatalf("query Imported Resource publication baseline: %v", err)
	}
	semanticHash := sha256.Sum256(payload)
	var networkRevision, policyRevision, releaseVersion int64
	if err := transaction.QueryRow(ctx, `SELECT network_revision, policy_revision, release_version
FROM mesh_ops.publish_compiled_policy(
	$1::UUID, $2::BIGINT, $3::BYTEA, 4, $4::TIMESTAMPTZ, $5::JSONB
)`, releaseID, basePolicyRevision, semanticHash[:], destination.EvaluatedAt(), payload).Scan(
		&networkRevision, &policyRevision, &releaseVersion,
	); err != nil {
		_ = transaction.Rollback(ctx)
		t.Fatalf("publish Imported Resource policy atomically: %v", err)
	}
	if networkRevision != baseNetworkRevision+1 || policyRevision != basePolicyRevision+1 ||
		releaseVersion != 1 {
		t.Fatalf("Imported Resource publication revisions = %d/%d/%d, base = %d/%d",
			networkRevision, policyRevision, releaseVersion,
			baseNetworkRevision, basePolicyRevision)
	}
	var provenanceCount, localRuleCount int
	if err := transaction.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)
     FROM mesh.compiled_policy_imported_resource_destination AS imported
     JOIN mesh.policy_release AS release ON release.id = imported.policy_release_id
     WHERE release.public_id = $1::UUID),
    (SELECT pg_catalog.count(*)
     FROM mesh.compiled_policy_rule AS rule
     JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
     WHERE release.public_id = $1::UUID)`, releaseID).Scan(
		&provenanceCount, &localRuleCount,
	); err != nil {
		t.Fatalf("query Imported Resource publication evidence: %v", err)
	}
	if provenanceCount != 1 || localRuleCount != 0 {
		t.Fatalf("Imported Resource publication evidence = provenance %d, local rules %d",
			provenanceCount, localRuleCount)
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback Imported Resource publication probe: %v", err)
	}
	var releaseCount int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.policy_release
WHERE public_id = $1::UUID`, releaseID).Scan(&releaseCount); err != nil {
		t.Fatalf("verify Imported Resource publication rollback: %v", err)
	}
	if releaseCount != 0 {
		t.Fatalf("Imported Resource publication probe leaked %d releases", releaseCount)
	}

	publicationRule["destination_provider_inventory_revision"] =
		destination.ProviderInventoryRevision() + 1
	stalePayload, err := json.Marshal([]map[string]any{publicationRule})
	if err != nil {
		t.Fatalf("encode stale Imported Resource publication fixture: %v", err)
	}
	staleHash := sha256.Sum256(stalePayload)
	staleTransaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin stale Imported Resource publication transaction: %v", err)
	}
	setIntegrationScope(ctx, t, staleTransaction, 103, 204)
	setIntegrationChange(ctx, t, staleTransaction, staleChangeID)
	var ignoredNetworkRevision, ignoredPolicyRevision, ignoredReleaseVersion int64
	err = staleTransaction.QueryRow(ctx, `SELECT network_revision, policy_revision, release_version
FROM mesh_ops.publish_compiled_policy(
	$1::UUID, $2::BIGINT, $3::BYTEA, 4, $4::TIMESTAMPTZ, $5::JSONB
)`, releaseID, basePolicyRevision, staleHash[:], destination.EvaluatedAt(), stalePayload).Scan(
		&ignoredNetworkRevision, &ignoredPolicyRevision, &ignoredReleaseVersion,
	)
	postgresError, isPostgresError := errors.AsType[*pgconn.PgError](err)
	if !isPostgresError || postgresError.Code != "MT001" {
		_ = staleTransaction.Rollback(ctx)
		t.Fatalf("stale Imported Resource publication error = %v, want MT001", err)
	}
	if err := staleTransaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback stale Imported Resource publication: %v", err)
	}
	var currentNetworkRevision, currentPolicyRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision, policy_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 204`).Scan(
		&currentNetworkRevision, &currentPolicyRevision,
	); err != nil {
		t.Fatalf("query revision after stale publication: %v", err)
	}
	if currentNetworkRevision != baseNetworkRevision || currentPolicyRevision != basePolicyRevision {
		t.Fatalf(
			"stale Imported Resource publication advanced revisions to %d/%d, want %d/%d",
			currentNetworkRevision,
			currentPolicyRevision,
			baseNetworkRevision,
			basePolicyRevision,
		)
	}
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.policy_release
WHERE public_id = $1::UUID`, releaseID).Scan(&releaseCount); err != nil {
		t.Fatalf("verify stale Imported Resource publication rollback: %v", err)
	}
	if releaseCount != 0 {
		t.Fatalf("stale Imported Resource publication leaked %d releases", releaseCount)
	}
}

func newIntegrationResourceSharingStore(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *postgresadapter.ResourceSharingStore {
	t.Helper()
	store, err := postgresadapter.NewResourceSharingStore(
		runtimePool,
		postgresadapter.ResourceSharingOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
			IdempotencyTTL:   time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceSharingStore() error = %v", err)
	}
	return store
}

func activeIntegrationResourceID(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	workspaceID, networkID int64,
) resource.ID {
	t.Helper()
	var value string
	if err := admin.QueryRow(ctx, `SELECT resource.public_id::TEXT
FROM mesh.resource AS resource
JOIN mesh.resource_device_target AS target
  ON target.workspace_id = resource.workspace_id
 AND target.network_id = resource.network_id
 AND target.resource_id = resource.id
 AND target.target_generation = resource.target_generation
 AND target.state = 'active'
WHERE resource.workspace_id = $1
  AND resource.network_id = $2
  AND resource.state = 'active'
  AND resource.deleted_at IS NULL
ORDER BY resource.created_at DESC, resource.id DESC
LIMIT 1`, workspaceID, networkID).Scan(&value); err != nil {
		t.Fatalf("query active Resource Sharing fixture: %v", err)
	}
	id, err := resource.ParseID(value)
	if err != nil {
		t.Fatalf("resource.ParseID() error = %v", err)
	}
	return id
}

func integrationSharingTraffic(t *testing.T) sharing.TrafficSet {
	t.Helper()
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatalf("policy.NewPortRange() error = %v", err)
	}
	constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{port},
	})
	if err != nil {
		t.Fatalf("sharing.NewTrafficConstraint() error = %v", err)
	}
	traffic, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	if err != nil {
		t.Fatalf("sharing.NewTrafficSet() error = %v", err)
	}
	return traffic
}

func assertCommittedResourceSharingEvidence(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	offerID sharing.OfferID,
	contractID sharing.ContractID,
) {
	t.Helper()
	var offerCount, contractCount, importCount, auditCount, outboxCount int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.share_offer WHERE public_id = $1::UUID),
    (SELECT pg_catalog.count(*) FROM mesh.trust_contract WHERE public_id = $2::UUID AND state = 'revoked'),
    (SELECT pg_catalog.count(*) FROM mesh.imported_resource AS imported
     JOIN mesh.trust_contract AS contract ON contract.id = imported.trust_contract_id
     WHERE contract.public_id = $2::UUID AND imported.state = 'revoked'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
     WHERE target_public_id IN ($1::UUID, $2::UUID)),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
     WHERE event_class = 'network.revision.advanced'
       AND payload->>'subsystem' = 'sharing')`, offerID.String(), contractID.String()).Scan(
		&offerCount, &contractCount, &importCount, &auditCount, &outboxCount,
	); err != nil {
		t.Fatalf("query committed Resource Sharing evidence: %v", err)
	}
	if offerCount != 1 || contractCount != 1 || importCount != 1 ||
		auditCount != 8 || outboxCount < 8 {
		t.Fatalf(
			"Resource Sharing evidence offer=%d contract=%d import=%d audit=%d outbox=%d",
			offerCount, contractCount, importCount, auditCount, outboxCount,
		)
	}
}
