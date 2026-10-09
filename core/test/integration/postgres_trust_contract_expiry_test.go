//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/sharing/contractexpiry"
)

const expiringShareLabel = "expiring-db"

// assertTrustContractExpiryReleasesAccessName qualifies schema 112: an
// expired share blocks a new share of the same name until the worker
// finalizes it; finalizing ends every row that names the contract, advances
// both Networks once with system evidence, and the next share reserves the
// same consumer DNS name. Times are injected just behind the database clock
// so the contract is already past expiry without sleeping.
func assertTrustContractExpiryReleasesAccessName(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	store *postgresadapter.ResourceSharingStore,
	workerPool *postgresadapter.Pool,
	session accountsession.Session,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
) {
	t.Helper()
	importedName, err := resource.ParseDisplayName("Expiring shared Resource")
	if err != nil {
		t.Fatal(err)
	}
	start := integrationDatabaseNow(ctx, t, admin)
	expiresAt := start.Add(30 * time.Microsecond)
	first := createLabeledShare(ctx, t, store, session, providerScope, consumerScope, resourceID,
		maximumTraffic, reason, importedName, start, expiresAt, 240)
	firstName := first.accessName
	if now := integrationDatabaseNow(ctx, t, admin); !now.After(expiresAt) {
		t.Fatalf("database clock %s is not past expiry %s", now, expiresAt)
	}
	assertImportedResourceAccessName(ctx, t, admin, first.contract.ImportedResourceID(), firstName, "reserved", 1)

	// Before finalization the expired name still blocks the next share.
	again := integrationDatabaseNow(ctx, t, admin)
	second := createLabeledOffer(ctx, t, store, session, providerScope, consumerScope, resourceID,
		maximumTraffic, reason, again, again.Add(time.Hour), 243)
	if second.offer.AccessName() != firstName {
		t.Fatalf("relabeled offer name = %s, want %s", second.offer.AccessName(), firstName)
	}
	if _, err := store.DecideOffer(ctx, acceptLabeledOffer(t, session, providerScope, consumerScope,
		second, importedName, reason, 244), again.Add(time.Millisecond)); !errors.Is(err, sharing.ErrConflict) {
		t.Fatalf("accept over an unfinalized expired share: error = %v, want conflict", err)
	}

	expiry, err := postgresadapter.NewTrustContractExpiryStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	installation := contractInstallation(ctx, t, admin, first.contract.ID())
	if !listsExpiredContract(ctx, t, expiry, installation, first.contract.ID()) {
		t.Fatal("expired open contract was not discovered")
	}
	before := shareRevisions(ctx, t, admin, first.contract.ID())
	changed, err := expiry.Expire(ctx, installation, first.contract.ID())
	if err != nil || !changed {
		t.Fatalf("Expire() = %v, %v", changed, err)
	}
	assertExpiredShareRows(ctx, t, admin, first.contract)
	after := shareRevisions(ctx, t, admin, first.contract.ID())
	for index := range before {
		if after[index] != before[index]+1 {
			t.Fatalf("revisions before %v after %v, want each advanced once", before, after)
		}
	}
	assertTrustContractExpiryEvidence(ctx, t, admin, first.contract.ID())

	changed, err = expiry.Expire(ctx, installation, first.contract.ID())
	if err != nil || changed {
		t.Fatalf("repeated Expire() = %v, %v, want unchanged", changed, err)
	}
	if listsExpiredContract(ctx, t, expiry, installation, first.contract.ID()) {
		t.Fatal("finalized contract is still discovered")
	}
	if got := shareRevisions(ctx, t, admin, first.contract.ID()); got != after {
		t.Fatalf("repeated expiry advanced revisions %v -> %v", after, got)
	}
	assertExpiryEntryPointsAreWorkerOnly(ctx, t, admin, installation, first.contract.ID())

	// The same offer now reserves the same name for a new Imported Resource.
	retry := integrationDatabaseNow(ctx, t, admin)
	accepted, err := store.DecideOffer(ctx, acceptLabeledOffer(t, session, providerScope, consumerScope,
		second, importedName, reason, 245), retry)
	if err != nil {
		t.Fatalf("accept after expiry finalization: %v", err)
	}
	replacement, hasContract := accepted.Contract()
	if !hasContract || replacement.ImportedResourceID() == first.contract.ImportedResourceID() {
		t.Fatalf("replacement share = %+v", accepted)
	}
	assertImportedResourceAccessName(ctx, t, admin, replacement.ImportedResourceID(), firstName, "reserved", 1)
	assertImportedResourceAccessName(ctx, t, admin, first.contract.ImportedResourceID(), firstName, "withdrawn", 2)
}

type labeledOffer struct {
	offer sharing.OfferSnapshot
	token sharing.OfferToken
}

type labeledShare struct {
	contract   sharing.Contract
	accessName sharing.AccessName
}

func integrationDatabaseNow(ctx context.Context, t *testing.T, admin *pgx.Conn) time.Time {
	t.Helper()
	var now time.Time
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC()
}

func createLabeledOffer(
	ctx context.Context,
	t *testing.T,
	store *postgresadapter.ResourceSharingStore,
	session accountsession.Session,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
	at, expiresAt time.Time,
	proofMarker byte,
) labeledOffer {
	t.Helper()
	label, err := sharing.ParseAccessLabel(expiringShareLabel)
	if err != nil {
		t.Fatal(err)
	}
	command, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: expiresAt, AccessLabel: label, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, proofMarker),
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateOffer(ctx, command, at)
	if err != nil {
		t.Fatalf("create labeled Share Offer: %v", err)
	}
	offer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken {
		t.Fatalf("labeled Share Offer = %+v", created)
	}
	return labeledOffer{offer: offer, token: token}
}

func acceptLabeledOffer(
	t *testing.T,
	session accountsession.Session,
	providerScope, consumerScope network.Scope,
	offer labeledOffer,
	importedName resource.DisplayName,
	reason sharing.AuditReason,
	proofMarker byte,
) sharing.DecideOffer {
	t.Helper()
	decision, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: offer.offer.Offer().ID(), ExpectedOfferVersion: offer.offer.Offer().Version(),
		Token: offer.token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccessName: offer.offer.AccessName(), AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, proofMarker),
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

// createLabeledShare offers, accepts and activates at injected times, so the
// alias model provisions its Private Endpoint and Federation Alias.
func createLabeledShare(
	ctx context.Context,
	t *testing.T,
	store *postgresadapter.ResourceSharingStore,
	session accountsession.Session,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
	importedName resource.DisplayName,
	at, expiresAt time.Time,
	proofMarker byte,
) labeledShare {
	t.Helper()
	offer := createLabeledOffer(ctx, t, store, session, providerScope, consumerScope, resourceID,
		maximumTraffic, reason, at, expiresAt, proofMarker)
	accepted, err := store.DecideOffer(ctx, acceptLabeledOffer(t, session, providerScope, consumerScope,
		offer, importedName, reason, proofMarker+1), at.Add(10*time.Microsecond))
	if err != nil {
		t.Fatalf("accept labeled Share Offer: %v", err)
	}
	contract, hasContract := accepted.Contract()
	if !hasContract {
		t.Fatalf("labeled acceptance = %+v", accepted)
	}
	activation, err := sharing.NewActivateContract(sharing.ActivateContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: contract.ID(), ExpectedContractVersion: contract.Version(),
		AccountSession: session, Reason: reason, Idempotency: resourceAuthorityProof(t, proofMarker+2),
	})
	if err != nil {
		t.Fatal(err)
	}
	activated, err := store.ActivateContract(ctx, activation, at.Add(20*time.Microsecond))
	if err != nil {
		t.Fatalf("activate labeled share: %v", err)
	}
	active, hasContract := activated.Contract()
	if !hasContract || active.State() != sharing.ContractStateActive {
		t.Fatalf("labeled activation = %+v", activated)
	}
	return labeledShare{contract: active, accessName: offer.offer.AccessName()}
}

func contractInstallation(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.ContractID) deployment.ID {
	t.Helper()
	var value string
	if err := admin.QueryRow(ctx, `SELECT deployment.installation_public_id::TEXT
FROM mesh.trust_contract AS contract
JOIN mesh.deployment AS deployment ON deployment.id = contract.deployment_id
WHERE contract.public_id = $1::UUID`, contract.String()).Scan(&value); err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(value)
	if err != nil {
		t.Fatal(err)
	}
	return installation
}

func listsExpiredContract(
	ctx context.Context,
	t *testing.T,
	expiry *postgresadapter.TrustContractExpiryStore,
	installation deployment.ID,
	contract sharing.ContractID,
) bool {
	t.Helper()
	cursor := contractexpiry.Cursor{}
	for range 64 {
		page, err := expiry.List(ctx, installation, cursor, 128)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		for _, candidate := range page.Items {
			if candidate.ContractID == contract {
				return true
			}
		}
		if page.Done {
			return false
		}
		cursor = page.Next
	}
	t.Fatal("expiry discovery did not finish")
	return false
}

// shareRevisions returns provider then consumer network and sharing revisions.
func shareRevisions(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.ContractID) [4]int64 {
	t.Helper()
	var revisions [4]int64
	if err := admin.QueryRow(ctx, `SELECT provider.network_revision, provider.sharing_revision,
    consumer.network_revision, consumer.sharing_revision
FROM mesh.trust_contract AS contract
JOIN mesh_ops.network_revision AS provider
  ON provider.workspace_id = contract.provider_workspace_id AND provider.network_id = contract.provider_network_id
JOIN mesh_ops.network_revision AS consumer
  ON consumer.workspace_id = contract.consumer_workspace_id AND consumer.network_id = contract.consumer_network_id
WHERE contract.public_id = $1::UUID`, contract.String()).Scan(
		&revisions[0], &revisions[1], &revisions[2], &revisions[3],
	); err != nil {
		t.Fatal(err)
	}
	return revisions
}

func assertExpiredShareRows(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.Contract) {
	t.Helper()
	var contractState, importState, endpointState, leaseState string
	var contractVersion int64
	var endedAtExpiry, endedMatchesUpdate bool
	if err := admin.QueryRow(ctx, `SELECT contract.state, contract.version,
    contract.ended_at >= contract.expires_at, contract.ended_at = contract.updated_at,
    imported.state, endpoint.state, lease.state
FROM mesh.trust_contract AS contract
JOIN mesh.imported_resource AS imported ON imported.trust_contract_id = contract.id
JOIN mesh.private_endpoint AS endpoint ON endpoint.trust_contract_id = contract.id
JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
WHERE contract.public_id = $1::UUID`, contract.ID().String()).Scan(
		&contractState, &contractVersion, &endedAtExpiry, &endedMatchesUpdate,
		&importState, &endpointState, &leaseState,
	); err != nil {
		t.Fatalf("read expired share rows: %v", err)
	}
	if contractState != "expired" || contractVersion != contract.Version()+1 || !endedAtExpiry || !endedMatchesUpdate ||
		importState != "expired" || endpointState != "expired" || leaseState != "withdrawn" {
		t.Fatalf("expired share rows = contract %s v%d ended %t/%t, import %s, endpoint %s, lease %s",
			contractState, contractVersion, endedAtExpiry, endedMatchesUpdate, importState, endpointState, leaseState)
	}
}

func assertTrustContractExpiryEvidence(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.ContractID) {
	t.Helper()
	var changes, events, systemActors, outbox, mutations int
	if err := admin.QueryRow(ctx, `WITH expiry AS (
    SELECT identity.change_public_id, identity.transaction_id, event.actor_principal_public_id
    FROM mesh_audit.audit_event AS event
    JOIN mesh_audit.audit_event_identity AS identity
      ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
    WHERE event.action = 'trust_contract.expired' AND event.target_public_id = $1::UUID
)
SELECT
    (SELECT pg_catalog.count(DISTINCT change_public_id) FROM expiry),
    (SELECT pg_catalog.count(*) FROM expiry),
    (SELECT pg_catalog.count(*) FROM expiry WHERE actor_principal_public_id IS NULL),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS outbox
     WHERE outbox.change_public_id IN (SELECT change_public_id FROM expiry)
       AND outbox.event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
     WHERE mutation.change_public_id IN (SELECT change_public_id FROM expiry))`,
		contract.String()).Scan(&changes, &events, &systemActors, &outbox, &mutations); err != nil {
		t.Fatalf("read expiry evidence: %v", err)
	}
	// Contract, Imported Resource, access name, Private Endpoint, alias lease.
	if changes != 1 || events != 2 || systemActors != 2 || outbox != 2 || mutations != 5 {
		t.Fatalf("expiry evidence: changes %d, events %d, system %d, outbox %d, mutations %d",
			changes, events, systemActors, outbox, mutations)
	}
}

// assertExpiryEntryPointsAreWorkerOnly checks the runtime role cannot call the
// finalizer and that finalize cannot append evidence without a mutation.
func assertExpiryEntryPointsAreWorkerOnly(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	installation deployment.ID,
	contract sharing.ContractID,
) {
	t.Helper()
	change := newIntegrationPublicationID(t).String()
	scope, target := installation.String(), contract.String()
	for _, testCase := range []struct {
		name, role, query, code string
		args                    []any
	}{
		{name: "runtime list", role: "mesh_runtime", code: "42501", args: []any{scope},
			query: `SELECT mesh_ops.list_expired_trust_contracts_v1($1::UUID, NULL, NULL, 1)`},
		{name: "runtime prepare", role: "mesh_runtime", code: "42501", args: []any{scope, target, change},
			query: `SELECT mesh_ops.prepare_trust_contract_expiry_v1($1::UUID, $2::UUID, $3::UUID)`},
		{name: "worker proof helper", role: "mesh_worker", code: "42501", args: []any{change},
			query: `SELECT mesh_ops.trust_contract_expiry_proof_internal_v1(1, $1::UUID)`},
		{name: "worker finalize without mutation", role: "mesh_worker", code: "23514", args: []any{scope, target, change},
			query: `SELECT mesh_ops.finalize_trust_contract_expiry_v1($1::UUID, $2::UUID, $3::UUID,
    '[{"stream_id":"1"},{"stream_id":"2"}]'::JSONB)`},
	} {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec(ctx, `SET LOCAL ROLE `+testCase.role); err != nil {
			t.Fatal(err)
		}
		var ignored any
		err = transaction.QueryRow(ctx, testCase.query, testCase.args...).Scan(&ignored)
		if rollbackErr := transaction.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err == nil {
			t.Fatalf("%s succeeded", testCase.name)
		}
		assertPostgreSQLCode(t, err, testCase.code)
	}
}
