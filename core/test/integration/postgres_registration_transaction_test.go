//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const registrationTransactionChangeID = "01890f21-0000-7000-8000-000000000001"

func assertPostgreSQLRegistrationTransaction(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	command registrationapp.Command,
) {
	t.Helper()
	var beforeNetworkRevision, beforeInventoryRevision int64
	if err := adminConnection.QueryRow(ctx, `SELECT network_revision, inventory_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(
		&beforeNetworkRevision,
		&beforeInventoryRevision,
	); err != nil {
		t.Fatalf("read revisions before registration transaction: %v", err)
	}
	transactions, err := postgresadapter.NewRegistrationTransactions(
		runtimePool,
		postgresadapter.RegistrationTransactionOptions{
			StatementTimeout:      5 * time.Second,
			LockTimeout:           time.Second,
			IdleTimeout:           10 * time.Second,
			AddressCandidateLimit: 256,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationTransactions() error = %v", err)
	}
	transaction, err := transactions.Begin(ctx, command.Scope)
	if err != nil {
		t.Fatalf("RegistrationTransactions.Begin() error = %v", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), integrationCleanupTimeout)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			t.Errorf("RegistrationTransaction.Rollback() error = %v", err)
		}
	}()

	resolution, err := transaction.Resolve(ctx, command)
	if err != nil {
		t.Fatalf("RegistrationTransaction.Resolve() error = %v", err)
	}
	change := registrationTransactionChange(t, command, resolution)
	result, err := transaction.Apply(ctx, change)
	if err != nil {
		t.Fatalf("RegistrationTransaction.Apply() error = %v", err)
	}
	if result.NodeID() != change.NodeID() || result.Hostname() != command.Hostname ||
		result.Disposition() != registrationapp.DispositionCreated ||
		result.NetworkRevision() != beforeNetworkRevision+1 {
		t.Fatalf(
			"registration transaction result = %+v, want created Node at revision %d",
			result,
			beforeNetworkRevision+1,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("RegistrationTransaction.Commit() error = %v", err)
	}
	committed = true

	assertRegistrationTransactionEvidence(
		ctx,
		t,
		adminConnection,
		command,
		change,
		beforeNetworkRevision+1,
		beforeInventoryRevision+1,
	)
	replayStore, err := postgresadapter.NewRegistrationReplayStore(runtimePool)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationReplayStore() error = %v", err)
	}
	replayed, found, err := replayStore.ResolveCommitted(ctx, command)
	if err != nil || !found || replayed.NodeID() != result.NodeID() ||
		replayed.Hostname() != result.Hostname() || replayed.NetworkRevision() != result.NetworkRevision() {
		t.Fatalf("committed registration replay = (%+v, %t, %v), want exact result", replayed, found, err)
	}
}

func assertRegistrationTransactionLockHelpers(
	ctx context.Context,
	t *testing.T,
	runtimeConnection *pgx.Conn,
	command registrationapp.Command,
) {
	t.Helper()
	err := runtimeConnection.QueryRow(
		ctx,
		"SELECT credential_internal_id FROM mesh_ops.lock_registration_credential($1::UUID)",
		command.CredentialID.String(),
	).Scan(new(int64))
	assertPostgreSQLCode(t, err, "42501")
	unscopedRows, err := runtimeConnection.Query(
		ctx,
		"SELECT prefix_internal_id FROM mesh_ops.lock_registration_prefixes(9::BIGINT)",
	)
	if err == nil {
		for unscopedRows.Next() {
		}
		err = unscopedRows.Err()
		unscopedRows.Close()
	}
	assertPostgreSQLCode(t, err, "42501")

	transaction, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin registration lock-helper transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	assertResolvedNetworkScope(
		ctx,
		t,
		transaction,
		firstWorkspacePublicID,
		firstNetworkPublicID,
		101,
		201,
	)
	if err := transaction.QueryRow(
		ctx,
		"SELECT credential_internal_id FROM mesh_ops.lock_registration_credential($1::UUID)",
		command.CredentialID.String(),
	).Scan(new(int64)); err != nil {
		t.Fatalf("runtime registration credential lock helper: %v", err)
	}
	var directPrefixCount int
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.network_prefix AS prefix
JOIN mesh.address_pool AS pool
  ON pool.workspace_id = prefix.workspace_id
 AND pool.address_realm_id = prefix.address_realm_id
 AND pool.id = prefix.address_pool_id
JOIN mesh.address_realm AS realm
  ON realm.workspace_id = prefix.workspace_id
 AND realm.id = prefix.address_realm_id
WHERE prefix.state = 'active'
  AND pool.state = 'active'
  AND pool.purpose = 'node_overlay'
  AND realm.state = 'active'`).Scan(&directPrefixCount); err != nil {
		t.Fatalf("runtime direct registration prefix snapshot: %v", err)
	}
	rows, err := transaction.Query(
		ctx,
		"SELECT prefix_internal_id FROM mesh_ops.lock_registration_prefixes(9::BIGINT)",
	)
	if err != nil {
		t.Fatalf("runtime registration prefix lock helper: %v", err)
	}
	defer rows.Close()
	prefixCount := 0
	for rows.Next() {
		prefixCount++
		if err := rows.Scan(new(int64)); err != nil {
			t.Fatalf("scan runtime registration prefix lock helper: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read runtime registration prefix lock helper: %v", err)
	}
	if prefixCount != 1 {
		t.Fatalf(
			"runtime registration prefix lock helper returned %d rows, want 1 (direct snapshot %d)",
			prefixCount,
			directPrefixCount,
		)
	}
}

func assertWorkerCannotLockRegistrationResources(
	ctx context.Context,
	t *testing.T,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	var canLockCredential, canLockPrefixes bool
	if err := workerConnection.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege(
        CURRENT_USER,
        'mesh_ops.lock_registration_credential(uuid)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        CURRENT_USER,
        'mesh_ops.lock_registration_prefixes(bigint)',
        'EXECUTE'
    )`).Scan(&canLockCredential, &canLockPrefixes); err != nil {
		t.Fatalf("query worker registration lock privileges: %v", err)
	}
	if canLockCredential || canLockPrefixes {
		t.Fatalf(
			"worker registration lock privileges: credential=%t prefixes=%t, want false/false",
			canLockCredential,
			canLockPrefixes,
		)
	}
	err := workerConnection.QueryRow(ctx, `SELECT credential_internal_id
FROM mesh_ops.lock_registration_credential(
    '01890f20-0000-7000-8000-000000000612'::UUID
)`).Scan(new(int64))
	assertPostgreSQLCode(t, err, "42501")
	rows, err := workerConnection.Query(
		ctx,
		"SELECT prefix_internal_id FROM mesh_ops.lock_registration_prefixes(9::BIGINT)",
	)
	if err == nil {
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
	}
	assertPostgreSQLCode(t, err, "42501")
}

func registrationTransactionChange(
	t *testing.T,
	command registrationapp.Command,
	resolution registrationapp.Resolution,
) registrationapp.Change {
	t.Helper()
	occurredAt := time.Now().UTC()
	credential, err := resolution.Credential().Consume(occurredAt, command.RecoveryEpoch)
	if err != nil {
		t.Fatalf("consume integration registration credential: %v", err)
	}
	registrationValue, err := resolution.Registration().Authorize(occurredAt)
	if err != nil {
		t.Fatalf("authorize integration registration: %v", err)
	}
	nodeID, err := node.ParseID("01890f20-0000-7000-8000-000000000613")
	if err != nil {
		t.Fatalf("parse integration transaction Node ID: %v", err)
	}
	registrationValue, err = registrationValue.Complete(nodeID, occurredAt)
	if err != nil {
		t.Fatalf("complete integration registration: %v", err)
	}
	change, err := registrationapp.NewChange(registrationapp.ChangeParams{
		Registration: registrationValue,
		Profile:      resolution.Profile(),
		Credential:   credential,
		Identity:     command.Identity,
		OwnerID:      credential.IssuerID(),
		CustodianID:  credential.IssuerID(),
		NodeID:       nodeID,
		Hostname:     command.Hostname,
		Disposition:  registrationapp.DispositionCreated,
		MutationIDs:  integrationRegistrationMutationIDs(t),
		OccurredAt:   occurredAt,
	})
	if err != nil {
		t.Fatalf("construct integration registration change: %v", err)
	}
	return change
}

func integrationRegistrationMutationIDs(t *testing.T) registrationapp.MutationIDs {
	t.Helper()
	values := [...]string{
		registrationTransactionChangeID,
		"01890f21-0000-7000-8000-000000000002",
		"01890f21-0000-7000-8000-000000000003",
		"01890f21-0000-7000-8000-000000000004",
		"01890f21-0000-7000-8000-000000000005",
		"01890f21-0000-7000-8000-000000000006",
		"01890f21-0000-7000-8000-000000000007",
		"01890f21-0000-7000-8000-000000000008",
	}
	ids := make([]publicid.ID, len(values))
	for index, value := range values {
		id, err := publicid.Parse(value)
		if err != nil {
			t.Fatalf("parse integration mutation ID %q: %v", value, err)
		}
		ids[index] = id
	}
	mutationIDs, err := registrationapp.NewMutationIDs(registrationapp.MutationIDParams{
		ChangeID:          ids[0],
		AuditEventID:      ids[1],
		OutboxEventID:     ids[2],
		CredentialUseID:   ids[3],
		MachineKeyEpochID: ids[4],
		NodeKeyEpochID:    ids[5],
		IPv4LeaseID:       ids[6],
		IPv6LeaseID:       ids[7],
	})
	if err != nil {
		t.Fatalf("construct integration mutation IDs: %v", err)
	}
	return mutationIDs
}

func assertRegistrationTransactionEvidence(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command registrationapp.Command,
	change registrationapp.Change,
	wantNetworkRevision int64,
	wantInventoryRevision int64,
) {
	t.Helper()
	var usedCount, networkRevision, inventoryRevision, authorityMutations int64
	var registrationState, disposition, nodePublicID, hostname, address, eventClass string
	var auditMatchesStream bool
	if err := connection.QueryRow(ctx, `SELECT
    credential.used_count,
    registration.state,
    registration.completed_disposition,
    device.public_id::TEXT,
    device.hostname,
    pg_catalog.host(lease.address),
    revision.network_revision,
    revision.inventory_revision,
    outbox.event_class,
    stream.latest_event_hash = identity.event_hash,
    (
        SELECT pg_catalog.count(*)
        FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = $3::UUID
    )
FROM mesh.pending_registration AS registration
JOIN mesh.enrollment_credential AS credential
  ON credential.id = registration.enrollment_credential_id
JOIN mesh.device AS device ON device.id = registration.device_id
JOIN mesh.node_address_lease AS lease
  ON lease.device_id = device.id
 AND lease.state = 'active'
 AND lease.lease_role = 'primary'
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = registration.workspace_id
 AND revision.network_id = registration.network_id
JOIN mesh_ops.outbox_event AS outbox
  ON outbox.change_public_id = $3::UUID
JOIN mesh_audit.audit_event_identity AS identity
  ON identity.change_public_id = outbox.change_public_id
 AND identity.transaction_id = outbox.transaction_id
JOIN mesh_audit.audit_stream AS stream ON stream.id = identity.stream_id
WHERE registration.public_id = $1::UUID
  AND credential.public_id = $2::UUID`,
		command.RegistrationID.String(),
		command.CredentialID.String(),
		registrationTransactionChangeID,
	).Scan(
		&usedCount,
		&registrationState,
		&disposition,
		&nodePublicID,
		&hostname,
		&address,
		&networkRevision,
		&inventoryRevision,
		&eventClass,
		&auditMatchesStream,
		&authorityMutations,
	); err != nil {
		t.Fatalf("query committed registration transaction evidence: %v", err)
	}
	if usedCount != 1 || registrationState != "completed" || disposition != "created" ||
		nodePublicID != change.NodeID().String() || hostname != command.Hostname.String() ||
		address != "100.64.1.2" || networkRevision != wantNetworkRevision ||
		inventoryRevision != wantInventoryRevision ||
		eventClass != "network.revision.advanced" || !auditMatchesStream || authorityMutations != 7 {
		t.Fatalf(
			"registration evidence = uses %d state %q disposition %q Node %q hostname %q "+
				"address %q revisions %d/%d event %q linked %t mutations %d",
			usedCount,
			registrationState,
			disposition,
			nodePublicID,
			hostname,
			address,
			networkRevision,
			inventoryRevision,
			eventClass,
			auditMatchesStream,
			authorityMutations,
		)
	}
}
