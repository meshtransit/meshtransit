//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func assertAuthorityEvidenceFoundation(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	var mutations, identities, payloads, outboxEvents, streams int64
	var mutationsWithoutAudit, mutationsWithoutOutbox, brokenHashLinks int64
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event_identity),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_stream),
    (
        SELECT pg_catalog.count(*)
        FROM mesh_audit.authority_mutation AS mutation
        WHERE NOT EXISTS (
            SELECT 1
            FROM mesh_audit.audit_event_identity AS identity
            JOIN mesh_audit.audit_event AS event
              ON event.event_identity_id = identity.id
             AND event.occurred_at = identity.occurred_at
            WHERE identity.change_public_id = mutation.change_public_id
              AND identity.transaction_id = mutation.transaction_id
        )
    ),
    (
        SELECT pg_catalog.count(*)
        FROM mesh_audit.authority_mutation AS mutation
        WHERE NOT EXISTS (
            SELECT 1
            FROM mesh_ops.outbox_event AS event
            WHERE event.change_public_id = mutation.change_public_id
              AND event.transaction_id = mutation.transaction_id
        )
    ),
    (
        WITH chain AS (
            SELECT
                identity.previous_event_hash,
                pg_catalog.lag(identity.event_hash) OVER (
                    PARTITION BY identity.stream_id
                    ORDER BY identity.stream_sequence
                ) AS predecessor_hash
            FROM mesh_audit.audit_event_identity AS identity
        )
        SELECT pg_catalog.count(*)
        FROM chain
        WHERE previous_event_hash <> COALESCE(
            predecessor_hash,
            pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        )
    )`).Scan(
		&mutations,
		&identities,
		&payloads,
		&outboxEvents,
		&streams,
		&mutationsWithoutAudit,
		&mutationsWithoutOutbox,
		&brokenHashLinks,
	); err != nil {
		t.Fatalf("query authority evidence foundation: %v", err)
	}
	if mutations != 14 || identities != 5 || payloads != 5 || outboxEvents != 5 || streams != 3 {
		t.Fatalf(
			"authority evidence counts: mutations=%d identities=%d payloads=%d outbox=%d streams=%d",
			mutations,
			identities,
			payloads,
			outboxEvents,
			streams,
		)
	}
	if mutationsWithoutAudit != 0 || mutationsWithoutOutbox != 0 || brokenHashLinks != 0 {
		t.Fatalf(
			"authority evidence integrity: missing audit=%d missing outbox=%d broken hash links=%d",
			mutationsWithoutAudit,
			mutationsWithoutOutbox,
			brokenHashLinks,
		)
	}

	var deploymentNextSequence, networkNextSequence int64
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT next_sequence FROM mesh_audit.audit_stream WHERE id = 1),
    (SELECT next_sequence FROM mesh_audit.audit_stream WHERE id = 201)`).Scan(
		&deploymentNextSequence,
		&networkNextSequence,
	); err != nil {
		t.Fatalf("query seeded audit stream sequences: %v", err)
	}
	if deploymentNextSequence != 4 || networkNextSequence != 2 {
		t.Fatalf(
			"seeded audit stream sequences: deployment=%d network=%d, want 4 and 2",
			deploymentNextSequence,
			networkNextSequence,
		)
	}
}

func assertAuthorityMutationAtomicity(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	t.Run("change context is transaction local", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin missing change context transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)

		_, err = transaction.Exec(ctx, `UPDATE mesh.network
SET display_name = 'Missing context', version = version + 1
WHERE id = 201`)
		assertPostgreSQLCode(t, err, "23514")
	})

	t.Run("deferred evidence failure rolls back domain mutation", func(t *testing.T) {
		const changePublicID = "01890f01-0000-7000-8000-000000000801"
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin incomplete evidence transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, changePublicID)
		if _, err := transaction.Exec(ctx, `UPDATE mesh.network
SET display_name = 'Incomplete evidence', version = version + 1
WHERE id = 201`); err != nil {
			t.Fatalf("execute incomplete authority mutation: %v", err)
		}
		assertPostgreSQLCode(t, transaction.Commit(ctx), "23514")

		var version, mutations int64
		if err := connection.QueryRow(ctx, `SELECT
    (SELECT version FROM mesh.network WHERE id = 201),
    (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation WHERE change_public_id = $1)`,
			changePublicID,
		).Scan(&version, &mutations); err != nil {
			t.Fatalf("query incomplete evidence rollback: %v", err)
		}
		if version != 1 || mutations != 0 {
			t.Fatalf("incomplete evidence persisted version=%d mutations=%d", version, mutations)
		}
	})

	const completedChangePublicID = "01890f01-0000-7000-8000-000000000901"
	t.Run("domain audit and outbox commit atomically", func(t *testing.T) {
		commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
			changePublicID:         completedChangePublicID,
			eventPublicID:          "01890f02-0000-7000-8000-000000000901",
			outboxPublicID:         "01890f03-0000-7000-8000-000000000901",
			streamID:               201,
			aggregateKind:          "network",
			aggregatePublicID:      "01890f00-0000-7000-8000-000000000201",
			aggregateVersion:       2,
			networkRevision:        int64(2),
			actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
			action:                 "network.updated",
			permission:             "network.update",
			outboxEventClass:       "network.updated",
		}, func(transaction pgx.Tx) {
			setIntegrationScope(ctx, t, transaction, 101, 201)
			if _, err := transaction.Exec(ctx, `UPDATE mesh.network
SET display_name = 'Network one updated', version = version + 1
WHERE workspace_id = 101 AND id = 201`); err != nil {
				t.Fatalf("update audited integration network: %v", err)
			}
			if _, err := transaction.Exec(ctx, `UPDATE mesh_ops.network_revision
SET network_revision = network_revision + 1,
    updated_at = pg_catalog.clock_timestamp()
WHERE workspace_id = 101 AND network_id = 201`); err != nil {
				t.Fatalf("update integration network revision: %v", err)
			}
		})

		assertCommittedAuthorityChange(ctx, t, connection, completedChangePublicID)
	})

	t.Run("stale audit stream head aborts mutation", func(t *testing.T) {
		const changePublicID = "01890f01-0000-7000-8000-000000000902"
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin stale audit head transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, changePublicID)
		if _, err := transaction.Exec(ctx, `UPDATE mesh.network
SET display_name = 'Stale audit head', version = version + 1
WHERE id = 201`); err != nil {
			t.Fatalf("execute stale audit head mutation: %v", err)
		}

		var sequence int64
		err = transaction.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
    201::BIGINT,
    '01890f02-0000-7000-8000-000000000902'::UUID,
    '01890f03-0000-7000-8000-000000000902'::UUID,
    1::BIGINT,
    $1::BYTEA,
    $2::BYTEA,
    'network'::TEXT,
    '01890f00-0000-7000-8000-000000000201'::UUID,
    3::BIGINT,
    3::BIGINT,
    '01890f00-0000-7000-8000-000000000011'::UUID,
    'network.updated'::TEXT,
    'network.update'::TEXT,
    NULL::UUID,
    NULL::BYTEA,
    NULL::BYTEA,
    '{}'::JSONB,
    'network.updated'::TEXT,
    '{}'::JSONB
)`, make([]byte, sha256.Size), make([]byte, sha256.Size)).Scan(&sequence)
		assertPostgreSQLCode(t, err, "40001")
		if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatalf("rollback stale audit head transaction: %v", err)
		}

		var version, mutations int64
		if err := connection.QueryRow(ctx, `SELECT
    (SELECT version FROM mesh.network WHERE id = 201),
    (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation WHERE change_public_id = $1)`,
			changePublicID,
		).Scan(&version, &mutations); err != nil {
			t.Fatalf("query stale audit head rollback: %v", err)
		}
		if version != 2 || mutations != 0 {
			t.Fatalf("stale audit head persisted version=%d mutations=%d", version, mutations)
		}
	})

	t.Run("change identifier cannot cross transactions", func(t *testing.T) {
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatalf("begin reused change identifier transaction: %v", err)
		}
		defer rollbackIntegrationTransaction(ctx, t, transaction)
		setIntegrationChange(ctx, t, transaction, completedChangePublicID)
		_, err = transaction.Exec(ctx, `UPDATE mesh.network
SET display_name = 'Reused change', version = version + 1
WHERE id = 201`)
		assertPostgreSQLCode(t, err, "23P01")
	})

	t.Run("security evidence is immutable", func(t *testing.T) {
		_, err := connection.Exec(ctx, `UPDATE mesh_audit.audit_event_identity
SET event_hash = event_hash
WHERE change_public_id = $1`, completedChangePublicID)
		assertPostgreSQLCode(t, err, "23514")
	})
}

func assertCommittedAuthorityChange(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	changePublicID string,
) {
	t.Helper()

	var operation string
	var beforeVersion, afterVersion, streamSequence, aggregateVersion, networkRevision int64
	var transactionIDsMatch, streamHeadMatches bool
	var partitionName string
	var occurredAt time.Time
	if err := connection.QueryRow(ctx, `SELECT
    mutation.operation,
    mutation.before_version,
    mutation.after_version,
    identity.stream_sequence,
    outbox.aggregate_version,
    outbox.network_revision,
    mutation.transaction_id = identity.transaction_id
        AND identity.transaction_id = outbox.transaction_id,
    stream.latest_event_hash = identity.event_hash
        AND stream.next_sequence = identity.stream_sequence + 1,
    event.tableoid::pg_catalog.regclass::TEXT,
    event.occurred_at
FROM mesh_audit.authority_mutation AS mutation
JOIN mesh_audit.audit_event_identity AS identity
  ON identity.change_public_id = mutation.change_public_id
 AND identity.transaction_id = mutation.transaction_id
JOIN mesh_audit.audit_event AS event
  ON event.event_identity_id = identity.id
 AND event.occurred_at = identity.occurred_at
JOIN mesh_ops.outbox_event AS outbox
  ON outbox.change_public_id = mutation.change_public_id
 AND outbox.transaction_id = mutation.transaction_id
JOIN mesh_audit.audit_stream AS stream
  ON stream.id = identity.stream_id
WHERE mutation.change_public_id = $1`, changePublicID).Scan(
		&operation,
		&beforeVersion,
		&afterVersion,
		&streamSequence,
		&aggregateVersion,
		&networkRevision,
		&transactionIDsMatch,
		&streamHeadMatches,
		&partitionName,
		&occurredAt,
	); err != nil {
		t.Fatalf("query committed authority change: %v", err)
	}
	if operation != "update" || beforeVersion != 1 || afterVersion != 2 ||
		streamSequence != 2 || aggregateVersion != 2 || networkRevision != 2 ||
		!transactionIDsMatch || !streamHeadMatches {
		t.Fatalf(
			"committed authority change: operation=%s versions=%d/%d sequence=%d "+
				"aggregate=%d revision=%d transaction match=%t stream head match=%t",
			operation,
			beforeVersion,
			afterVersion,
			streamSequence,
			aggregateVersion,
			networkRevision,
			transactionIDsMatch,
			streamHeadMatches,
		)
	}
	wantPartition := "mesh_audit.audit_event_default"
	switch occurredAt.UTC().Format("2006_01") {
	case "2026_09", "2026_10":
		wantPartition = "mesh_audit.audit_event_" + occurredAt.UTC().Format("2006_01")
	}
	if partitionName != wantPartition {
		t.Fatalf("audit event partition = %q, want %q", partitionName, wantPartition)
	}
}
