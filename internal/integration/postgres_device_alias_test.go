//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

const reserveDeviceAliasesSQL = `SELECT alias_role, family, address::TEXT, owner_device_id,
    node_key_epoch, version FROM mesh_ops.reserve_device_aliases_internal_v1(
        $1::UUID, $2::UUID, $3::BIGINT, $4::BIGINT, $5::BIGINT, $6::UUID[])`

type deviceAliasFixtureRow struct {
	Role                  string
	Family                int
	Address               string
	Owner, Epoch, Version int64
}

func assertPostgreSQLDeviceAliasReservation(
	ctx context.Context, t *testing.T, admin *pgx.Conn, importedID sharing.ImportedResourceID,
) {
	t.Helper()
	seedDeviceAliasAuthority(ctx, t, admin)
	var endpointID, providerID string
	if err := admin.QueryRow(ctx, `SELECT endpoint.public_id::TEXT, device.public_id::TEXT
        FROM mesh.private_endpoint AS endpoint
        JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
        JOIN mesh.resource_device_target AS target ON target.resource_id = contract.resource_id
            AND target.target_generation = contract.target_generation
        JOIN mesh.device AS device ON device.id = target.device_id
        JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
        WHERE imported.public_id = $1::UUID`, importedID.String()).Scan(&endpointID, &providerID); err != nil {
		t.Fatal(err)
	}
	consumerID := integrationPublicID("01890fa1-0000-7000-8000-", 2301)
	args := []any{endpointID, consumerID, int64(1), int64(1), int64(1), deviceAliasPublicIDs(3400)}
	for _, role := range []string{"mesh_runtime", "mesh_worker", "mesh_observer", "mesh_share_writer"} {
		var read, write, reserve, quarantine bool
		if err := admin.QueryRow(ctx, `SELECT
            has_table_privilege($1, 'mesh.device_alias_lease', 'SELECT'),
            has_table_privilege($1, 'mesh.device_alias_lease', 'INSERT'),
            has_function_privilege($1, 'mesh_ops.reserve_device_aliases_internal_v1(uuid,uuid,bigint,bigint,bigint,uuid[])', 'EXECUTE'),
            has_function_privilege($1, 'mesh_ops.quarantine_device_aliases_internal_v1(uuid,bigint,timestamp with time zone)', 'EXECUTE')`, role).Scan(
			&read, &write, &reserve, &quarantine); err != nil {
			t.Fatal(err)
		}
		if read || write || reserve || quarantine {
			t.Fatalf("unexpected alias authority for %s", role)
		}
	}
	before := deviceAliasSnapshot(ctx, t, admin, endpointID)
	for _, fault := range []struct {
		name, sql, code string
		argumentIndex   int
		value           any
	}{
		{name: "stale provider epoch", code: "40001", argumentIndex: 3, value: int64(2)},
		{name: "foreign consumer", code: "40001", argumentIndex: 1, value: providerID},
		{name: "stale endpoint generation", code: "40001", argumentIndex: 2, value: int64(2)},
		{name: "null lease identity", code: "22023", argumentIndex: 5, value: []any{nil, nil, nil, nil}},
		{name: "missing source family", code: "MT001", argumentIndex: -1,
			sql: `UPDATE mesh.address_pool SET state='quarantined', version=version+1, updated_at=clock_timestamp() WHERE id=2298`},
		{name: "overlapping overlay pool", code: "23514", argumentIndex: -1,
			sql: `UPDATE mesh.address_pool SET prefix='100.64.3.0/29', version=version+1, updated_at=clock_timestamp() WHERE id=2297`},
		{name: "last family exhausted", code: "MT001", argumentIndex: -1,
			sql: `INSERT INTO mesh_ops.federation_alias_pool_cursor (address_pool_id,deployment_id,next_offset,updated_at)
                VALUES (2298,1,4294967296,clock_timestamp()) ON CONFLICT (address_pool_id)
                DO UPDATE SET next_offset=4294967296`},
	} {
		t.Run("alias "+fault.name, func(t *testing.T) {
			tx := beginDeviceAliasTransaction(ctx, t, admin, 3500)
			if fault.sql != "" {
				if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, fault.sql); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_migrator`); err != nil {
					t.Fatal(err)
				}
			}
			faultArgs := append([]any(nil), args...)
			if fault.argumentIndex >= 0 {
				faultArgs[fault.argumentIndex] = fault.value
			}
			_, err := readDeviceAliasRows(ctx, tx, faultArgs)
			requireDeviceAliasCode(t, err, fault.code)
			rollbackIntegrationTransaction(ctx, t, tx)
			if after := deviceAliasSnapshot(ctx, t, admin, endpointID); !reflect.DeepEqual(before, after) {
				t.Fatalf("failed alias allocation changed durable state: before=%v after=%v", before, after)
			}
		})
	}
	t.Run("alias explicit IPv6 profile", func(t *testing.T) {
		tx := beginDeviceAliasTransaction(ctx, t, admin, 3590)
		if _, err := tx.Exec(ctx, `RESET ROLE; UPDATE mesh.address_realm SET ipv4_enabled=FALSE,version=version+1,updated_at=clock_timestamp() WHERE id=399; SET LOCAL ROLE mesh_migrator`); err != nil {
			t.Fatal(err)
		}
		singleRows, err := readDeviceAliasRows(ctx, tx, args)
		if err != nil || len(singleRows) != 2 {
			t.Fatalf("explicit IPv6 aliases=%v error=%v", singleRows, err)
		}
		for _, row := range singleRows {
			if row.Family != 6 {
				t.Fatal("inferred a disabled address family")
			}
		}
		rollbackIntegrationTransaction(ctx, t, tx)
		if after := deviceAliasSnapshot(ctx, t, admin, endpointID); !reflect.DeepEqual(before, after) {
			t.Fatal("profile rollback changed authority")
		}
	})
	// Hold a winner's complete reservation. A second writer must wait for its
	// revision locks and fail at the caller's finite timeout, without partial IPs.
	winner := beginDeviceAliasTransaction(ctx, t, admin, 3600)
	if _, err := winner.Exec(ctx, `SELECT set_config('mesh.workspace_id','101',TRUE),set_config('mesh.network_id','201',TRUE),
        set_config('mesh.device_alias_deployment_id','999',TRUE),set_config('mesh.share_provider_workspace_id','101',TRUE),
        set_config('mesh.share_provider_network_id','201',TRUE),set_config('mesh.share_consumer_workspace_id','102',TRUE),
        set_config('mesh.share_consumer_network_id','202',TRUE)`); err != nil {
		t.Fatal(err)
	}
	rows, err := readDeviceAliasRows(ctx, winner, args)
	if err != nil {
		var postgresErr *pgconn.PgError
		if errors.As(err, &postgresErr) {
			t.Fatalf("reserve complete alias pair: %v stage=%s", err, postgresErr.Detail)
		}
		t.Fatalf("reserve complete alias pair: %v", err)
	}
	var scopesRestored bool
	if err := winner.QueryRow(ctx, `SELECT current_setting('mesh.workspace_id')='101' AND current_setting('mesh.network_id')='201'
        AND current_setting('mesh.device_alias_deployment_id')='999' AND current_setting('mesh.share_provider_workspace_id')='101'
        AND current_setting('mesh.share_provider_network_id')='201' AND current_setting('mesh.share_consumer_workspace_id')='102'
        AND current_setting('mesh.share_consumer_network_id')='202'`).Scan(&scopesRestored); err != nil {
		t.Fatal(err)
	}
	if !scopesRestored {
		t.Fatal("alias function leaked derived transaction scopes")
	}
	if len(rows) != 4 {
		t.Fatalf("alias rows=%d, want four", len(rows))
	}
	resourceAliases := make(map[int]string)
	sourceAliases := make(map[int]string)
	for _, row := range rows {
		if row.Epoch != 1 || row.Version != 1 {
			t.Fatalf("bad alias pin: %+v", row)
		}
		if row.Role == "resource" {
			resourceAliases[row.Family] = row.Address
		} else {
			sourceAliases[row.Family] = row.Address
		}
	}
	if resourceAliases[6] != "fd00:feed::1/128" || sourceAliases[6] != "fd00:feed:1::1/128" ||
		resourceAliases[4] != "100.96.0.1/32" || sourceAliases[4] != "100.96.0.9/32" {
		t.Fatalf("role-separated alias pair resource=%v source=%v", resourceAliases, sourceAliases)
	}
	contender, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := contender.Close(cleanupCtx); err != nil {
			t.Errorf("close alias contender: %v", err)
		}
	}()
	blocked := beginDeviceAliasTransaction(ctx, t, contender, 3601)
	if _, err := blocked.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = readDeviceAliasRows(ctx, blocked, args)
	requireDeviceAliasCode(t, err, "55P03")
	rollbackIntegrationTransaction(ctx, t, blocked)
	appendDeviceAliasEvidence(ctx, t, winner, endpointID, 3600, "both")
	if err := winner.Commit(ctx); err != nil {
		t.Fatalf("commit bilateral alias reservation: %v", err)
	}
	committed := deviceAliasSnapshot(ctx, t, admin, endpointID)
	replay := beginDeviceAliasTransaction(ctx, t, admin, 3610)
	replayArgs := append([]any(nil), args...)
	replayArgs[5] = deviceAliasPublicIDs(3410)
	replayRows, err := readDeviceAliasRows(ctx, replay, replayArgs)
	if err != nil || !reflect.DeepEqual(rows, replayRows) {
		t.Fatalf("exact owner replay=%v error=%v", replayRows, err)
	}
	if err := replay.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if after := deviceAliasSnapshot(ctx, t, admin, endpointID); !reflect.DeepEqual(committed, after) {
		t.Fatalf("idempotent alias retry changed state: before=%v after=%v", committed, after)
	}
	// A distinct consumer receives distinct source aliases and reuses the same
	// endpoint Resource aliases; no duplicate address owner is created.
	second := beginDeviceAliasTransaction(ctx, t, admin, 3620)
	secondArgs := append([]any(nil), args...)
	secondArgs[1], secondArgs[5] = integrationPublicID("01890fa1-0000-7000-8000-", 2302), deviceAliasPublicIDs(3420)
	secondRows, err := readDeviceAliasRows(ctx, second, secondArgs)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range secondRows {
		if row.Role == "resource" && row.Address != resourceAliases[row.Family] {
			t.Fatalf("Resource alias changed: %+v", row)
		}
		if row.Role == "consumer_source" && (row.Address == sourceAliases[row.Family] || row.Owner != 2302) {
			t.Fatalf("consumer source alias reused: %+v", row)
		}
	}
	appendDeviceAliasEvidence(ctx, t, second, endpointID, 3620, "both")
	if err := second.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// A valid mutation with only one Network's audit/outbox must fail at commit.
	beforeIncomplete := deviceAliasSnapshot(ctx, t, admin, endpointID)
	incomplete := beginDeviceAliasTransaction(ctx, t, admin, 3630)
	thirdArgs := append([]any(nil), args...)
	thirdArgs[1], thirdArgs[5] = integrationPublicID("01890fa1-0000-7000-8000-", 2303), deviceAliasPublicIDs(3430)
	if _, err := readDeviceAliasRows(ctx, incomplete, thirdArgs); err != nil {
		t.Fatal(err)
	}
	appendDeviceAliasEvidence(ctx, t, incomplete, endpointID, 3630, "consumer_only")
	requireDeviceAliasCode(t, incomplete.Commit(ctx), "23514")
	if after := deviceAliasSnapshot(ctx, t, admin, endpointID); !reflect.DeepEqual(beforeIncomplete, after) {
		t.Fatalf("incomplete bilateral evidence committed state: before=%v after=%v", beforeIncomplete, after)
	}
	wrongBatch := beginDeviceAliasTransaction(ctx, t, admin, 3640)
	if _, err := readDeviceAliasRows(ctx, wrongBatch, thirdArgs); err != nil {
		t.Fatal(err)
	}
	appendDeviceAliasEvidence(ctx, t, wrongBatch, endpointID, 3640, "wrong_batch")
	requireDeviceAliasCode(t, wrongBatch.Commit(ctx), "23514")
	if after := deviceAliasSnapshot(ctx, t, admin, endpointID); !reflect.DeepEqual(beforeIncomplete, after) {
		t.Fatal("wrong evidence batch committed")
	}
	assertDeviceAliasQuarantine(ctx, t, admin, endpointID, args)
}

func deviceAliasPublicIDs(base int64) []string {
	ids := make([]string, 4)
	for index := range ids {
		ids[index] = integrationPublicID("01890fa2-0000-7000-8000-", base+int64(index))
	}
	return ids
}

func beginDeviceAliasTransaction(ctx context.Context, t *testing.T, connection *pgx.Conn, marker int64) pgx.Tx {
	t.Helper()
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := tx.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback aliases: %v", err)
		}
	})
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_migrator; SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
		t.Fatal(err)
	}
	setIntegrationChange(ctx, t, tx, integrationPublicID("01890fa3-0000-7000-8000-", marker))
	return tx
}

func readDeviceAliasRows(ctx context.Context, tx pgx.Tx, args []any) ([]deviceAliasFixtureRow, error) {
	rows, err := tx.Query(ctx, reserveDeviceAliasesSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]deviceAliasFixtureRow, 0, 4)
	for rows.Next() {
		var row deviceAliasFixtureRow
		if err := rows.Scan(&row.Role, &row.Family, &row.Address, &row.Owner, &row.Epoch, &row.Version); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func requireDeviceAliasCode(t *testing.T, err error, want string) {
	t.Helper()
	var postgresErr *pgconn.PgError
	if !errors.As(err, &postgresErr) || postgresErr.Code != want {
		t.Fatalf("alias error=%v, want SQLSTATE %s", err, want)
	}
}

func deviceAliasSnapshot(ctx context.Context, t *testing.T, connection *pgx.Conn, endpointID string) []int64 {
	t.Helper()
	var leaseCount, cursorVersions, cursorOffsets, networkRevision, sharingRevision, eventCount, outboxCount int64
	if err := connection.QueryRow(ctx, `SELECT
        (SELECT count(*) FROM mesh.device_alias_lease AS lease JOIN mesh.private_endpoint AS endpoint ON endpoint.id=lease.private_endpoint_id WHERE endpoint.public_id=$1::UUID),
        (SELECT coalesce(sum(version),0)::BIGINT FROM mesh_ops.federation_alias_pool_cursor),
        (SELECT coalesce(sum(next_offset),0)::BIGINT FROM mesh_ops.federation_alias_pool_cursor),
        (SELECT sum(network_revision)::BIGINT FROM mesh_ops.network_revision WHERE network_id IN (202,203)),
        (SELECT sum(sharing_revision)::BIGINT FROM mesh_ops.network_revision WHERE network_id IN (202,203)),
        (SELECT count(*) FROM mesh_audit.audit_event_identity), (SELECT count(*) FROM mesh_ops.outbox_event)`, endpointID).Scan(
		&leaseCount, &cursorVersions, &cursorOffsets, &networkRevision, &sharingRevision, &eventCount, &outboxCount); err != nil {
		t.Fatal(err)
	}
	return []int64{leaseCount, cursorVersions, cursorOffsets, networkRevision, sharingRevision, eventCount, outboxCount}
}

func appendDeviceAliasEvidence(ctx context.Context, t *testing.T, tx pgx.Tx, endpointID string, marker int64, evidenceMode string) {
	t.Helper()
	var members string
	if err := tx.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('public_id',lease.public_id,
        'version',mutation.after_version) ORDER BY lease.public_id)::TEXT
        FROM mesh_audit.authority_mutation AS mutation
        JOIN mesh.device_alias_lease AS lease ON lease.public_id=mutation.row_public_id
        JOIN mesh.private_endpoint AS endpoint ON endpoint.id=lease.private_endpoint_id
        WHERE endpoint.public_id=$1::UUID AND mutation.aggregate_kind='device_alias_lease'
          AND mutation.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT`, endpointID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if evidenceMode == "wrong_batch" {
		members = "[]"
	}
	// Lock audit streams in Network scope order, after all authority/address locks.
	for index, streamID := range []int64{202, 203} {
		if evidenceMode == "consumer_only" && index == 1 {
			break
		}
		var revision, sharingRevision, version int64
		var aggregateID string
		column, sharingColumn := "consumer_network_revision", "consumer_sharing_revision"
		if streamID == 203 {
			column, sharingColumn = "provider_network_revision", "provider_sharing_revision"
		}
		// Identifiers are a fixed internal allowlist, never request input.
		query := fmt.Sprintf(`SELECT lease.%s, lease.%s, lease.public_id::TEXT, lease.version FROM mesh.device_alias_lease AS lease
            JOIN mesh.private_endpoint AS endpoint ON endpoint.id=lease.private_endpoint_id
            JOIN mesh_audit.authority_mutation AS mutation ON mutation.row_public_id=lease.public_id
                AND mutation.aggregate_kind='device_alias_lease' AND mutation.after_version=lease.version
                AND mutation.transaction_id=(pg_current_xact_id()::TEXT)::BIGINT
            WHERE endpoint.public_id=$1::UUID ORDER BY lease.id LIMIT 1`, column, sharingColumn)
		if err := tx.QueryRow(ctx, query, endpointID).Scan(&revision, &sharingRevision, &aggregateID, &version); err != nil {
			t.Fatal(err)
		}
		auditPayload, err := json.Marshal(map[string]any{
			"endpoint_public_id": endpointID, "mutated_leases": json.RawMessage(members),
			"network_revision": revision, "sharing_revision": sharingRevision,
		})
		if err != nil {
			t.Fatal(err)
		}
		outboxPayload, err := json.Marshal(map[string]any{
			"endpoint_public_id": endpointID, "network_revision": revision,
			"subsystem": "sharing", "subsystem_revision": sharingRevision,
		})
		if err != nil {
			t.Fatal(err)
		}
		appendIntegrationAuthorityEvidence(ctx, t, tx, authorityEvidenceFixture{
			changePublicID: integrationPublicID("01890fa3-0000-7000-8000-", marker),
			eventPublicID:  integrationPublicID("01890fa4-0000-7000-8000-", marker+int64(index)),
			outboxPublicID: integrationPublicID("01890fa5-0000-7000-8000-", marker+int64(index)),
			streamID:       streamID, aggregateKind: "device_alias_lease", aggregatePublicID: aggregateID,
			aggregateVersion: version, networkRevision: revision, action: "device_alias.reserved",
			permission: "system.reconcile", outboxEventClass: "network.revision.advanced",
			auditPayload:  string(auditPayload),
			outboxPayload: string(outboxPayload),
		})
	}
}

func assertDeviceAliasQuarantine(ctx context.Context, t *testing.T, admin *pgx.Conn, endpointID string, args []any) {
	t.Helper()
	short := beginDeviceAliasTransaction(ctx, t, admin, 3640)
	_, err := short.Exec(ctx, `SELECT mesh_ops.quarantine_device_aliases_internal_v1($1::UUID,1,clock_timestamp()+interval '1 hour')`, endpointID)
	requireDeviceAliasCode(t, err, "23514")
	rollbackIntegrationTransaction(ctx, t, short)
	quarantine := beginDeviceAliasTransaction(ctx, t, admin, 3650)
	var count int64
	if err := quarantine.QueryRow(ctx, `SELECT mesh_ops.quarantine_device_aliases_internal_v1($1::UUID,1,clock_timestamp()+interval '48 hours')`, endpointID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("quarantined aliases=%d, want 6", count)
	}
	appendDeviceAliasEvidence(ctx, t, quarantine, endpointID, 3650, "both")
	if err := quarantine.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := deviceAliasSnapshot(ctx, t, admin, endpointID)
	retry := beginDeviceAliasTransaction(ctx, t, admin, 3660)
	_, err = readDeviceAliasRows(ctx, retry, args)
	requireDeviceAliasCode(t, err, "40001")
	rollbackIntegrationTransaction(ctx, t, retry)
	duplicate := beginDeviceAliasTransaction(ctx, t, admin, 3661)
	_, err = duplicate.Exec(ctx, `SELECT set_config('mesh.device_alias_deployment_id','1',TRUE);
        INSERT INTO mesh.device_alias_lease OVERRIDING SYSTEM VALUE
        SELECT (jsonb_populate_record(NULL::mesh.device_alias_lease, to_jsonb(lease)
            || jsonb_build_object('id',999999,'public_id','01890fa2-0000-7000-8000-000000003499',
                'owner_device_id',2303,'node_public_key',(SELECT public_key FROM mesh.device_node_key_epoch WHERE device_id=2303 AND epoch=1),'state','reserved','quarantine_until',NULL,'version',1,'updated_at',lease.created_at))).*
        FROM mesh.device_alias_lease AS lease WHERE alias_role='consumer_source' AND family=4 AND owner_device_id=2301`)
	requireDeviceAliasCode(t, err, "23505") // Quarantine still owns the address.
	rollbackIntegrationTransaction(ctx, t, duplicate)
	earlyRelease := beginDeviceAliasTransaction(ctx, t, admin, 3662)
	_, err = earlyRelease.Exec(ctx, `UPDATE mesh.device_alias_lease SET state='released',version=version+1,
        updated_at=clock_timestamp(),provider_network_revision=provider_network_revision+1,
        provider_sharing_revision=provider_sharing_revision+1,consumer_network_revision=consumer_network_revision+1,
        consumer_sharing_revision=consumer_sharing_revision+1 WHERE owner_device_id=2301`)
	requireDeviceAliasCode(t, err, "23514")
	rollbackIntegrationTransaction(ctx, t, earlyRelease)
	if after := deviceAliasSnapshot(ctx, t, admin, endpointID); !reflect.DeepEqual(before, after) {
		t.Fatal("quarantine failure changed state")
	}
}

func seedDeviceAliasAuthority(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var consumerRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision+1 FROM mesh_ops.network_revision WHERE workspace_id=102 AND network_id=202`).Scan(&consumerRevision); err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890fa3-0000-7000-8000-000000002290", eventPublicID: "01890fa4-0000-7000-8000-000000002290",
		outboxPublicID: "01890fa5-0000-7000-8000-000000002290", streamID: 1, aggregateKind: "address_realm",
		aggregatePublicID: "01890f00-0000-7000-8000-000000000399", aggregateVersion: 2,
		action: "device_alias.pools_configured", permission: "system.bootstrap", outboxEventClass: "deployment.changed",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE mesh.address_realm SET ipv4_enabled=TRUE,version=version+1,updated_at=clock_timestamp() WHERE id=399;
            INSERT INTO mesh.address_pool (id,public_id,deployment_id,address_realm_id,purpose,prefix,family,state)
            OVERRIDING SYSTEM VALUE VALUES
            (2296,'01890fa0-0000-7000-8000-000000002296',1,399,'federation_resource_alias','100.96.0.0/29',4,'active'),
            (2297,'01890fa0-0000-7000-8000-000000002297',1,399,'federation_consumer_alias','100.96.0.8/29',4,'active'),
            (2298,'01890fa0-0000-7000-8000-000000002298',1,399,'federation_consumer_alias','fd00:feed:1::/96',6,'active')`); err != nil {
			t.Fatal(err)
		}
	})
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890fa3-0000-7000-8000-000000002299", eventPublicID: "01890fa4-0000-7000-8000-000000002299",
		outboxPublicID: "01890fa5-0000-7000-8000-000000002299", streamID: 202, aggregateKind: "device", networkRevision: consumerRevision,
		aggregatePublicID: "01890fa1-0000-7000-8000-000000002301", aggregateVersion: 1,
		action: "device.registered", permission: "system.bootstrap", outboxEventClass: "network.inventory.changed",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE mesh_ops.network_revision SET network_revision=network_revision+1,inventory_revision=inventory_revision+1,updated_at=clock_timestamp() WHERE workspace_id=102 AND network_id=202;
            INSERT INTO mesh.enrollment_profile (id,public_id,workspace_id,network_id,created_by_principal_id,
            display_name,name_key,node_lifetime_seconds,ephemeral_mode,credential_use_policy,credential_max_uses,state)
            OVERRIDING SYSTEM VALUE VALUES (2299,'01890fa0-0000-7000-8000-000000002299',102,202,11,
            'Alias test enrollment','alias-test',3600,'persistent','bounded',10,'active')`); err != nil {
			t.Fatal(err)
		}
		for offset := int64(0); offset < 3; offset++ {
			id := int64(2301) + offset
			publicID := integrationPublicID("01890fa1-0000-7000-8000-", id)
			if _, err := tx.Exec(ctx, `INSERT INTO mesh.device (id,public_id,workspace_id,network_id,enrollment_profile_id,
                owner_principal_id,custodian_principal_id,registered_by_kind,registered_by_principal_id,
                hostname,hostname_key,is_ephemeral,expires_at,state)
                OVERRIDING SYSTEM VALUE VALUES ($1,$2::UUID,102,202,2299,11,11,'principal',11,$3,$3,FALSE,
                clock_timestamp()+interval '1 hour','active')`, id, publicID, fmt.Sprintf("alias-consumer-%d.example", id)); err != nil {
				t.Fatal(err)
			}
			for index, table := range []string{"device_machine_key_epoch", "device_node_key_epoch"} {
				material := filledIntegrationKey(byte(0xd1 + offset*2 + int64(index)))
				query := fmt.Sprintf(`INSERT INTO mesh.%s (public_id,workspace_id,network_id,device_id,epoch,public_key,
                    fingerprint,valid_from,state) VALUES ($1::UUID,102,202,$2,1,$3,$3,clock_timestamp(),'active')`, table)
				if _, err := tx.Exec(ctx, query, integrationPublicID("01890fa6-0000-7000-8000-", id*2+int64(index)), id, material[:]); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
