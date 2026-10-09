//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/sharing"
)

// assertSameWorkspaceAliasAllocation proves Network-scoped alias uniqueness on
// a live same-Workspace endpoint: its Resource Alias is unique in both
// participating Networks, while an unrelated Network pair may reuse an address
// that another provider Network retains.
func assertSameWorkspaceAliasAllocation(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.Contract) {
	t.Helper()
	var endpointID, poolID, deploymentID int64
	var resourceAlias string
	if err := admin.QueryRow(ctx, `SELECT endpoint.id, lease.address_pool_id, endpoint.deployment_id,
            pg_catalog.host(endpoint.resource_alias)
        FROM mesh.private_endpoint AS endpoint
        JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
        JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
        WHERE contract.public_id = $1::UUID AND endpoint.state = 'provisioning'
          AND endpoint.provider_workspace_id = endpoint.consumer_workspace_id`, contract.ID().String()).Scan(
		&endpointID, &poolID, &deploymentID, &resourceAlias,
	); err != nil {
		t.Fatalf("read same-Workspace alias endpoint: %v", err)
	}
	var collisions int
	if err := admin.QueryRow(ctx, `SELECT count(*)::INTEGER FROM mesh.federation_alias_lease AS lease
        WHERE lease.state IN ('reserved', 'active') AND pg_catalog.host(lease.resource_alias) = $1
          AND lease.id <> (SELECT alias_lease_id FROM mesh.private_endpoint WHERE id = $2)
          AND (lease.provider_network_id IN (203, 204) OR lease.consumer_network_id IN (203, 204))`,
		resourceAlias, endpointID).Scan(&collisions); err != nil {
		t.Fatal(err)
	}
	if collisions != 0 {
		t.Fatalf("same-Workspace Resource Alias %s collides in a participating Network", resourceAlias)
	}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, tx)
	var reused string
	var retainedInProvider, retainedHere bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.host(mesh_ops.allocate_network_scoped_alias_v1($1, $2, 201, 999999))`,
		deploymentID, poolID).Scan(&reused); err != nil {
		t.Fatalf("allocate for an unrelated Network pair: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT
            EXISTS (SELECT 1 FROM mesh.federation_alias_lease AS lease
                WHERE lease.state IN ('reserved', 'active') AND pg_catalog.host(lease.resource_alias) = $1
                  AND (lease.provider_network_id = 203 OR lease.consumer_network_id = 203)),
            mesh_ops.device_alias_address_retained_v1($2, $1::INET, 201, 999999, NULL, NULL)`,
		reused, deploymentID).Scan(&retainedInProvider, &retainedHere); err != nil {
		t.Fatal(err)
	}
	if !retainedInProvider || retainedHere {
		t.Fatalf("allocator chose %s: retained in Network 203=%t, in the requested Networks=%t; want reuse of a 203 alias",
			reused, retainedInProvider, retainedHere)
	}
	var sameNetworkConflict bool
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.device_alias_address_retained_v1($1, $2::INET, 204, 201, NULL, NULL)`,
		deploymentID, resourceAlias).Scan(&sameNetworkConflict); err != nil {
		t.Fatal(err)
	}
	if !sameNetworkConflict {
		t.Fatal("a retained consumer-Network alias was reported free for another pair touching that Network")
	}
	for _, role := range []struct {
		name string
		want bool
	}{
		{"mesh_runtime", false}, {"mesh_worker", false}, {"mesh_observer", false},
		{"mesh_share_writer", true}, {"mesh_device_alias_writer", true},
	} {
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT has_function_privilege($1,
            'mesh_ops.allocate_network_scoped_alias_v1(bigint,bigint,bigint,bigint)', 'EXECUTE')`, role.name).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed != role.want {
			t.Fatalf("%s alias allocator EXECUTE = %t, want %t", role.name, allowed, role.want)
		}
	}
}

// assertSameWorkspaceAliasMapProjection proves the Network-based alias reader
// gives each side of a same-Workspace share its own local alias and the peer's
// alias as the only remote route. A Workspace comparison cannot tell these two
// Networks apart.
func assertSameWorkspaceAliasMapProjection(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.Contract) {
	t.Helper()
	var endpointID, consumerID string
	var generation, providerEpoch, consumerEpoch int64
	if err := admin.QueryRow(ctx, `SELECT endpoint.public_id::TEXT, endpoint.generation,
            provider.current_node_key_epoch, consumer.public_id::TEXT, consumer.current_node_key_epoch
        FROM mesh.private_endpoint AS endpoint
        JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
        JOIN mesh.resource_device_target AS target ON target.resource_id = contract.resource_id
         AND target.target_generation = contract.target_generation AND target.state = 'active'
        JOIN mesh.device AS provider ON provider.id = target.device_id
        JOIN LATERAL (SELECT device.* FROM mesh.device AS device
            WHERE device.workspace_id = endpoint.consumer_workspace_id
              AND device.network_id = endpoint.consumer_network_id
              AND device.state = 'active' AND device.deleted_at IS NULL
              AND device.expires_at > clock_timestamp()
            ORDER BY device.id LIMIT 1) AS consumer ON TRUE
        WHERE contract.public_id = $1::UUID`, contract.ID().String()).Scan(
		&endpointID, &generation, &providerEpoch, &consumerID, &consumerEpoch,
	); err != nil {
		t.Fatalf("read same-Workspace alias map fixture: %v", err)
	}
	tx := beginDeviceAliasTransaction(ctx, t, admin, 4600)
	defer rollbackIntegrationTransaction(ctx, t, tx)
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, seedAliasMapIntentSQL, pgx.QueryExecModeSimpleProtocol, endpointID, consumerID); err != nil {
		t.Fatalf("seed same-Workspace alias intent: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_migrator`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `SELECT alias_role, pg_catalog.host(address) || CASE family WHEN 4 THEN '/32' ELSE '/128' END
        FROM mesh_ops.reserve_device_aliases_internal_v2($1::UUID, $2::UUID, $3, $4, $5, $6::UUID[])
        ORDER BY family`, endpointID, consumerID, generation, providerEpoch, consumerEpoch, deviceAliasPublicIDs(4610))
	if err != nil {
		t.Fatalf("reserve same-Workspace aliases: %v", err)
	}
	var resourceAliases, sourceAliases []string
	for rows.Next() {
		var role, address string
		if err := rows.Scan(&role, &address); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if role == "resource" {
			resourceAliases = append(resourceAliases, address)
		} else {
			sourceAliases = append(sourceAliases, address)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("reserve same-Workspace aliases: %v", err)
	}
	if len(resourceAliases) != 2 || len(sourceAliases) != 2 {
		t.Fatalf("same-Workspace aliases resource=%v source=%v, want both families", resourceAliases, sourceAliases)
	}
	// The worker reserves in its own committed transaction and maps read later;
	// this rolled-back fixture backdates the leases to the transaction start so
	// the reader's created-before-snapshot pin holds.
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.device_alias_lease AS lease
        SET created_at = transaction_timestamp() - interval '1 second',
            updated_at = transaction_timestamp() - interval '1 second'
        FROM mesh.private_endpoint AS endpoint
        WHERE endpoint.id = lease.private_endpoint_id AND endpoint.public_id = $1::UUID`, endpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, insertAliasReadinessSQL, endpointID, consumerID); err != nil {
		t.Fatalf("insert same-Workspace readiness: %v", err)
	}
	for _, perspective := range []struct {
		name          string
		network       int64
		local, remote []string
	}{
		{name: "consumer", network: 204, local: sourceAliases, remote: resourceAliases},
		{name: "provider", network: 203, local: resourceAliases, remote: sourceAliases},
	} {
		var machine, key []byte
		if err := tx.QueryRow(ctx, `SELECT machine.fingerprint, node_key.public_key
            FROM mesh.device AS device
            JOIN mesh.device_machine_key_epoch AS machine ON machine.device_id = device.id
             AND machine.epoch = device.current_machine_key_epoch
            JOIN mesh.device_node_key_epoch AS node_key ON node_key.device_id = device.id
             AND node_key.epoch = device.current_node_key_epoch
            WHERE device.id = CASE WHEN $1::BIGINT = 204
                THEN (SELECT id FROM mesh.device WHERE public_id = $2::UUID)
                ELSE (SELECT target.device_id FROM mesh.trust_contract AS contract
                    JOIN mesh.resource_device_target AS target ON target.resource_id = contract.resource_id
                     AND target.target_generation = contract.target_generation AND target.state = 'active'
                    WHERE contract.public_id = $3::UUID) END`,
			perspective.network, consumerID, contract.ID().String()).Scan(&machine, &key); err != nil {
			t.Fatal(err)
		}
		setIntegrationScope(ctx, t, tx, 103, perspective.network)
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		assertReachableAliasMapMatches(ctx, t, tx, machine, key)
		var encoded []string
		edgeRows, err := tx.Query(ctx, `SELECT edge::TEXT FROM mesh_ops.load_device_alias_map_edges_v3($1::BYTEA,$2::BYTEA,257) AS edge`, machine, key)
		if err != nil {
			t.Fatalf("%s alias map: %v", perspective.name, err)
		}
		for edgeRows.Next() {
			var value string
			if err := edgeRows.Scan(&value); err != nil {
				edgeRows.Close()
				t.Fatal(err)
			}
			encoded = append(encoded, value)
		}
		edgeRows.Close()
		if err := edgeRows.Err(); err != nil {
			t.Fatalf("%s alias map: %v", perspective.name, err)
		}
		if len(encoded) != 1 {
			if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
				t.Fatal(err)
			}
			var diagnostic string
			if err := tx.QueryRow(ctx, `SELECT jsonb_build_object(
                'endpoint', (SELECT row_to_json(e) FROM (SELECT e.state, e.mode, e.generation, e.expires_at > now() AS live FROM mesh.private_endpoint e WHERE e. public_id=$1::UUID) e),
                'legacy', (SELECT row_to_json(l) FROM (SELECT l.state, l.generation, l.resource_alias = p.resource_alias AS same FROM mesh.federation_alias_lease l JOIN mesh.private_endpoint p ON p.alias_lease_id=l.id WHERE p.public_id=$1::UUID) l),
                'name', (SELECT n.state FROM mesh.imported_resource_access_name n JOIN mesh.private_endpoint p ON p.access_name_id=n.id WHERE p.public_id=$1::UUID),
                'readiness', (SELECT count(*) FROM mesh.device_alias_client_readiness r JOIN mesh.private_endpoint p ON p.id=r.private_endpoint_id WHERE p.public_id=$1::UUID AND r.state='ready'),
                'leases', (SELECT jsonb_agg(jsonb_build_object('role',d.alias_role,'family',d.family,'state',d.state)) FROM mesh.device_alias_lease d JOIN mesh.private_endpoint p ON p.id=d.private_endpoint_id WHERE p.public_id=$1::UUID),
                'compat', (SELECT count(*) FROM mesh.device_alias_client_version WHERE alias_version=1),
                'rules', (SELECT count(*) FROM mesh.compiled_policy_imported_resource_destination r JOIN mesh.private_endpoint p ON p.imported_resource_id=r.imported_resource_id WHERE p.public_id=$1::UUID),
                'contract', (SELECT row_to_json(c) FROM (SELECT c.state, c.expires_at > now() AS live, c.version = p.contract_version AS pinned FROM mesh.trust_contract c JOIN mesh.private_endpoint p ON p.trust_contract_id=c.id WHERE p.public_id=$1::UUID) c),
                'profile', (SELECT direct_sharing_ceiling_profile FROM mesh.deployment WHERE id=1),
                'realm', (SELECT row_to_json(r) FROM (SELECT ipv4_enabled, ipv6_enabled FROM mesh.address_realm WHERE kind='federation_alias') r),
                'consumer', (SELECT row_to_json(c) FROM (SELECT d.id, d.state, d.created_at <= now() AS born, d.expires_at > now() AS live,
                    o.state AS owner_state, o.deployment_id AS owner_deployment,
                    (SELECT bool_and(m.valid_from <= now() AND m.state='active') FROM mesh.device_machine_key_epoch m WHERE m.device_id=d.id AND m.epoch=d.current_machine_key_epoch) AS machine_ok,
                    (SELECT bool_and(k.valid_from <= now() AND k.state='active') FROM mesh.device_node_key_epoch k WHERE k.device_id=d.id AND k.epoch=d.current_node_key_epoch) AS node_ok,
                    (SELECT count(*) FROM mesh.device_alias_client_version v WHERE v.device_id=d.id AND v.alias_version=1 AND v.session_generation=d.session_generation AND v.node_key_epoch=d.current_node_key_epoch) AS compat_ok,
                    (SELECT count(*) FROM mesh.compiled_policy_imported_resource_destination r WHERE r.source_device_id=d.id) AS rules
                    FROM mesh.device d JOIN mesh.principal o ON o.id=d.owner_principal_id WHERE d.public_id=$2::UUID) c),
                'release', (SELECT jsonb_agg(jsonb_build_object('rev',r.policy_revision,'state',r.state)) FROM mesh.policy_release r WHERE r.workspace_id=103 AND r.network_id=204 AND r.state='active'),
                'consumer_revision', (SELECT policy_revision FROM mesh_ops.network_revision WHERE workspace_id=103 AND network_id=204),
                'rule_pins', (SELECT row_to_json(x) FROM (SELECT r.policy_revision, r.trust_contract_version, r.resource_export_version, r.imported_resource_version, r.contract_expires_at = c.expires_at AS expiry_ok, r.constraint_hash = c.constraint_hash AS hash_ok, r.provider_sharing_revision, r.consumer_sharing_revision, r.provider_inventory_revision FROM mesh.compiled_policy_imported_resource_destination r JOIN mesh.private_endpoint p ON p.imported_resource_id=r.imported_resource_id JOIN mesh.trust_contract c ON c.id=p.trust_contract_id WHERE p.public_id=$1::UUID) x)
            )::TEXT`, endpointID, consumerID).Scan(&diagnostic); err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s alias map edges=%d, want 1; evidence %s", perspective.name, len(encoded), diagnostic)
		}
		var record struct {
			Peer struct {
				Addresses []string `json:"addresses"`
			} `json:"peer"`
			Aliases struct {
				LocalAddresses  []string `json:"local_addresses"`
				RemoteAddresses []string `json:"remote_addresses"`
			} `json:"aliases"`
		}
		if err := json.Unmarshal([]byte(encoded[0]), &record); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(record.Aliases.LocalAddresses, perspective.local) ||
			!slices.Equal(record.Aliases.RemoteAddresses, perspective.remote) ||
			!slices.Equal(record.Peer.Addresses, perspective.remote) {
			t.Fatalf("%s alias map local=%v remote=%v peer=%v, want local=%v remote=%v",
				perspective.name, record.Aliases.LocalAddresses, record.Aliases.RemoteAddresses,
				record.Peer.Addresses, perspective.local, perspective.remote)
		}
		if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
	}
}
