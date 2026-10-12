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
	// Two providers sharing into one Network: an allocation for another
	// provider (201) into a Network this endpoint already uses (204) never
	// returns the retained alias, nor any alias retained in either Network.
	for _, pair := range [][2]int64{{201, 204}, {204, 201}, {201, 203}} {
		var allocated string
		var retained bool
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.host(a.address), mesh_ops.device_alias_address_retained_v1($1, a.address, $3, $4, NULL, NULL)
            FROM (SELECT mesh_ops.allocate_network_scoped_alias_v1($1, $2, $3, $4) AS address) AS a`,
			deploymentID, poolID, pair[0], pair[1]).Scan(&allocated, &retained); err != nil {
			t.Fatalf("allocate for Networks %v: %v", pair, err)
		}
		if allocated == resourceAlias || retained {
			t.Fatalf("Networks %v were given %s, retained %t (endpoint alias %s)", pair, allocated, retained, resourceAlias)
		}
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
	var consumerDevice int64
	var consumerMachine, consumerKey []byte
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
		var deviceID int64
		var machine, key []byte
		if err := tx.QueryRow(ctx, `SELECT device.id, machine.fingerprint, node_key.public_key
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
			perspective.network, consumerID, contract.ID().String()).Scan(&deviceID, &machine, &key); err != nil {
			t.Fatal(err)
		}
		setIntegrationScope(ctx, t, tx, 103, perspective.network)
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		assertReachableAliasMapMatches(ctx, t, tx, machine, key)
		assertNetworkSharing(ctx, t, tx, perspective.name, true)
		assertSharingBinds(ctx, t, tx, perspective.name, deviceID, true)
		assertSharingDependencies(ctx, t, tx, perspective.name, "v2", machine, key, 1)
		if perspective.network == 204 {
			consumerDevice, consumerMachine, consumerKey = deviceID, machine, key
		}
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
	// A consumer Device that is no rule source keeps the shared map view: it
	// leaves the share-bound set and gets no dependency from v2 (v1 gave every
	// consumer Device one). The compiled rules go only in this rolled-back
	// transaction.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mesh.compiled_policy_imported_resource_destination
        WHERE workspace_id = 103 AND network_id = 204`); err != nil {
		t.Fatalf("drop the consumer rules: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	setIntegrationScope(ctx, t, tx, 103, 204)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	assertSharingBinds(ctx, t, tx, "consumer without a rule", consumerDevice, false)
	assertSharingDependencies(ctx, t, tx, "consumer without a rule", "v2", consumerMachine, consumerKey, 0)
	assertSharingDependencies(ctx, t, tx, "consumer without a rule", "v1", consumerMachine, consumerKey, 1)
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	// Once every contract of both Networks has ended, neither takes part in
	// a share and their Devices may use the shared map view again.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.trust_contract
        SET state = 'revoked', ended_at = GREATEST(created_at, clock_timestamp()),
            updated_at = GREATEST(created_at, clock_timestamp())
        WHERE state IN ('activating', 'active')
          AND ((provider_workspace_id = 103 AND provider_network_id IN (203, 204))
            OR (consumer_workspace_id = 103 AND consumer_network_id IN (203, 204)))`); err != nil {
		t.Fatalf("end the same-Workspace contracts: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct {
		name    string
		network int64
	}{{name: "consumer after revoke", network: 204}, {name: "provider after revoke", network: 203}} {
		setIntegrationScope(ctx, t, tx, 103, scope.network)
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		assertNetworkSharing(ctx, t, tx, scope.name, false)
		assertSharingBinds(ctx, t, tx, scope.name, -1, false)
		if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
	}
}

// assertNetworkSharing checks what the shared map view reads about the
// scoped Network taking part in a Device share (schema 145).
func assertNetworkSharing(ctx context.Context, t *testing.T, tx pgx.Tx, name string, want bool) {
	t.Helper()
	var sharing bool
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.map_network_has_sharing_v1()`).Scan(&sharing); err != nil {
		t.Fatalf("%s Network sharing: %v", name, err)
	}
	if sharing != want {
		t.Fatalf("%s Network sharing = %t, want %t", name, sharing, want)
	}
}

// assertSharingBinds checks the share-bound Device set of the scoped Network
// (schema 146): whether it lists device, or with device -1 whether it is
// empty.
func assertSharingBinds(ctx context.Context, t *testing.T, tx pgx.Tx, name string, device int64, want bool) {
	t.Helper()
	var devices []int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(device_id), '{}')
        FROM mesh_ops.map_network_sharing_devices_v1(1000)`).Scan(&devices); err != nil {
		t.Fatalf("%s share-bound Devices: %v", name, err)
	}
	if device < 0 {
		if (len(devices) != 0) != want {
			t.Fatalf("%s share-bound Devices = %v, want any=%t", name, devices, want)
		}
		return
	}
	if slices.Contains(devices, device) != want {
		t.Fatalf("%s share-bound Devices = %v, want %d listed=%t", name, devices, device, want)
	}
}

// assertSharingDependencies counts the remote Networks the dependency
// reader of version gives the authenticated Device.
func assertSharingDependencies(
	ctx context.Context, t *testing.T, tx pgx.Tx, name, version string, machine, key []byte, want int,
) {
	t.Helper()
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.load_device_sharing_dependencies_`+version+
		`($1::BYTEA, $2::BYTEA, 257)`, machine, key).Scan(&count); err != nil {
		t.Fatalf("%s sharing dependencies %s: %v", name, version, err)
	}
	if count != want {
		t.Fatalf("%s sharing dependencies %s = %d, want %d", name, version, count, want)
	}
	if version == "v2" {
		// Schema 147 returns v2's dependencies below its limit; a smaller
		// limit bounds the contracts visited and ends with the marker.
		read := func(query string, limit int) []string {
			rows, err := tx.Query(ctx, query, machine, key, limit)
			if err != nil {
				t.Fatalf("%s sharing dependencies: %v", name, err)
			}
			defer rows.Close()
			var values []string
			for rows.Next() {
				var value string
				if err := rows.Scan(&value); err != nil {
					t.Fatal(err)
				}
				values = append(values, value)
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("%s sharing dependencies: %v", name, err)
			}
			return values
		}
		const v2 = `SELECT d::TEXT FROM mesh_ops.load_device_sharing_dependencies_v2($1::BYTEA, $2::BYTEA, $3::INTEGER) AS d`
		const v3 = `SELECT d::TEXT FROM mesh_ops.load_device_sharing_dependencies_v3($1::BYTEA, $2::BYTEA, $3::INTEGER) AS d`
		previous := read(v2, 257)
		slices.Sort(previous)
		scaled := read(v3, 10000)
		slices.Sort(scaled)
		if !slices.Equal(previous, scaled) {
			t.Fatalf("%s sharing dependencies v3 = %v, v2 = %v", name, scaled, previous)
		}
		if want > 0 {
			bounded := read(v3, 1)
			if len(bounded) == 0 || len(bounded) > 2 || len(bounded) == 2 && bounded[1] != `{"limited": true}` ||
				!slices.Contains(previous, bounded[0]) {
				t.Fatalf("%s sharing dependencies v3 at limit 1 = %v", name, bounded)
			}
		}
	}
}
