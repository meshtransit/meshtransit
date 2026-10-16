//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// assertAliasWorkerKeepsResourceAliasAcrossKeyRotation: the provider Device
// rotates its node key while suspended (written the way the rotation writer
// does: the old epoch expires, a new one is current and the session
// advances). After resume and a claim on the new key, the endpoint gets the
// same Resource aliases back, now pinned to the new node key, and the share
// is back in the consumer's map.
func assertAliasWorkerKeepsResourceAliasAcrossKeyRotation(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, provider, consumer aliasMapIdentity) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_provider_rotation`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := tx.Exec(ctx, `RESET ROLE; ROLLBACK TO SAVEPOINT alias_provider_rotation`); err != nil {
			t.Fatal(err)
		}
	}()
	marker := int64(5100)
	resourceAliases := aliasLeaseAddresses(ctx, t, tx, endpointID, "resource", provider.id)
	if len(resourceAliases) != 2 {
		t.Fatalf("ready share Resource aliases %v, want both families", resourceAliases)
	}
	suspendAliasDevice(ctx, t, tx, provider.id)
	if modes := runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); len(modes) == 0 || modes[0] != "quarantine_resource" {
		t.Fatalf("worker on provider suspend ran %v, want quarantine_resource first", modes)
	}
	// Valid from before this transaction's start, so the map reader's
	// snapshot pin holds, as for the worker's backdated leases.
	execAsReplica(ctx, t, tx, `WITH provider AS (SELECT * FROM mesh.device WHERE public_id=$1::UUID),
 expired AS (UPDATE mesh.device_node_key_epoch AS key_epoch SET state='expired',
   valid_until=GREATEST(key_epoch.valid_from,transaction_timestamp()-INTERVAL '1 second'),
   version=key_epoch.version+1,updated_at=GREATEST(key_epoch.updated_at,transaction_timestamp())
  FROM provider WHERE key_epoch.device_id=provider.id AND key_epoch.epoch=provider.current_node_key_epoch RETURNING key_epoch.id),
 inserted AS (INSERT INTO mesh.device_node_key_epoch(public_id,workspace_id,network_id,device_id,epoch,public_key,fingerprint,valid_from,state,created_at,updated_at)
  SELECT $2::UUID,provider.workspace_id,provider.network_id,provider.id,provider.current_node_key_epoch+1,
   sha256(convert_to('alias provider rotation '||provider.public_id::TEXT,'UTF8')),
   sha256(sha256(convert_to('alias provider rotation '||provider.public_id::TEXT,'UTF8'))),
   transaction_timestamp()-INTERVAL '1 second','active',transaction_timestamp()-INTERVAL '1 second',transaction_timestamp()-INTERVAL '1 second'
  FROM provider RETURNING id)
UPDATE mesh.device AS device SET current_node_key_epoch=device.current_node_key_epoch+1,session_generation=device.session_generation+1,
 version=device.version+1,updated_at=clock_timestamp()
FROM provider WHERE device.id=provider.id AND EXISTS(SELECT 1 FROM expired) AND EXISTS(SELECT 1 FROM inserted)`,
		provider.id, "01890fb0-0000-7000-8000-000000005199")
	resumeAliasDevice(ctx, t, tx, provider.id)
	execAsReplica(ctx, t, tx, `UPDATE mesh.device_alias_client_version AS claim SET session_generation=device.session_generation,
  node_key_epoch=device.current_node_key_epoch,node_public_key=key_epoch.public_key,observed_at=clock_timestamp()
  FROM mesh.device AS device JOIN mesh.device_node_key_epoch AS key_epoch ON key_epoch.device_id=device.id AND key_epoch.epoch=device.current_node_key_epoch
  WHERE device.public_id=$1::UUID AND claim.device_id=device.id`, provider.id)
	if modes := runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); !slices.Equal(modes, []string{"reserve", "ready"}) {
		t.Fatalf("worker after provider key rotation ran %v, want reserve then ready", modes)
	}
	if again := aliasLeaseAddresses(ctx, t, tx, endpointID, "resource", provider.id); !slices.Equal(again, resourceAliases) {
		t.Fatalf("Resource aliases after key rotation %v, want the endpoint's own %v", again, resourceAliases)
	}
	var pinned, history int
	if err := tx.QueryRow(ctx, `SELECT
   (SELECT count(*) FROM mesh.device_alias_lease AS lease JOIN mesh.device_node_key_epoch AS key_epoch ON key_epoch.device_id=provider.id AND key_epoch.epoch=provider.current_node_key_epoch
    WHERE lease.private_endpoint_id=endpoint.id AND lease.alias_role='resource' AND lease.state='reserved'
      AND lease.node_key_epoch=key_epoch.epoch AND lease.node_public_key=key_epoch.public_key AND lease.session_generation=provider.session_generation),
   (SELECT count(*) FROM mesh.device_alias_lease AS lease WHERE lease.private_endpoint_id=endpoint.id AND lease.alias_role='resource'
      AND lease.state='quarantined' AND lease.node_key_epoch=provider.current_node_key_epoch-1)
  FROM mesh.private_endpoint AS endpoint, mesh.device AS provider WHERE endpoint.public_id=$1::UUID AND provider.public_id=$2::UUID`,
		endpointID, provider.id).Scan(&pinned, &history); err != nil {
		t.Fatal(err)
	}
	if pinned != 2 || history != 2 {
		t.Fatalf("Resource leases on the new key=%d, quarantined on the old key=%d; want 2 and 2", pinned, history)
	}
	assertAliasMapPeers(ctx, t, tx, "consumer after provider key rotation", consumer, [][]string{resourceAliases})
}

// assertAliasResourceAddressKeptForItsSlot drives uniqueness trigger v3
// directly while the endpoint's Resource aliases are quarantined: only a new
// Resource lease of the same endpoint, owner Device and family may take a
// quarantined Resource address; any other lease in a participating Network
// is refused with 23505 before any other check runs.
func assertAliasResourceAddressKeptForItsSlot(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, provider aliasMapIdentity) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_resource_slot`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := tx.Exec(ctx, `RESET ROLE; ROLLBACK TO SAVEPOINT alias_resource_slot`); err != nil {
			t.Fatal(err)
		}
	}()
	marker := int64(5300)
	suspendAliasDevice(ctx, t, tx, provider.id)
	if modes := runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); len(modes) == 0 || modes[0] != "quarantine_resource" {
		t.Fatalf("worker on provider suspend ran %v, want quarantine_resource first", modes)
	}
	resumeAliasDevice(ctx, t, tx, provider.id)
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	// target: the quarantined Resource lease outside the Resource Alias
	// family; legacy: the one on the endpoint's Resource Alias; source: the
	// consumer's quarantined source lease of target's family.
	var target, legacy, source, otherEndpoint, otherDevice int64
	if err := tx.QueryRow(ctx, `SELECT target.id,legacy.id,source.id,
   COALESCE((SELECT other.id FROM mesh.private_endpoint AS other WHERE other.id<>endpoint.id ORDER BY other.id LIMIT 1),0),
   COALESCE((SELECT other.id FROM mesh.device AS other WHERE other.workspace_id=provider.workspace_id AND other.network_id=provider.network_id
     AND other.id<>provider.id ORDER BY other.id LIMIT 1),0)
  FROM mesh.private_endpoint AS endpoint JOIN mesh.device AS provider ON provider.public_id=$2::UUID
  JOIN mesh.device AS consumer ON consumer.public_id=$3::UUID
  JOIN mesh.device_alias_lease AS target ON target.private_endpoint_id=endpoint.id AND target.alias_role='resource'
   AND target.state='quarantined' AND target.address<>endpoint.resource_alias
  JOIN mesh.device_alias_lease AS legacy ON legacy.private_endpoint_id=endpoint.id AND legacy.alias_role='resource'
   AND legacy.state='quarantined' AND legacy.address=endpoint.resource_alias
  JOIN mesh.device_alias_lease AS source ON source.private_endpoint_id=endpoint.id AND source.alias_role='consumer_source'
   AND source.state='quarantined' AND source.owner_device_id=consumer.id AND source.family=target.family
  WHERE endpoint.public_id=$1::UUID`, endpointID, provider.id, consumerID).Scan(
		&target, &legacy, &source, &otherEndpoint, &otherDevice); err != nil {
		t.Fatalf("quarantined alias rows: %v", err)
	}
	if otherEndpoint == 0 || otherDevice == 0 {
		t.Fatalf("fixture lacks another endpoint (%d) or another provider-Network Device (%d)", otherEndpoint, otherDevice)
	}
	refused := []struct {
		name            string
		source          int64
		endpoint, owner string
	}{
		{"another endpoint", target, fmt.Sprint(otherEndpoint), "source.owner_device_id"},
		{"another Device's source lease", source, "source.private_endpoint_id", "source.owner_device_id"},
		{"another owner Device", target, "source.private_endpoint_id", fmt.Sprint(otherDevice)},
		// The address CHECK also refuses a family mismatch; the trigger runs first.
		{"another family", legacy, "source.private_endpoint_id", "source.owner_device_id"},
	}
	for index, test := range refused {
		_, err := insertAliasLeaseCopy(ctx, t, tx, fmt.Sprintf("01890fb0-0000-7000-8000-%012d", 5400+index), test.source, target, test.endpoint, test.owner)
		var postgresErr *pgconn.PgError
		if !errors.As(err, &postgresErr) || postgresErr.Code != "23505" || postgresErr.Message != "alias address is retained in a participating Network" {
			t.Fatalf("%s: insert at a quarantined Resource address returned %v, want the uniqueness refusal", test.name, err)
		}
	}
	// The same endpoint, owner Device and family takes its own address back,
	// in both families.
	for index, row := range []int64{target, legacy} {
		if _, err := insertAliasLeaseCopy(ctx, t, tx, fmt.Sprintf("01890fb0-0000-7000-8000-%012d", 5410+index), row, row,
			"source.private_endpoint_id", "source.owner_device_id"); err != nil {
			t.Fatalf("readmitted Resource lease %d: %v", index, err)
		}
	}
}

// insertAliasLeaseCopy inserts, as the administrator with every trigger, a
// reserved copy of lease source at target's address, with the endpoint and
// owner Device expressions given (constants of this file, never input).
func insertAliasLeaseCopy(ctx context.Context, t *testing.T, tx pgx.Tx, publicID string, source, target int64, endpoint, owner string) (int64, error) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_lease_copy`); err != nil {
		t.Fatal(err)
	}
	// The scope the allocator sets for the lifecycle triggers' reads.
	if _, err := tx.Exec(ctx, `SELECT set_config('mesh.device_alias_deployment_id',lease.deployment_id::TEXT,TRUE),
  set_config('mesh.share_provider_workspace_id',lease.provider_workspace_id::TEXT,TRUE),set_config('mesh.share_provider_network_id',lease.provider_network_id::TEXT,TRUE),
  set_config('mesh.share_consumer_workspace_id',lease.consumer_workspace_id::TEXT,TRUE),set_config('mesh.share_consumer_network_id',lease.consumer_network_id::TEXT,TRUE)
  FROM mesh.device_alias_lease AS lease WHERE lease.id=$1::BIGINT`, source); err != nil {
		t.Fatal(err)
	}
	var id int64
	err := tx.QueryRow(ctx, fmt.Sprintf(`WITH decided AS (SELECT clock_timestamp() AS at)
INSERT INTO mesh.device_alias_lease(public_id,deployment_id,address_realm_id,address_pool_id,
 provider_workspace_id,provider_network_id,consumer_workspace_id,consumer_network_id,
 private_endpoint_id,endpoint_generation,recovery_epoch,resource_version,target_generation,
 owner_workspace_id,owner_network_id,owner_device_id,session_generation,
 machine_key_epoch,node_key_epoch,node_public_key,alias_role,family,address,expires_at,
 provider_network_revision,provider_sharing_revision,consumer_network_revision,consumer_sharing_revision,
 state,created_at,updated_at)
SELECT $1::UUID,source.deployment_id,source.address_realm_id,source.address_pool_id,
 source.provider_workspace_id,source.provider_network_id,source.consumer_workspace_id,source.consumer_network_id,
 %[1]s,source.endpoint_generation,source.recovery_epoch,source.resource_version,source.target_generation,
 source.owner_workspace_id,source.owner_network_id,%[2]s,owner.session_generation,
 source.machine_key_epoch,source.node_key_epoch,source.node_public_key,source.alias_role,source.family,target.address,source.expires_at,
 source.provider_network_revision,source.provider_sharing_revision,source.consumer_network_revision,source.consumer_sharing_revision,
 'reserved',decided.at,decided.at
FROM mesh.device_alias_lease AS source CROSS JOIN decided
JOIN mesh.device_alias_lease AS target ON target.id=$3::BIGINT
JOIN mesh.device AS owner ON owner.id=%[2]s
WHERE source.id=$2::BIGINT RETURNING id`, endpoint, owner), publicID, source, target).Scan(&id)
	statement := `RELEASE SAVEPOINT alias_lease_copy`
	if err != nil {
		statement = `ROLLBACK TO SAVEPOINT alias_lease_copy`
	}
	if _, rollbackErr := tx.Exec(ctx, statement); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	return id, err
}
