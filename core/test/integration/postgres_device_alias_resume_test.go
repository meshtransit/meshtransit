//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The worker functions the alias worker uses once the operator granted them.
const (
	aliasWorkLoadVersion    = "v3"
	aliasWorkPrepareVersion = "v4"
)

type aliasWorkItem struct {
	EndpointID        string  `json:"endpoint_id"`
	ConsumerID        *string `json:"consumer_id"`
	Generation        int64   `json:"generation"`
	ProviderNodeEpoch int64   `json:"provider_node_epoch"`
	ConsumerNodeEpoch int64   `json:"consumer_node_epoch"`
	Mode              string  `json:"mode"`
}

// assertAliasWorkerReadmitsResumedConsumer: suspending the consumer Device of
// a ready share takes the edge out of the provider's map; once the Device is
// resumed and its client claims aliases again, the worker reserves the
// Device's own source aliases again and makes the pair ready, so the edge is
// back in both maps (TD-CORE-37). Each cycle keeps the old rows as history
// and takes no new address from the pool.
func assertAliasWorkerReadmitsResumedConsumer(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, provider, consumer aliasMapIdentity) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_resume`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := tx.Exec(ctx, `RESET ROLE; ROLLBACK TO SAVEPOINT alias_resume`); err != nil {
			t.Fatal(err)
		}
	}()
	marker := int64(4500)
	resourceAliases := aliasLeaseAddresses(ctx, t, tx, endpointID, "resource", provider.id)
	sources := aliasLeaseAddresses(ctx, t, tx, endpointID, "consumer_source", consumer.id)
	if len(resourceAliases) != 2 || len(sources) != 2 {
		t.Fatalf("ready share aliases resource=%v source=%v, want both families", resourceAliases, sources)
	}
	assertAliasMapPeers(ctx, t, tx, "provider before suspend", provider, [][]string{sources})
	for cycle := 1; cycle <= 2; cycle++ {
		// What the Device lifecycle writes on suspend and resume (schema 125).
		execAsReplica(ctx, t, tx, `UPDATE mesh.device SET state='suspended',suspended_reason='admin',
  session_generation=session_generation+1,version=version+1,updated_at=clock_timestamp() WHERE public_id=$1::UUID`, consumerID)
		modes := runAliasWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker)
		if !slices.Equal(modes, []string{"withdraw", "quarantine_consumer"}) {
			t.Fatalf("cycle %d: worker on suspend ran %v, want withdraw then quarantine_consumer", cycle, modes)
		}
		assertAliasMapPeers(ctx, t, tx, "provider while suspended", provider, nil)
		if cycle == 1 {
			assertAliasPrepareRefused(ctx, t, tx, deploymentID, endpointID, consumerID, &marker)
		}
		execAsReplica(ctx, t, tx, `UPDATE mesh.device SET state='active',suspended_reason=NULL,
  version=version+1,updated_at=clock_timestamp() WHERE public_id=$1::UUID`, consumerID)
		if cycle == 1 {
			// Nothing is readmitted until the client claims aliases for its new session.
			if modes := runAliasWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); len(modes) != 0 {
				t.Fatalf("worker before the client claim ran %v, want nothing", modes)
			}
		}
		// The resumed client reconnects and claims aliases for its new session.
		execAsReplica(ctx, t, tx, `UPDATE mesh.device_alias_client_version AS claim SET session_generation=device.session_generation,observed_at=clock_timestamp()
  FROM mesh.device AS device WHERE device.public_id=$1::UUID AND claim.device_id=device.id`, consumerID)
		if cycle == 1 {
			// Nor while the Device is no source of a rule to the share any more.
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_resume_without_rule`); err != nil {
				t.Fatal(err)
			}
			execAsReplica(ctx, t, tx, `DELETE FROM mesh.compiled_policy_imported_resource_destination
  WHERE source_device_id=(SELECT id FROM mesh.device WHERE public_id=$1::UUID)`, consumerID)
			if modes := runAliasWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); len(modes) != 0 {
				t.Fatalf("worker without a rule ran %v, want nothing", modes)
			}
			if _, err := tx.Exec(ctx, `RESET ROLE; ROLLBACK TO SAVEPOINT alias_resume_without_rule`); err != nil {
				t.Fatal(err)
			}
		}
		modes = runAliasWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker)
		if !slices.Equal(modes, []string{"reserve", "ready"}) {
			t.Fatalf("cycle %d: worker on resume ran %v, want reserve then ready", cycle, modes)
		}
		if again := aliasLeaseAddresses(ctx, t, tx, endpointID, "consumer_source", consumer.id); !slices.Equal(again, sources) {
			t.Fatalf("cycle %d: resumed source aliases %v, want the Device's own %v", cycle, again, sources)
		}
		assertAliasMapPeers(ctx, t, tx, "provider after resume", provider, [][]string{sources})
		assertAliasMapPeers(ctx, t, tx, "consumer after resume", consumer, [][]string{resourceAliases})

		if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		var ready, withdrawn, quarantined, addresses int
		if err := tx.QueryRow(ctx, `SELECT
   (SELECT count(*) FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id AND state='ready'),
   (SELECT count(*) FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND consumer_device_id=consumer.id AND state='withdrawn'),
   (SELECT count(*) FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source' AND owner_device_id=consumer.id AND state='quarantined'),
   (SELECT count(DISTINCT address) FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='consumer_source' AND owner_device_id=consumer.id)
  FROM mesh.private_endpoint AS endpoint, mesh.device AS consumer WHERE endpoint.public_id=$1::UUID AND consumer.public_id=$2::UUID`,
			endpointID, consumerID).Scan(&ready, &withdrawn, &quarantined, &addresses); err != nil {
			t.Fatal(err)
		}
		if ready != 1 || withdrawn != cycle || quarantined != 2*cycle || addresses != 2 {
			t.Fatalf("cycle %d: readiness ready=%d withdrawn=%d, quarantined sources=%d on %d addresses; want 1, %d, %d on 2",
				cycle, ready, withdrawn, quarantined, addresses, cycle, 2*cycle)
		}
		if modes := runAliasWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); len(modes) != 0 {
			t.Fatalf("cycle %d: worker after readmission ran %v, want nothing", cycle, modes)
		}
	}
}

// assertAliasPrepareRefused: prepare v4 itself refuses to reserve or make
// ready a suspended consumer Device, whatever work it is handed.
func assertAliasPrepareRefused(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, marker *int64) {
	t.Helper()
	var generation, providerEpoch, consumerEpoch int64
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT endpoint.generation,provider.current_node_key_epoch,consumer.current_node_key_epoch
  FROM mesh.private_endpoint AS endpoint JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
  JOIN mesh.resource_device_target AS target ON target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation AND target.state='active'
  JOIN mesh.device AS provider ON provider.id=target.device_id JOIN mesh.device AS consumer ON consumer.public_id=$2::UUID
  WHERE endpoint.public_id=$1::UUID`, endpointID, consumerID).Scan(&generation, &providerEpoch, &consumerEpoch); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"reserve", "ready"} {
		next := func() string {
			*marker++
			return fmt.Sprintf("01890fb0-0000-7000-8000-%012d", *marker)
		}
		if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_prepare_refused; SET LOCAL ROLE mesh_worker`); err != nil {
			t.Fatal(err)
		}
		var body []byte
		err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_change_`+aliasWorkPrepareVersion+`($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`,
			deploymentID, endpointID, consumerID, generation, providerEpoch, consumerEpoch, []string{next(), next(), next(), next()}, next(), next(), mode).Scan(&body)
		requireDeviceAliasCode(t, err, "40001")
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_prepare_refused`); err != nil {
			t.Fatal(err)
		}
	}
}

func execAsReplica(ctx context.Context, t *testing.T, tx pgx.Tx, statement string, arguments ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=origin`); err != nil {
		t.Fatal(err)
	}
}

// runAliasWorkerUntilIdle runs the worker's work for one consumer the way the
// worker does, one guarded change per pass, and returns the modes it ran.
func runAliasWorkerUntilIdle(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, marker *int64) []string {
	t.Helper()
	var modes []string
	for range 6 {
		if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL ROLE mesh_worker`); err != nil {
			t.Fatal(err)
		}
		var encoded []byte
		if err := tx.QueryRow(ctx, `SELECT mesh_ops.load_device_alias_work_`+aliasWorkLoadVersion+`($1::UUID,NULL,NULL,128)`, deploymentID).Scan(&encoded); err != nil {
			t.Fatalf("load alias work: %v", err)
		}
		var page struct {
			Items []aliasWorkItem `json:"items"`
		}
		if err := json.Unmarshal(encoded, &page); err != nil {
			t.Fatal(err)
		}
		index := slices.IndexFunc(page.Items, func(item aliasWorkItem) bool {
			return item.EndpointID == endpointID && item.ConsumerID != nil && *item.ConsumerID == consumerID
		})
		if index < 0 {
			return modes
		}
		item := page.Items[index]
		runAliasWorkItem(ctx, t, tx, deploymentID, consumerID, item, marker)
		modes = append(modes, item.Mode)
	}
	t.Fatalf("alias worker did not settle after %v", modes)
	return nil
}

func runAliasWorkItem(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, consumerID string, item aliasWorkItem, marker *int64) {
	t.Helper()
	next := func() string {
		*marker++
		return fmt.Sprintf("01890fb0-0000-7000-8000-%012d", *marker)
	}
	change := next()
	var body []byte
	withdrawal := item.Mode == "withdraw" || item.Mode == "quarantine_consumer"
	if withdrawal {
		if err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::UUID,$6::TEXT)`,
			deploymentID, item.EndpointID, consumerID, item.Generation, change, item.Mode).Scan(&body); err != nil {
			t.Fatalf("prepare %s: %v", item.Mode, err)
		}
	} else {
		leases := []string{next(), next(), next(), next()}
		if err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_change_`+aliasWorkPrepareVersion+`($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`,
			deploymentID, item.EndpointID, consumerID, item.Generation, item.ProviderNodeEpoch, item.ConsumerNodeEpoch, leases, next(), change, item.Mode).Scan(&body); err != nil {
			t.Fatalf("prepare %s: %v", item.Mode, err)
		}
	}
	var proof aliasWorkerProof
	if err := json.Unmarshal(body, &proof); err != nil || !proof.Changed {
		t.Fatalf("%s proof %s: %v", item.Mode, body, err)
	}
	events := hashIntegrationAliasEvidence(t, proof, *marker+1)
	*marker += 4
	var count int
	var err error
	if withdrawal {
		err = tx.QueryRow(ctx, `SELECT mesh_ops.finalize_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::JSONB)`,
			deploymentID, item.EndpointID, item.Generation, change, item.Mode, events).Scan(&count)
	} else {
		err = tx.QueryRow(ctx, `SELECT mesh_ops.finalize_device_alias_change_v1($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::JSONB)`,
			deploymentID, item.EndpointID, item.Generation, change, proof.AggregateKind, events).Scan(&count)
	}
	if err != nil || count != 2 {
		t.Fatalf("finalize %s: count=%d %v", item.Mode, count, err)
	}
	if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE; SET CONSTRAINTS ALL DEFERRED`); err != nil {
		t.Fatalf("%s evidence: %v", item.Mode, err)
	}
	if item.Mode == "reserve" {
		// The worker reserves in its own committed transaction and maps read
		// later; backdate the new leases to this transaction's start so the
		// readers' created-before-snapshot pin holds.
		execAsReplica(ctx, t, tx, `UPDATE mesh.device_alias_lease AS lease
  SET created_at=transaction_timestamp()-INTERVAL '1 second',updated_at=transaction_timestamp()-INTERVAL '1 second'
  FROM mesh.private_endpoint AS endpoint WHERE endpoint.public_id=$1::UUID AND lease.private_endpoint_id=endpoint.id
   AND lease.state='reserved' AND lease.created_at>transaction_timestamp()`, item.EndpointID)
	}
}

func aliasLeaseAddresses(ctx context.Context, t *testing.T, tx pgx.Tx, endpointID, role, ownerID string) []string {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `SELECT host(lease.address)||CASE lease.family WHEN 4 THEN '/32' ELSE '/128' END
  FROM mesh.device_alias_lease AS lease JOIN mesh.private_endpoint AS endpoint ON endpoint.id=lease.private_endpoint_id
  JOIN mesh.device AS owner ON owner.id=lease.owner_device_id
  WHERE endpoint.public_id=$1::UUID AND lease.alias_role=$2 AND owner.public_id=$3::UUID AND lease.state='reserved' ORDER BY lease.family`, endpointID, role, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return addresses
}

// assertAliasMapPeers reads the Device's alias edges through the reader the
// map session uses and compares each edge's peer addresses.
func assertAliasMapPeers(ctx context.Context, t *testing.T, tx pgx.Tx, name string, self aliasMapIdentity, want [][]string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	setIntegrationScope(ctx, t, tx, self.workspace, self.network)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `SELECT edge::TEXT FROM mesh_ops.load_device_alias_map_edges_v7($1::BYTEA,$2::BYTEA,10000) AS edge`, self.machine, self.key)
	if err != nil {
		t.Fatalf("%s alias map: %v", name, err)
	}
	encoded, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("%s alias map: %v", name, err)
	}
	var peers [][]string
	for _, value := range encoded {
		var record struct {
			Peer struct {
				Addresses []string `json:"addresses"`
			} `json:"peer"`
		}
		if err := json.Unmarshal([]byte(value), &record); err != nil {
			t.Fatal(err)
		}
		peers = append(peers, record.Peer.Addresses)
	}
	if !slices.EqualFunc(peers, want, slices.Equal[[]string]) {
		t.Fatalf("%s alias map peers=%v, want %v", name, peers, want)
	}
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
}
