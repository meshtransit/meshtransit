//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// assertAliasWorkerRestoresResumedProvider: suspending the provider Device of
// a ready share quarantines the endpoint's Resource aliases and takes the
// edge out of both maps; once the Device is resumed and its client claims
// aliases again, the worker reserves the same Resource aliases (the share's
// DNS name points at the endpoint's Resource Alias) and makes the pair ready,
// so the edge is back in both maps (TD-CORE-40). Each cycle keeps the old
// rows as history and takes no new address from the pool.
func assertAliasWorkerRestoresResumedProvider(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, provider, consumer aliasMapIdentity) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_provider_resume`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := tx.Exec(ctx, `RESET ROLE; ROLLBACK TO SAVEPOINT alias_provider_resume`); err != nil {
			t.Fatal(err)
		}
	}()
	marker := int64(4700)
	resourceAliases := aliasLeaseAddresses(ctx, t, tx, endpointID, "resource", provider.id)
	sources := aliasLeaseAddresses(ctx, t, tx, endpointID, "consumer_source", consumer.id)
	if len(resourceAliases) != 2 || len(sources) != 2 {
		t.Fatalf("ready share aliases resource=%v source=%v, want both families", resourceAliases, sources)
	}
	var published string
	if err := tx.QueryRow(ctx, `SELECT host(resource_alias)||CASE family(resource_alias) WHEN 4 THEN '/32' ELSE '/128' END
  FROM mesh.private_endpoint WHERE public_id=$1::UUID`, endpointID).Scan(&published); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(resourceAliases, published) {
		t.Fatalf("Resource aliases %v miss the endpoint's Resource Alias %s", resourceAliases, published)
	}
	assertAliasMapPeers(ctx, t, tx, "consumer before suspend", consumer, [][]string{resourceAliases})
	for cycle := 1; cycle <= 2; cycle++ {
		suspendAliasDevice(ctx, t, tx, provider.id)
		modes := runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker)
		own, others := splitAliasWorkModes(modes)
		if !slices.Equal(own, []string{"quarantine_resource", "withdraw", "quarantine_consumer"}) {
			t.Fatalf("cycle %d: worker on provider suspend ran %v, want quarantine_resource, withdraw, quarantine_consumer", cycle, modes)
		}
		if slices.ContainsFunc(others, func(mode string) bool { return mode != "quarantine_consumer" }) {
			t.Fatalf("cycle %d: worker on provider suspend ran %v for other consumers", cycle, others)
		}
		// The quarantine keeps the share out of the consumer's map while the
		// provider is suspended (the reader refuses the suspended Device's own).
		assertAliasMapPeers(ctx, t, tx, "consumer while provider suspended", consumer, nil)
		if cycle == 1 {
			assertAliasPrepareRefusedFor(ctx, t, tx, deploymentID, endpointID, provider.id, consumerID, &marker)
		}
		resumeAliasDevice(ctx, t, tx, provider.id)
		if cycle == 1 {
			// Nothing comes back until the provider's client claims aliases for its new session.
			if modes := runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); len(modes) != 0 {
				t.Fatalf("worker before the provider claim ran %v, want nothing", modes)
			}
		}
		claimAliasVersion(ctx, t, tx, provider.id)
		modes = runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker)
		if !slices.Equal(modes, []string{"reserve", "ready"}) {
			t.Fatalf("cycle %d: worker on provider resume ran %v, want reserve then ready", cycle, modes)
		}
		if again := aliasLeaseAddresses(ctx, t, tx, endpointID, "resource", provider.id); !slices.Equal(again, resourceAliases) {
			t.Fatalf("cycle %d: resumed Resource aliases %v, want the endpoint's own %v", cycle, again, resourceAliases)
		}
		if again := aliasLeaseAddresses(ctx, t, tx, endpointID, "consumer_source", consumer.id); !slices.Equal(again, sources) {
			t.Fatalf("cycle %d: consumer source aliases %v, want its own %v", cycle, again, sources)
		}
		assertAliasMapPeers(ctx, t, tx, "consumer after provider resume", consumer, [][]string{resourceAliases})
		assertAliasMapPeers(ctx, t, tx, "provider after resume", provider, [][]string{sources})

		if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		var reserved, quarantined, addresses, ready int
		if err := tx.QueryRow(ctx, `SELECT
   (SELECT count(*) FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved'),
   (SELECT count(*) FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='quarantined'),
   (SELECT count(DISTINCT address) FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource'),
   (SELECT count(*) FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND state='ready')
  FROM mesh.private_endpoint AS endpoint WHERE endpoint.public_id=$1::UUID`, endpointID).Scan(&reserved, &quarantined, &addresses, &ready); err != nil {
			t.Fatal(err)
		}
		if reserved != 2 || quarantined != 2*cycle || addresses != 2 || ready != 1 {
			t.Fatalf("cycle %d: Resource leases reserved=%d quarantined=%d on %d addresses, ready pairs=%d; want 2, %d on 2, 1",
				cycle, reserved, quarantined, addresses, ready, 2*cycle)
		}
		if modes := runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker); len(modes) != 0 {
			t.Fatalf("cycle %d: worker after provider resume ran %v, want nothing", cycle, modes)
		}
		if cycle == 1 {
			// The previous worker's prepare fails closed on the Resource
			// lease history; the readmitted pair stays ready.
			assertAliasPrepareVersionRefused(ctx, t, tx, "v4", deploymentID, endpointID, provider.id, consumerID, &marker)
			assertAliasMapPeers(ctx, t, tx, "consumer after previous prepare", consumer, [][]string{resourceAliases})
		}
	}
}

// assertAliasWorkerKeepsGoneProviderOut: a share whose provider Device was
// suspended does not come back when the share was revoked, the Device was
// deleted or the Resource no longer targets it, whatever the client claims.
func assertAliasWorkerKeepsGoneProviderOut(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, provider, consumer aliasMapIdentity) {
	t.Helper()
	for _, test := range []struct{ name, statement string }{
		{"revoked share", `UPDATE mesh.trust_contract SET state='revoked',ended_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp()
  WHERE id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID) AND $2::UUID IS NOT NULL`},
		{"deleted provider", `UPDATE mesh.device SET state='deleted',suspended_reason=NULL,deleted_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp()
  WHERE public_id=$2::UUID AND $1::UUID IS NOT NULL`},
		{"retargeted resource", `UPDATE mesh.resource_device_target SET state='superseded',version=version+1,updated_at=clock_timestamp()
  WHERE device_id=(SELECT id FROM mesh.device WHERE public_id=$2::UUID) AND state='active' AND $1::UUID IS NOT NULL`},
	} {
		t.Run("provider stays out after "+test.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_provider_gone`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := tx.Exec(ctx, `RESET ROLE; ROLLBACK TO SAVEPOINT alias_provider_gone`); err != nil {
					t.Fatal(err)
				}
			}()
			marker := int64(4900)
			suspendAliasDevice(ctx, t, tx, provider.id)
			modes := runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker)
			if len(modes) == 0 || modes[0] != "quarantine_resource" {
				t.Fatalf("worker on provider suspend ran %v, want quarantine_resource first", modes)
			}
			execAsReplica(ctx, t, tx, test.statement, endpointID, provider.id)
			if test.name != "deleted provider" {
				resumeAliasDevice(ctx, t, tx, provider.id)
			}
			claimAliasVersion(ctx, t, tx, provider.id)
			modes = runAliasEndpointWorkerUntilIdle(ctx, t, tx, deploymentID, endpointID, consumerID, &marker)
			if slices.ContainsFunc(modes, func(mode string) bool {
				return strings.HasSuffix(mode, "reserve") || strings.HasSuffix(mode, "ready")
			}) {
				t.Fatalf("worker after %s ran %v, want no reservation or readiness", test.name, modes)
			}
			assertAliasPrepareRefusedFor(ctx, t, tx, deploymentID, endpointID, provider.id, consumerID, &marker)
			if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
				t.Fatal(err)
			}
			var reserved, ready int
			if err := tx.QueryRow(ctx, `SELECT
   (SELECT count(*) FROM mesh.device_alias_lease WHERE private_endpoint_id=endpoint.id AND alias_role='resource' AND state='reserved'),
   (SELECT count(*) FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=endpoint.id AND state='ready')
  FROM mesh.private_endpoint AS endpoint WHERE endpoint.public_id=$1::UUID`, endpointID).Scan(&reserved, &ready); err != nil {
				t.Fatal(err)
			}
			if reserved != 0 || ready != 0 {
				t.Fatalf("after %s: reserved Resource leases=%d ready pairs=%d, want none", test.name, reserved, ready)
			}
			assertAliasMapPeers(ctx, t, tx, "consumer after "+test.name, consumer, nil)
		})
	}
}

// What the Device lifecycle writes on suspend and resume (schema 125).
func suspendAliasDevice(ctx context.Context, t *testing.T, tx pgx.Tx, deviceID string) {
	t.Helper()
	execAsReplica(ctx, t, tx, `UPDATE mesh.device SET state='suspended',suspended_reason='admin',
  session_generation=session_generation+1,version=version+1,updated_at=clock_timestamp() WHERE public_id=$1::UUID`, deviceID)
}

func resumeAliasDevice(ctx context.Context, t *testing.T, tx pgx.Tx, deviceID string) {
	t.Helper()
	execAsReplica(ctx, t, tx, `UPDATE mesh.device SET state='active',suspended_reason=NULL,
  version=version+1,updated_at=clock_timestamp() WHERE public_id=$1::UUID`, deviceID)
}

// claimAliasVersion: the Device's client reconnects and claims aliases for its current session.
func claimAliasVersion(ctx context.Context, t *testing.T, tx pgx.Tx, deviceID string) {
	t.Helper()
	execAsReplica(ctx, t, tx, `UPDATE mesh.device_alias_client_version AS claim SET session_generation=device.session_generation,observed_at=clock_timestamp()
  FROM mesh.device AS device WHERE device.public_id=$1::UUID AND claim.device_id=device.id`, deviceID)
}

// assertAliasPrepareRefusedFor: prepare refuses to reserve or make ready the
// pair whatever work it is handed, pinned to the provider's current keys.
func assertAliasPrepareRefusedFor(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, providerID, consumerID string, marker *int64) {
	t.Helper()
	assertAliasPrepareVersionRefused(ctx, t, tx, aliasWorkPrepareVersion, deploymentID, endpointID, providerID, consumerID, marker)
}

func assertAliasPrepareVersionRefused(ctx context.Context, t *testing.T, tx pgx.Tx, version, deploymentID, endpointID, providerID, consumerID string, marker *int64) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var generation, providerEpoch, consumerEpoch int64
	if err := tx.QueryRow(ctx, `SELECT endpoint.generation,provider.current_node_key_epoch,consumer.current_node_key_epoch
  FROM mesh.private_endpoint AS endpoint, mesh.device AS provider, mesh.device AS consumer
  WHERE endpoint.public_id=$1::UUID AND provider.public_id=$2::UUID AND consumer.public_id=$3::UUID`,
		endpointID, providerID, consumerID).Scan(&generation, &providerEpoch, &consumerEpoch); err != nil {
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
		err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_change_`+version+`($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`,
			deploymentID, endpointID, consumerID, generation, providerEpoch, consumerEpoch, []string{next(), next(), next(), next()}, next(), next(), mode).Scan(&body)
		requireDeviceAliasCode(t, err, "40001")
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_prepare_refused`); err != nil {
			t.Fatal(err)
		}
	}
}

// runAliasEndpointWorkerUntilIdle runs all of the worker's work for one
// endpoint the way the worker does, one guarded change per pass, and returns
// the modes it ran; work for another consumer Device is prefixed "other ".
func runAliasEndpointWorkerUntilIdle(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, marker *int64) []string {
	t.Helper()
	var modes []string
	for range 12 {
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
		index := slices.IndexFunc(page.Items, func(item aliasWorkItem) bool { return item.EndpointID == endpointID })
		if index < 0 {
			return modes
		}
		item := page.Items[index]
		runAliasWorkItem(ctx, t, tx, deploymentID, consumerID, item, marker)
		label := item.Mode
		if item.ConsumerID != nil && *item.ConsumerID != consumerID {
			label = "other " + item.Mode
		}
		modes = append(modes, label)
	}
	t.Fatalf("alias worker did not settle after %v", modes)
	return nil
}

func splitAliasWorkModes(modes []string) (own, others []string) {
	for _, mode := range modes {
		if other, found := strings.CutPrefix(mode, "other "); found {
			others = append(others, other)
		} else {
			own = append(own, mode)
		}
	}
	return own, others
}
