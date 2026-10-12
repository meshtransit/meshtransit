//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/publicid"
)

func assertDeviceAliasGuardedWorker(ctx context.Context, t *testing.T, tx pgx.Tx, endpointID, consumerID string, provider, consumer aliasMapIdentity) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var safe bool
	if err := tx.QueryRow(ctx, `SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
  AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=pg_roles.oid OR member=pg_roles.oid)
  FROM pg_roles WHERE rolname='mesh_device_alias_writer'`).Scan(&safe); err != nil || !safe {
		t.Fatal("unsafe alias writer role", err)
	}
	var deploymentID string
	var generation, providerEpoch, consumerEpoch int64
	if err := tx.QueryRow(ctx, `SELECT deployment.installation_public_id::TEXT,endpoint.generation,provider.current_node_key_epoch,consumer.current_node_key_epoch
  FROM mesh.private_endpoint AS endpoint JOIN mesh.deployment AS deployment ON deployment.id=endpoint.deployment_id
  JOIN mesh.device AS consumer ON consumer.public_id=$2::UUID
  JOIN mesh.trust_contract AS contract ON contract.id=endpoint.trust_contract_id
  JOIN mesh.resource_device_target AS target ON target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation AND target.state='active'
  JOIN mesh.device AS provider ON provider.id=target.device_id WHERE endpoint.public_id=$1::UUID`, endpointID, consumerID).Scan(&deploymentID, &generation, &providerEpoch, &consumerEpoch); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, query string }{
		{"worker table read", `SET LOCAL ROLE mesh_worker; SELECT count(*) FROM mesh.device_alias_lease`},
		{"worker readiness write", `SET LOCAL ROLE mesh_worker; DELETE FROM mesh.device_alias_client_readiness`},
		{"runtime prepare", `SET LOCAL ROLE mesh_runtime; SELECT mesh_ops.prepare_device_alias_change_v2(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`},
		{"worker inner allocator", `SET LOCAL ROLE mesh_worker; SELECT mesh_ops.reserve_device_aliases_internal_v1(NULL,NULL,NULL,NULL,NULL,NULL)`},
		{"runtime prepare v3", `SET LOCAL ROLE mesh_runtime; SELECT mesh_ops.prepare_device_alias_change_v3(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`},
		{"worker inner allocator v3", `SET LOCAL ROLE mesh_worker; SELECT mesh_ops.reserve_device_aliases_internal_v3(NULL,NULL,NULL,NULL,NULL,NULL)`},
	} {
		if _, err := tx.Exec(ctx, `SAVEPOINT alias_worker_privilege`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, test.query)
		requireDeviceAliasCode(t, err, "42501")
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_worker_privilege`); err != nil {
			t.Fatal(err)
		}
	}
	assertAliasWorkCandidates(ctx, t, tx, deploymentID, endpointID, consumerID)
	assertAliasWorkerAuthorityRejections(ctx, t, tx, deploymentID, endpointID, consumerID, generation, providerEpoch, consumerEpoch)
	// The _v3 modes run the same flow through prepare v3 (schema 147).
	for _, run := range []string{"missing_evidence", "wrong_evidence", "complete", "readiness", "readiness_missing_evidence",
		"complete_v3", "readiness_v3"} {
		mode, version := strings.TrimSuffix(run, "_v3"), "v2"
		if mode != run {
			version = "v3"
		}
		t.Run("guarded alias worker "+run, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT guarded_alias_worker`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT guarded_alias_worker`); err != nil {
					t.Fatal(err)
				}
			}()
			readinessMode := mode == "readiness" || mode == "readiness_missing_evidence"
			if !readinessMode {
				if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica;
     DELETE FROM mesh.device_alias_lease WHERE private_endpoint_id=(SELECT id FROM mesh.private_endpoint WHERE public_id=$1::UUID);
     SET LOCAL session_replication_role=origin`, pgx.QueryExecModeSimpleProtocol, endpointID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_worker;
    SELECT set_config('mesh.workspace_id','999',TRUE),set_config('mesh.network_id','999',TRUE),set_config('mesh.share_provider_workspace_id','999',TRUE),
    set_config('mesh.share_consumer_workspace_id','999',TRUE),set_config('mesh.device_alias_deployment_id','999',TRUE)`); err != nil {
				t.Fatal(err)
			}
			prepare := func(change, readiness string, kind string) aliasWorkerProof {
				var body []byte
				err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_change_`+version+`($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`,
					deploymentID, endpointID, consumerID, generation, providerEpoch, consumerEpoch, []string{
						"01890fb0-0000-7000-8000-000000004101", "01890fb0-0000-7000-8000-000000004102", "01890fb0-0000-7000-8000-000000004103", "01890fb0-0000-7000-8000-000000004104",
					}, readiness, change, kind).Scan(&body)
				if err != nil {
					t.Fatal("guarded prepare failed", err)
				}
				var proof aliasWorkerProof
				if err := json.Unmarshal(body, &proof); err != nil || !proof.Changed || len(proof.Events) != 2 {
					t.Fatal("invalid guarded proof", err)
				}
				var restored bool
				if err := tx.QueryRow(ctx, `SELECT current_setting('mesh.workspace_id')='999' AND current_setting('mesh.network_id')='999'
     AND current_setting('mesh.share_provider_workspace_id')='999' AND current_setting('mesh.share_consumer_workspace_id')='999'
     AND current_setting('mesh.device_alias_deployment_id')='999'`).Scan(&restored); err != nil || !restored {
					t.Fatal("worker scope leaked", err)
				}
				return proof
			}
			change := "01890fb0-0000-7000-8000-000000004111"
			kind := "reserve"
			if readinessMode {
				kind = "ready"
			}
			proof := prepare(change, "01890fb0-0000-7000-8000-000000004110", kind)
			if mode == "missing_evidence" || mode == "readiness_missing_evidence" {
				_, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
				requireDeviceAliasCode(t, err, "23514")
			} else {
				events := hashIntegrationAliasEvidence(t, proof, 4120)
				if mode == "wrong_evidence" {
					proof.Events[0].AuditPayload = `{}`
					events = hashIntegrationAliasEvidence(t, proof, 4120)
				}
				var finalized int
				err := tx.QueryRow(ctx, `SELECT mesh_ops.finalize_device_alias_change_v1($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::JSONB)`, deploymentID, endpointID, generation, change, proof.AggregateKind, events).Scan(&finalized)
				if mode == "wrong_evidence" {
					requireDeviceAliasCode(t, err, "23514")
				} else {
					if err != nil || finalized != 2 {
						t.Fatal("reservation evidence failed", err)
					}
					if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE; SET CONSTRAINTS ALL DEFERRED`); err != nil {
						t.Fatal(err)
					}
					var duplicate int
					_, err = tx.Exec(ctx, `SAVEPOINT duplicate_alias_evidence`)
					if err != nil {
						t.Fatal(err)
					}
					err = tx.QueryRow(ctx, `SELECT mesh_ops.finalize_device_alias_change_v1($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::JSONB)`, deploymentID, endpointID, generation, change, proof.AggregateKind, events).Scan(&duplicate)
					requireDeviceAliasCode(t, err, "23514")
					if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT duplicate_alias_evidence`); err != nil {
						t.Fatal(err)
					}
					if readinessMode {
						var replay []byte
						if err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_change_`+version+`($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,'ready')`,
							deploymentID, endpointID, consumerID, generation, providerEpoch, consumerEpoch, []string{"01890fb0-0000-7000-8000-000000004101", "01890fb0-0000-7000-8000-000000004102", "01890fb0-0000-7000-8000-000000004103", "01890fb0-0000-7000-8000-000000004104"}, "01890fb0-0000-7000-8000-000000004130", "01890fb0-0000-7000-8000-000000004131").Scan(&replay); err != nil {
							t.Fatal(err)
						}
						if string(replay) != `{"events": [], "changed": false}` {
							t.Fatalf("idempotent readiness changed: %s", replay)
						}
						assertAliasMapCount(ctx, t, tx, provider, 1)
						assertAliasMapCount(ctx, t, tx, consumer, 1)
						assertAliasWorkerWithdrawal(ctx, t, tx, deploymentID, endpointID, consumerID, generation, provider, consumer)
					}
				}
			}
		})
	}
}

type aliasWorkerProof struct {
	Changed          bool               `json:"changed"`
	ChangeID         string             `json:"change_id"`
	Action           string             `json:"action,omitempty"`
	AggregateKind    string             `json:"aggregate_kind"`
	AggregateID      string             `json:"aggregate_id"`
	AggregateVersion int64              `json:"aggregate_version"`
	Events           []aliasWorkerEvent `json:"events"`
}

type aliasWorkerEvent struct {
	WorkspaceID     string `json:"workspace_id"`
	NetworkID       string `json:"network_id"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	NetworkRevision int64  `json:"network_revision"`
	SharingRevision int64  `json:"sharing_revision"`
	AuditPayload    string `json:"audit_payload"`
	OutboxPayload   string `json:"outbox_payload"`
	EventID         string `json:"event_id,omitempty"`
	OutboxID        string `json:"outbox_id,omitempty"`
	EventHash       string `json:"event_hash,omitempty"`
}

func hashIntegrationAliasEvidence(t *testing.T, proof aliasWorkerProof, marker int64) []byte {
	t.Helper()
	aggregateID, err := publicid.Parse(proof.AggregateID)
	if err != nil {
		t.Fatal(err)
	}
	changeID, err := publicid.Parse(proof.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	action := "sharing.device_alias.reserve"
	if proof.AggregateKind == "device_alias_client_readiness" {
		action = "sharing.device_alias.ready"
	}
	if proof.Action != "" {
		action = proof.Action
	}
	for index := range proof.Events {
		event := &proof.Events[index]
		eventID, err := publicid.Parse(fmt.Sprintf("01890fb0-0000-7000-8000-%012d", marker+int64(index*2)))
		if err != nil {
			t.Fatal(err)
		}
		outboxID, err := publicid.Parse(fmt.Sprintf("01890fb0-0000-7000-8000-%012d", marker+int64(index*2)+1))
		if err != nil {
			t.Fatal(err)
		}
		previous, err := hex.DecodeString(event.PreviousHash)
		if err != nil || len(previous) != 32 {
			t.Fatal("invalid audit head", err)
		}
		hash, err := audit.HashEvent(audit.EventHashMaterial{PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: changeID,
			AggregateKind: proof.AggregateKind, AggregateID: aggregateID, AggregateVersion: proof.AggregateVersion, NetworkRevision: event.NetworkRevision,
			Action: action, Permission: "sharing.client_alias", AuditPayloadHash: sha256.Sum256([]byte(event.AuditPayload)), OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256([]byte(event.OutboxPayload)),
		})
		if err != nil {
			t.Fatal(err)
		}
		event.EventID, event.OutboxID, event.EventHash = eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])
	}
	encoded, err := json.Marshal(proof.Events)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertAliasWorkerAuthorityRejections(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, generation, providerEpoch, consumerEpoch int64) {
	t.Helper()
	for _, test := range []struct {
		name, mutation, mode string
		staleEpoch           bool
	}{
		{name: "changed accepted offer", mutation: `UPDATE mesh.share_offer SET accepted_contract_public_id='01890fb0-0000-7000-8000-000000004190' WHERE id=(SELECT share_offer_id FROM mesh.trust_contract WHERE id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID))`, mode: "reserve"},
		{name: "changed export semantics", mutation: `UPDATE mesh.resource_export SET resource_semantic_hash=decode(repeat('ab',32),'hex') WHERE id=(SELECT resource_export_id FROM mesh.trust_contract WHERE id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID))`, mode: "reserve"},
		{name: "missing current client claim", mutation: `DELETE FROM mesh.device_alias_client_version WHERE device_id=(SELECT id FROM mesh.device WHERE public_id=$1::UUID)`, mode: "reserve"},
		{name: "missing active rule", mutation: `DELETE FROM mesh.compiled_policy_imported_resource_destination WHERE trust_contract_id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID)`, mode: "ready"},
		{name: "stale consumer key", mode: "reserve", staleEpoch: true},
	} {
		t.Run("guarded alias rejects "+test.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT reject_alias_authority`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT reject_alias_authority`); err != nil {
					t.Fatal(err)
				}
			}()
			if test.mutation != "" {
				if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				selector := endpointID
				if test.name == "missing current client claim" {
					selector = consumerID
				}
				if _, err := tx.Exec(ctx, test.mutation, selector); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=origin`); err != nil {
					t.Fatal(err)
				}
			}
			epoch := consumerEpoch
			if test.staleEpoch {
				epoch++
			}
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_worker`); err != nil {
				t.Fatal(err)
			}
			var encoded []byte
			err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_change_v2($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`,
				deploymentID, endpointID, consumerID, generation, providerEpoch, epoch, []string{"01890fb0-0000-7000-8000-000000004101", "01890fb0-0000-7000-8000-000000004102", "01890fb0-0000-7000-8000-000000004103", "01890fb0-0000-7000-8000-000000004104"}, "01890fb0-0000-7000-8000-000000004180", "01890fb0-0000-7000-8000-000000004181", test.mode).Scan(&encoded)
			code := "40001"
			if test.name == "missing active rule" {
				code = "23514"
			}
			requireDeviceAliasCode(t, err, code)
		})
	}
}

func assertAliasWorkerWithdrawal(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string, generation int64, provider, consumer aliasMapIdentity) {
	t.Helper()
	for _, mode := range []string{"withdraw", "quarantine_consumer", "quarantine_resource"} {
		for _, evidence := range []string{"missing", "complete", "expired"} {
			if mode == "withdraw" && evidence == "expired" {
				continue
			}
			t.Run(mode+" "+evidence, func(t *testing.T) {
				if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_withdrawal`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_withdrawal`); err != nil {
						t.Fatal(err)
					}
				}()
				if evidence == "expired" {
					if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica;
      UPDATE mesh.device_alias_lease SET expires_at=clock_timestamp()-INTERVAL '1 millisecond' WHERE private_endpoint_id=(SELECT id FROM mesh.private_endpoint WHERE public_id=$1::UUID);
      SET LOCAL session_replication_role=origin`, pgx.QueryExecModeSimpleProtocol, endpointID); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_worker`); err != nil {
					t.Fatal(err)
				}
				var body []byte
				change := "01890fb0-0000-7000-8000-000000004201"
				if err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::UUID,$6::TEXT)`, deploymentID, endpointID, consumerID, generation, change, mode).Scan(&body); err != nil {
					t.Fatal(err)
				}
				var proof aliasWorkerProof
				if err := json.Unmarshal(body, &proof); err != nil || !proof.Changed || proof.Action != "sharing.device_alias."+mode {
					t.Fatal("invalid withdrawal proof", err)
				}
				if evidence == "missing" {
					_, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
					requireDeviceAliasCode(t, err, "23514")
					return
				}
				events := hashIntegrationAliasEvidence(t, proof, 4220)
				var count int
				if err := tx.QueryRow(ctx, `SELECT mesh_ops.finalize_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::JSONB)`, deploymentID, endpointID, generation, change, mode, events).Scan(&count); err != nil || count != 2 {
					t.Fatal("withdrawal finalization", err)
				}
				if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE; SET CONSTRAINTS ALL DEFERRED`); err != nil {
					t.Fatal(err)
				}
				assertAliasMapCount(ctx, t, tx, provider, 0)
				assertAliasMapCount(ctx, t, tx, consumer, 0)
				if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
					t.Fatal(err)
				}
				var resources, sources int
				var safe bool
				if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE alias_role='resource' AND state='reserved'),count(*) FILTER(WHERE alias_role='consumer_source' AND state='reserved'),
      bool_and(state<>'quarantined' OR quarantine_until>=GREATEST(updated_at,expires_at)+INTERVAL '24 hours') FROM mesh.device_alias_lease WHERE private_endpoint_id=(SELECT id FROM mesh.private_endpoint WHERE public_id=$1::UUID)`, endpointID).Scan(&resources, &sources, &safe); err != nil || !safe {
					t.Fatal("unsafe quarantine", err)
				}
				wantResources, wantSources := 2, 4
				if mode == "quarantine_resource" {
					wantResources = 0
				}
				if mode == "quarantine_consumer" {
					wantSources = 2
				}
				if resources != wantResources || sources != wantSources {
					t.Fatalf("withdrawal crossed alias role: resources=%d sources=%d", resources, sources)
				}
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_worker`); err != nil {
					t.Fatal(err)
				}
				if err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::UUID,$6::TEXT)`, deploymentID, endpointID, consumerID, generation, "01890fb0-0000-7000-8000-000000004231", mode).Scan(&body); err != nil {
					t.Fatal(err)
				}
				if string(body) != `{"events": [], "changed": false}` {
					t.Fatal("withdrawal replay mutated state")
				}
			})
		}
	}
}
