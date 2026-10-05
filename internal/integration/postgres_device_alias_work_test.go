//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"testing"
)

type aliasWorkPage struct {
	Items []struct {
		EndpointID string `json:"endpoint_id"`
		ConsumerID string `json:"consumer_id"`
		Mode       string `json:"mode"`
	} `json:"items"`
	Cursor struct {
		EndpointID *string `json:"endpoint_id"`
		ConsumerID *string `json:"consumer_id"`
	} `json:"cursor"`
	Done bool `json:"done"`
}

func assertAliasWorkCandidates(ctx context.Context, t *testing.T, tx pgx.Tx, deploymentID, endpointID, consumerID string) {
	t.Helper()
	for _, test := range []struct {
		name, mutation string
		want           string
	}{
		{name: "current rule and leases", want: "ready"},
		{name: "no current rule", mutation: `DELETE FROM mesh.compiled_policy_imported_resource_destination WHERE trust_contract_id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID)`},
		{name: "no client claim", mutation: `DELETE FROM mesh.device_alias_client_version WHERE device_id=(SELECT id FROM mesh.device WHERE public_id=$1::UUID)`},
		{name: "missing active target", mutation: `DELETE FROM mesh.resource_device_target WHERE resource_id=(SELECT resource_id FROM mesh.trust_contract WHERE id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID))`, want: "quarantine_resource"},
		{name: "changed import", mutation: `UPDATE mesh.imported_resource SET version=version+1 WHERE id=(SELECT imported_resource_id FROM mesh.private_endpoint WHERE public_id=$1::UUID)`, want: "quarantine_resource"},
		{name: "orphan Resource aliases", mutation: `UPDATE mesh.share_offer SET accepted_contract_public_id='01890fb0-0000-7000-8000-000000004190' WHERE id=(SELECT share_offer_id FROM mesh.trust_contract WHERE id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID));
DELETE FROM mesh.device_alias_lease WHERE private_endpoint_id=(SELECT id FROM mesh.private_endpoint WHERE public_id=$1::UUID) AND alias_role='consumer_source';
DELETE FROM mesh.device_alias_client_readiness WHERE private_endpoint_id=(SELECT id FROM mesh.private_endpoint WHERE public_id=$1::UUID);
DELETE FROM mesh.compiled_policy_imported_resource_destination WHERE trust_contract_id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID)`, want: "quarantine_resource"},
		{name: "terminal offer", mutation: `UPDATE mesh.share_offer SET accepted_contract_public_id='01890fb0-0000-7000-8000-000000004190' WHERE id=(SELECT share_offer_id FROM mesh.trust_contract WHERE id=(SELECT trust_contract_id FROM mesh.private_endpoint WHERE public_id=$1::UUID))`, want: "quarantine_resource"},
	} {
		t.Run("alias work "+test.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, `RESET ROLE; SAVEPOINT alias_work_hints`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_work_hints`); err != nil {
					t.Fatal(err)
				}
			}()
			if test.mutation != "" {
				selector := endpointID
				if test.name == "no client claim" {
					selector = consumerID
				}
				if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, test.mutation, pgx.QueryExecModeSimpleProtocol, selector); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=origin`); err != nil {
					t.Fatal(err)
				}
			}
			var before int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.authority_mutation WHERE transaction_id=(pg_current_xact_id()::TEXT)::BIGINT`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_worker;SELECT set_config('mesh.workspace_id','999',TRUE),set_config('mesh.network_id','999',TRUE),set_config('mesh.alias_worker_endpoint_public_id','01890fb0-0000-7000-8000-000000004199',TRUE)`); err != nil {
				t.Fatal(err)
			}
			var afterEndpoint, afterConsumer *string
			found := false
			seen := map[string]bool{}
			for pageNumber := 0; pageNumber < 32; pageNumber++ {
				var body []byte
				if err := tx.QueryRow(ctx, `SELECT mesh_ops.load_device_alias_work_v2($1::UUID,$2::UUID,$3::UUID,1)`, deploymentID, afterEndpoint, afterConsumer).Scan(&body); err != nil {
					t.Fatal(err)
				}
				var page aliasWorkPage
				if err := json.Unmarshal(body, &page); err != nil || page.Items == nil || len(page.Items) > 1 {
					t.Fatal("invalid work page", err)
				}
				for _, item := range page.Items {
					key := item.EndpointID + item.ConsumerID
					if seen[key] {
						t.Fatal("work cursor repeated a pair")
					}
					seen[key] = true
					if item.EndpointID == endpointID && (item.ConsumerID == consumerID || item.ConsumerID == "" && test.want == "quarantine_resource") {
						if item.Mode != test.want || test.want == "" {
							t.Fatalf("unexpected alias work: %s want %s", item.Mode, test.want)
						}
						found = true
					}
				}
				if page.Done {
					break
				}
				if page.Cursor.EndpointID == nil || pageNumber == 31 {
					t.Fatal("work pagination failed to finish")
				}
				afterEndpoint, afterConsumer = page.Cursor.EndpointID, page.Cursor.ConsumerID
			}
			if found != (test.want != "") {
				t.Fatal("expected alias work hint absent")
			}
			var restored bool
			if err := tx.QueryRow(ctx, `SELECT current_setting('mesh.workspace_id')='999' AND current_setting('mesh.network_id')='999' AND current_setting('mesh.alias_worker_endpoint_public_id')='01890fb0-0000-7000-8000-000000004199'`).Scan(&restored); err != nil || !restored {
				t.Fatal("work scope leaked", err)
			}
			if test.name == "orphan Resource aliases" {
				var generation int64
				if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
					t.Fatal(err)
				}
				if err := tx.QueryRow(ctx, `SELECT generation FROM mesh.private_endpoint WHERE public_id=$1::UUID`, endpointID).Scan(&generation); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_worker`); err != nil {
					t.Fatal(err)
				}
				var encoded []byte
				change := "01890fb0-0000-7000-8000-000000004251"
				if err := tx.QueryRow(ctx, `SELECT mesh_ops.prepare_device_alias_resource_quarantine_v2($1::UUID,$2::UUID,$3::BIGINT,$4::UUID)`, deploymentID, endpointID, generation, change).Scan(&encoded); err != nil {
					t.Fatal(err)
				}
				var proof aliasWorkerProof
				if err := json.Unmarshal(encoded, &proof); err != nil || !proof.Changed {
					t.Fatal("orphan resource prepare", err)
				}
				events := hashIntegrationAliasEvidence(t, proof, 4260)
				var finalized int
				if err := tx.QueryRow(ctx, `SELECT mesh_ops.finalize_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,'quarantine_resource',$5::JSONB)`, deploymentID, endpointID, generation, change, events).Scan(&finalized); err != nil || finalized != 2 {
					t.Fatal("orphan resource evidence", err)
				}
				if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE;SET CONSTRAINTS ALL DEFERRED`); err != nil {
					t.Fatal(err)
				}
				return
			}
			if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
				t.Fatal(err)
			}
			var after int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.authority_mutation WHERE transaction_id=(pg_current_xact_id()::TEXT)::BIGINT`).Scan(&after); err != nil || before != after {
				t.Fatal("work discovery mutated authority", err)
			}
		})
	}
	for _, test := range []struct {
		role, installation string
		limit              int
		code               string
	}{
		{role: "mesh_worker", installation: "01890fb0-0000-7000-8000-000000004198", limit: 1, code: "42501"},
		{role: "mesh_runtime", installation: deploymentID, limit: 1, code: "42501"},
		{role: "mesh_worker", installation: deploymentID, limit: 129, code: "22023"},
	} {
		if _, err := tx.Exec(ctx, `RESET ROLE;SAVEPOINT alias_work_denied`); err != nil {
			t.Fatal(err)
		}
		if test.role == "mesh_worker" {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_worker`); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
				t.Fatal(err)
			}
		}
		var body []byte
		err := tx.QueryRow(ctx, `SELECT mesh_ops.load_device_alias_work_v2($1::UUID,NULL,NULL,$2::INTEGER)`, test.installation, test.limit).Scan(&body)
		requireDeviceAliasCode(t, err, test.code)
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT alias_work_denied`); err != nil {
			t.Fatal(err)
		}
	}
}
