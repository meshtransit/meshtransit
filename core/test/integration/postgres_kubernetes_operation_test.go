//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/kubeaudit"
	"meshtransit.net/core/internal/domain/publicid"
)

// operationRow is one intent as control hands schema 245's writer.
func operationRow(t *testing.T, gateway, peer string, intent byte, digest string) map[string]any {
	t.Helper()
	return map[string]any{
		"gateway": gateway, "intent_id": hex.EncodeToString(append(make([]byte, 15), intent)), "digest": digest,
		"audit_id": mustPublicID(t).String(), "peer": peer, "owner_kind": "member", "owner_ref": "p:1",
		"network_revision": 7, "class": "write", "groups": []string{"edit"}, "verb": "delete",
		"api_group": "apps", "resource": "deployments", "subresource": "", "namespace": "default",
		"name": "web", "impersonated": "", "token_id": "0a0b", "observed_ms": time.Now().UnixMilli(),
		"clock_skew": false,
	}
}

func recordOperations(ctx context.Context, t *testing.T, runtime *pgx.Conn, rows ...map[string]any) []map[string]any {
	t.Helper()
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	var answer string
	if err := runtime.QueryRow(ctx, `SELECT mesh_ops.record_kubernetes_operations_v1($1::JSONB)::TEXT`,
		string(encoded)).Scan(&answer); err != nil {
		t.Fatalf("record operations: %v", err)
	}
	var decoded struct {
		Answers []map[string]any `json:"answers"`
	}
	if err := json.Unmarshal([]byte(answer), &decoded); err != nil || len(decoded.Answers) != len(rows) {
		t.Fatalf("answers %s: %v", answer, err)
	}
	return decoded.Answers
}

// assertKubernetesOperations qualifies schema 245 (K1b0 design §4): a
// gateway's type A intents are recorded under the gateway its keys name,
// for a peer of its own Network; sent again they answer the first audit_id,
// with other content conflict; rows never change; outcomes and denials go
// under the gateway that sent them; partitions are kept; only the roles
// named run each function.
func assertKubernetesOperations(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, keys replicaKeys, deviceID string,
) {
	t.Helper()
	gateway := hex.EncodeToString(fingerprintOf(keys)) + ":" + hex.EncodeToString(nodeKeyOf(keys))
	var peer string
	if err := admin.QueryRow(ctx, `SELECT peer.public_id::TEXT FROM mesh.device AS peer
JOIN mesh.device AS gateway ON gateway.workspace_id = peer.workspace_id AND gateway.network_id = peer.network_id
WHERE gateway.public_id = $1::UUID AND peer.kind <> 'kubernetes_gateway' AND peer.state = 'active'
  AND peer.deleted_at IS NULL
ORDER BY peer.id LIMIT 1`, deviceID).Scan(&peer); err != nil {
		t.Fatalf("a standard Device of the gateway's Network: %v", err)
	}
	digest := func(text string) string {
		sum := sha256.Sum256([]byte(text))
		return hex.EncodeToString(sum[:])
	}
	first := operationRow(t, gateway, peer, 1, digest("first"))
	otherGateway := operationRow(t, hex.EncodeToString(make([]byte, 32))+":"+hex.EncodeToString(make([]byte, 32)),
		peer, 2, digest("other"))
	selfPeer := operationRow(t, gateway, deviceID, 3, digest("self"))
	unknownPeer := operationRow(t, gateway, mustPublicID(t).String(), 4, digest("unknown"))
	answers := recordOperations(ctx, t, runtime, first, otherGateway, selfPeer, unknownPeer)
	for index, want := range []string{"accepted", "gateway", "device", "device"} {
		if answers[index]["outcome"] != want {
			t.Fatalf("answer %d = %v, want %s", index, answers[index], want)
		}
	}
	if answers[0]["audit_id"] != first["audit_id"] {
		t.Fatalf("accepted answer %v", answers[0])
	}
	// Sent again: the first audit_id; another content: conflict.
	again := operationRow(t, gateway, peer, 1, digest("first"))
	changed := operationRow(t, gateway, peer, 1, digest("changed"))
	answers = recordOperations(ctx, t, runtime, again, changed)
	if answers[0]["outcome"] != "duplicate" || answers[0]["audit_id"] != first["audit_id"] ||
		answers[1]["outcome"] != "conflict" || answers[1]["audit_id"] != nil {
		t.Fatalf("sent again: %v", answers)
	}
	// The row is the gateway's, for its cluster and Network, as recorded.
	var cluster, peerID, gatewayID int64
	var groups []string
	if err := admin.QueryRow(ctx, `SELECT operation.kubernetes_cluster_id, operation.peer_device_id,
    operation.gateway_device_id, operation.groups
FROM mesh_audit.kubernetes_operation AS operation WHERE operation.audit_id = $1::UUID`,
		first["audit_id"]).Scan(&cluster, &peerID, &gatewayID, &groups); err != nil {
		t.Fatal(err)
	}
	var expectedGateway int64
	if err := admin.QueryRow(ctx, `SELECT id FROM mesh.device WHERE public_id = $1::UUID`, deviceID).Scan(
		&expectedGateway); err != nil || gatewayID != expectedGateway || len(groups) != 1 || cluster == 0 {
		t.Fatalf("recorded gateway %d (want %d), groups %v, cluster %d: %v", gatewayID, expectedGateway, groups,
			cluster, err)
	}
	assertKubernetesOperationStore(ctx, t, runtimePool, keys, peer)
	assertKubernetesOperationProfiles(ctx, t, admin, runtimePool, keys, peer)
	// Append only.
	if _, err := admin.Exec(ctx, `UPDATE mesh_audit.kubernetes_operation SET verb = 'get'
WHERE audit_id = $1::UUID`, first["audit_id"]); sqlState(t, err) != "42501" {
		t.Fatalf("an operation changed: %v", err)
	}
	// One gateway's intent out of form, or sent twice in one batch, is
	// answered on its own; the other rows of the batch are recorded (review
	// b0a H1, H2).
	malformed := operationRow(t, gateway, peer, 6, digest("malformed"))
	malformed["observed_ms"] = "99999999999999999999"
	malformed["intent_id"] = "ZZ"
	twice := operationRow(t, gateway, peer, 7, digest("twice"))
	twiceAgain := operationRow(t, gateway, peer, 7, digest("twice"))
	twiceChanged := operationRow(t, gateway, peer, 7, digest("twice changed"))
	valid := operationRow(t, gateway, peer, 8, digest("valid"))
	answers = recordOperations(ctx, t, runtime, malformed, twice, twiceAgain, twiceChanged, valid)
	if answers[0]["outcome"] != "invalid" || answers[1]["outcome"] != "accepted" ||
		answers[2]["outcome"] != "duplicate" || answers[2]["audit_id"] != twice["audit_id"] ||
		answers[3]["outcome"] != "conflict" || answers[4]["outcome"] != "accepted" {
		t.Fatalf("a mixed batch: %v", answers)
	}
	var recorded int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.kubernetes_operation
WHERE audit_id IN ($1::UUID, $2::UUID, $3::UUID)`, twice["audit_id"], twiceAgain["audit_id"],
		valid["audit_id"]).Scan(&recorded); err != nil || recorded != 2 {
		t.Fatalf("recorded %d of the mixed batch (%v), want 2", recorded, err)
	}
	// Only at READ COMMITTED.
	tx, err := runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	encodedRows, _ := json.Marshal([]any{operationRow(t, gateway, peer, 9, digest("rr"))})
	_, err = tx.Exec(ctx, `SELECT mesh_ops.record_kubernetes_operations_v1($1::JSONB)`, string(encodedRows))
	_ = tx.Rollback(ctx)
	if sqlState(t, err) != "25001" {
		t.Fatalf("recorded at REPEATABLE READ: %v", err)
	}
	// A clock out of range refuses the whole batch.
	late := operationRow(t, gateway, peer, 5, digest("late"))
	late["audit_id"] = "01890f00-0000-7000-8000-000000000001"
	encoded, _ := json.Marshal([]any{late})
	if _, err := runtime.Exec(ctx, `SELECT mesh_ops.record_kubernetes_operations_v1($1::JSONB)`,
		string(encoded)); sqlState(t, err) != "22023" {
		t.Fatalf("a batch of another clock: %v", err)
	}

	// Outcomes and denials go under the gateway that sent them; an unknown
	// gateway's are skipped.
	outcomes, _ := json.Marshal([]map[string]any{
		{"gateway": gateway, "audit_id": first["audit_id"], "status": 200, "duration_ms": 12},
		{"gateway": otherGateway["gateway"], "audit_id": first["audit_id"], "status": 500, "duration_ms": 1},
	})
	denials, _ := json.Marshal([]map[string]any{
		{"gateway": gateway, "peer": peer, "reason": "forbidden", "count": 3,
			"first_ms": time.Now().Add(-time.Second).UnixMilli(), "last_ms": time.Now().UnixMilli()},
	})
	var written string
	if err := runtime.QueryRow(ctx, `SELECT mesh_ops.record_kubernetes_operation_outcomes_v1($1::JSONB,
    $2::JSONB)::TEXT`, string(outcomes), string(denials)).Scan(&written); err != nil ||
		written != `{"denials": 1, "outcomes": 1}` {
		t.Fatalf("outcomes = %s, %v", written, err)
	}

	// Partitions: three months ahead; a month past retention is dropped.
	if _, err := admin.Exec(ctx, `CREATE TABLE mesh_audit.kubernetes_operation_denial_2020_01
PARTITION OF mesh_audit.kubernetes_operation_denial
FOR VALUES FROM ('2020-01-01 00:00:00+00') TO ('2020-02-01 00:00:00+00')`); err != nil {
		t.Fatal(err)
	}
	var maintained string
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.maintain_kubernetes_operation_partitions_v1(13)::TEXT`).Scan(
		&maintained); err != nil || maintained != `{"ahead": 3, "dropped": ["kubernetes_operation_denial_2020_01"]}` {
		t.Fatalf("maintain = %s, %v", maintained, err)
	}

	// Roles: the runtime records; only the worker maintains and erases.
	for role, functions := range map[string]map[string]bool{
		"mesh_runtime": {
			"mesh_ops.record_kubernetes_operations_v1(jsonb)":                    true,
			"mesh_ops.record_kubernetes_operation_outcomes_v1(jsonb, jsonb)":     true,
			"mesh_ops.record_kubernetes_operations_v2(jsonb)":                    true,
			"mesh_ops.record_kubernetes_operation_outcomes_v2(jsonb, jsonb)":     true,
			"mesh_ops.maintain_kubernetes_operation_partitions_v1(integer)":      false,
			"mesh_ops.erase_kubernetes_operations_v1(uuid, text, text, integer)": false,
			"mesh_ops.ensure_kubernetes_operation_partitions_v1(integer)":        false,
		},
		"mesh_worker": {
			"mesh_ops.record_kubernetes_operations_v1(jsonb)":                    false,
			"mesh_ops.record_kubernetes_operations_v2(jsonb)":                    false,
			"mesh_ops.record_kubernetes_operation_outcomes_v2(jsonb, jsonb)":     false,
			"mesh_ops.maintain_kubernetes_operation_partitions_v1(integer)":      true,
			"mesh_ops.erase_kubernetes_operations_v1(uuid, text, text, integer)": true,
		},
		"mesh_observer": {
			"mesh_ops.record_kubernetes_operations_v1(jsonb)":                    false,
			"mesh_ops.record_kubernetes_operations_v2(jsonb)":                    false,
			"mesh_ops.erase_kubernetes_operations_v1(uuid, text, text, integer)": false,
		},
	} {
		for function, want := range functions {
			var granted bool
			if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege($1, $2, 'EXECUTE')`, role,
				function).Scan(&granted); err != nil || granted != want {
				t.Fatalf("%s on %s = %v (%v), want %v", role, function, granted, err, want)
			}
		}
	}
	for _, table := range []string{"kubernetes_operation", "kubernetes_operation_outcome", "kubernetes_operation_denial"} {
		var readable bool
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege('mesh_runtime', $1, 'SELECT')
    OR pg_catalog.has_table_privilege('mesh_runtime', $1, 'DELETE')`, "mesh_audit."+table).Scan(
			&readable); err != nil || readable {
			t.Fatalf("mesh_runtime reads or deletes %s directly (%v)", table, err)
		}
	}

	// Erasing the Workspace removes its rows a batch at a time, and records
	// who asked each time.
	erase := func() string {
		t.Helper()
		var erased string
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.erase_kubernetes_operations_v1(workspace.public_id,
    'soc@example.com', 'ERASE-1', 2)::TEXT
FROM mesh.device AS device JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
WHERE device.public_id = $1::UUID`, deviceID).Scan(&erased); err != nil {
			t.Fatalf("erase: %v", err)
		}
		return erased
	}
	// This test's three operations and the stores' two; two outcomes and
	// three denials (one of a profile, with its sample).
	if first, second, third := erase(), erase(), erase(); first != `{"denials": 2, "outcomes": 2, "remaining": true, "operations": 2}` ||
		second != `{"denials": 1, "outcomes": 0, "remaining": true, "operations": 2}` ||
		third != `{"denials": 0, "outcomes": 0, "remaining": false, "operations": 1}` {
		t.Fatalf("erase = %s, then %s, then %s", first, second, third)
	}
	var erasures int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.kubernetes_operation_erasure
WHERE actor = 'soc@example.com' AND change_ref = 'ERASE-1'`).Scan(&erasures); err != nil || erasures != 3 {
		t.Fatalf("erasures recorded %d (%v), want 3", erasures, err)
	}
}

// assertKubernetesOperationStore: the runtime store writes rows with
// synchronous commit and answers them; a duplicate sent again answers the
// first audit_id; reports go under the gateway (K1b0 b0b2).
func assertKubernetesOperationStore(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	keys replicaKeys, peer string,
) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesOperationStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	if granted, err := store.Granted(ctx); err != nil || !granted {
		t.Fatalf("Granted() = %v, %v", granted, err)
	}
	peerID, err := publicid.Parse(peer)
	if err != nil {
		t.Fatal(err)
	}
	gateway := kubeaudit.Gateway{MachineFingerprint: [32]byte(fingerprintOf(keys)), NodeKey: [32]byte(nodeKeyOf(keys))}
	row := func(last byte) kubeaudit.Row {
		now := time.Now()
		var id [16]byte
		millis := uint64(now.UnixMilli())
		for index := range 6 {
			id[5-index] = byte(millis >> (8 * index))
		}
		id[6], id[8], id[15] = 0x70, 0x80, last
		return kubeaudit.Row{Gateway: gateway, NetworkRevision: 7,
			Owner: kubeaudit.Owner{Kind: "member", Ref: "p:1"},
			Intent: kubeaudit.Intent{ID: id, Peer: peerID, Groups: []string{"edit"}, Class: kubeaudit.ClassExec,
				Verb: "create", Resource: "pods", Subresource: "exec", Namespace: "default", Name: "web-0",
				ObservedAt: now}}
	}
	// The store issues the audit_id; the same intent again answers it.
	first := row(1)
	answers, err := store.Record(ctx, []kubeaudit.Row{first})
	if err != nil || answers[0].Outcome != kubeaudit.OutcomeAccepted || !answers[0].AuditID.IsValid() {
		t.Fatalf("Record() = %+v, %v", answers, err)
	}
	firstID := answers[0].AuditID
	answers, err = store.Record(ctx, []kubeaudit.Row{first})
	if err != nil || answers[0].Outcome != kubeaudit.OutcomeDuplicate || answers[0].AuditID != firstID {
		t.Fatalf("Record(again) = %+v, %v", answers, err)
	}
	outcomes, denials, err := store.RecordReports(ctx, []kubeaudit.Reports{{Gateway: gateway,
		Finished: []kubeaudit.Finished{{AuditID: firstID, Status: 101, Duration: 3 * time.Second}},
		Denials: []kubeaudit.Denials{{Peer: peerID, Reason: kubeaudit.DenialForbidden, Count: 2,
			First: time.Now().Add(-time.Second), Last: time.Now()}},
	}})
	if err != nil || outcomes != 1 || denials != 1 {
		t.Fatalf("RecordReports() = %d, %d, %v", outcomes, denials, err)
	}
}

// assertKubernetesOperationProfiles qualifies schema 261 (K2 §29): an
// operation keeps the profile that let it through, and a denial of a
// profile reason its sample; a sample without a profile reason is not
// written.
func assertKubernetesOperationProfiles(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, keys replicaKeys, peer string,
) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesOperationStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := publicid.Parse(peer)
	if err != nil {
		t.Fatal(err)
	}
	gateway := kubeaudit.Gateway{MachineFingerprint: [32]byte(fingerprintOf(keys)), NodeKey: [32]byte(nodeKeyOf(keys))}
	now := time.Now()
	var id [16]byte
	millis := uint64(now.UnixMilli())
	for index := range 6 {
		id[5-index] = byte(millis >> (8 * index))
	}
	id[6], id[8], id[15] = 0x70, 0x80, 0x61
	scope := [32]byte{0x61, 0x62}
	answers, err := store.Record(ctx, []kubeaudit.Row{{Gateway: gateway, NetworkRevision: 7,
		Owner: kubeaudit.Owner{Kind: "member", Ref: "p:1"},
		Intent: kubeaudit.Intent{ID: id, Peer: peerID, Groups: []string{"edit"}, Class: kubeaudit.ClassWrite,
			Verb: "patch", Resource: "deployments", APIGroup: "apps", Namespace: "team-a", Name: "web",
			ObservedAt: now, Profile: scope[:], ReportAllowed: true}}})
	if err != nil || answers[0].Outcome != kubeaudit.OutcomeAccepted {
		t.Fatalf("Record(profile) = %+v, %v", answers, err)
	}
	var stored []byte
	var reported bool
	if err := admin.QueryRow(ctx, `SELECT profile_hash, report_allowed FROM mesh_audit.kubernetes_operation
WHERE audit_id = $1::UUID`, answers[0].AuditID.String()).Scan(&stored, &reported); err != nil ||
		!bytes.Equal(stored, scope[:]) || !reported {
		t.Fatalf("stored profile = %x %v, %v", stored, reported, err)
	}
	sample := &kubeaudit.DenialSample{Verb: "delete", Resource: "pods", Namespace: "team-a", Scope: scope}
	_, denials, err := store.RecordReports(ctx, []kubeaudit.Reports{{Gateway: gateway, Denials: []kubeaudit.Denials{
		{Peer: peerID, Reason: kubeaudit.DenialProfile, Count: 3, First: now.Add(-time.Second), Last: now,
			Sample: sample},
		{Peer: peerID, Reason: kubeaudit.DenialForbidden, Count: 1, First: now.Add(-time.Second), Last: now,
			Sample: sample},
	}}})
	if err != nil || denials != 1 {
		t.Fatalf("RecordReports(samples) = %d, %v", denials, err)
	}
	// Sent again: the same profile is a duplicate of the first, another
	// report_allowed a conflict.
	again, err := store.Record(ctx, []kubeaudit.Row{{Gateway: gateway, NetworkRevision: 7,
		Owner: kubeaudit.Owner{Kind: "member", Ref: "p:1"},
		Intent: kubeaudit.Intent{ID: id, Peer: peerID, Groups: []string{"edit"}, Class: kubeaudit.ClassWrite,
			Verb: "patch", Resource: "deployments", APIGroup: "apps", Namespace: "team-a", Name: "web",
			ObservedAt: now, Profile: scope[:], ReportAllowed: true}}})
	if err != nil || again[0].Outcome != kubeaudit.OutcomeDuplicate || again[0].AuditID != answers[0].AuditID {
		t.Fatalf("Record(profile again) = %+v, %v", again, err)
	}
	other, err := store.Record(ctx, []kubeaudit.Row{{Gateway: gateway, NetworkRevision: 7,
		Owner: kubeaudit.Owner{Kind: "member", Ref: "p:1"},
		Intent: kubeaudit.Intent{ID: id, Peer: peerID, Groups: []string{"edit"}, Class: kubeaudit.ClassWrite,
			Verb: "patch", Resource: "deployments", APIGroup: "apps", Namespace: "team-a", Name: "web",
			ObservedAt: now, Profile: scope[:]}}})
	if err != nil || other[0].Outcome != kubeaudit.OutcomeConflict {
		t.Fatalf("Record(other report) = %+v, %v", other, err)
	}
	assertKubernetesOperationProfileInput(ctx, t, admin, gateway, peer)
	assertKubernetesOperationFuturePartition(ctx, t, admin)
	var verb, namespace string
	var sampled []byte
	if err := admin.QueryRow(ctx, `SELECT sample_verb, sample_namespace, sample_scope
FROM mesh_audit.kubernetes_operation_denial WHERE reason = 'profile_denied' ORDER BY recorded_at DESC LIMIT 1`).Scan(
		&verb, &namespace, &sampled); err != nil || verb != "delete" || namespace != "team-a" ||
		!bytes.Equal(sampled, scope[:]) {
		t.Fatalf("stored sample = %s %s %x, %v", verb, namespace, sampled, err)
	}
}

// assertKubernetesOperationProfileInput: the v2 writer refuses a profile or
// report_allowed out of form as invalid, and skips a denial whose sample is
// out of form (review d4a M3).
func assertKubernetesOperationProfileInput(ctx context.Context, t *testing.T, admin *pgx.Conn,
	gateway kubeaudit.Gateway, peer string,
) {
	t.Helper()
	key := hex.EncodeToString(gateway.MachineFingerprint[:]) + ":" + hex.EncodeToString(gateway.NodeKey[:])
	scope := strings.Repeat("ab", 32)
	for name, change := range map[string]func(map[string]any){
		"upper case profile":       func(row map[string]any) { row["profile"] = strings.ToUpper(scope) },
		"short profile":            func(row map[string]any) { row["profile"] = scope[:62] },
		"empty profile":            func(row map[string]any) { row["profile"] = "" },
		"report as a string":       func(row map[string]any) { row["profile"], row["report_allowed"] = scope, "true" },
		"report without a profile": func(row map[string]any) { row["report_allowed"] = true },
	} {
		row := operationRow(t, key, peer, 0x70, strings.Repeat("cd", 32))
		change(row)
		encoded, err := json.Marshal([]map[string]any{row})
		if err != nil {
			t.Fatal(err)
		}
		var answer string
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.record_kubernetes_operations_v2($1::JSONB)::TEXT`,
			string(encoded)).Scan(&answer); err != nil || !strings.Contains(answer, `"invalid"`) {
			t.Errorf("%s: %s, %v", name, answer, err)
		}
	}
	denial := func(sample map[string]any) string {
		encoded, _ := json.Marshal([]map[string]any{{"gateway": key, "peer": peer, "reason": "profile_denied",
			"count": "1", "first_ms": fmt.Sprint(time.Now().UnixMilli()), "last_ms": fmt.Sprint(time.Now().UnixMilli()),
			"sample": sample}})
		return string(encoded)
	}
	for name, sample := range map[string]map[string]any{
		"no scope":       {"verb": "get", "api_group": "", "resource": "pods", "subresource": "", "namespace": "a"},
		"short scope":    {"verb": "get", "api_group": "", "resource": "pods", "subresource": "", "namespace": "a", "scope": scope[:63]},
		"no subresource": {"verb": "get", "api_group": "", "resource": "pods", "namespace": "a", "scope": scope},
		"not an object":  nil,
	} {
		payload := denial(sample)
		if name == "not an object" {
			payload = strings.Replace(denial(map[string]any{}), `"sample":{}`, `"sample":"get"`, 1)
		}
		var answer string
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.record_kubernetes_operation_outcomes_v2('[]'::JSONB,
    $1::JSONB)::TEXT`, payload).Scan(&answer); err != nil || !strings.Contains(answer, `"denials": 0`) {
			t.Errorf("sample %s: %s, %v", name, answer, err)
		}
	}
}

// assertKubernetesOperationFuturePartition: a partition made after schema
// 261 has the profile columns and their constraints (review d4a M3).
func assertKubernetesOperationFuturePartition(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.ensure_kubernetes_operation_partitions_v1(4)`); err != nil {
		t.Fatal(err)
	}
	insert := func(profile []byte) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT future`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, `WITH id AS (SELECT pg_catalog.uuidv7(INTERVAL '75 days') AS value)
INSERT INTO mesh_audit.kubernetes_operation (received_at, audit_id, workspace_id, network_id, kubernetes_cluster_id,
    gateway_device_id, peer_device_id, owner_kind, owner_ref, network_revision, class, groups, verb, api_group,
    resource, subresource, namespace, name, impersonated, token_id, observed_at, clock_skew, intent_id,
    intent_digest, profile_hash, report_allowed)
SELECT pg_catalog.uuid_extract_timestamp(id.value), id.value, 1, 1, 1, 1, 1, 'member', 'p:1', 1, 'write',
    '{edit}', 'get', '', 'pods', '', 'a', 'web', '', ''::BYTEA, pg_catalog.now(), FALSE,
    pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex'), pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
    $1::BYTEA, $1::BYTEA IS NOT NULL
FROM id`, profile)
		if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT future`); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		return err
	}
	if err := insert(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("a profiled row in a new month: %v", err)
	}
	if err := insert(bytes.Repeat([]byte{1}, 16)); err == nil || !strings.Contains(err.Error(), "23514") {
		t.Fatalf("a short profile in a new month: %v", err)
	}
}
