//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/adapter/kubecustody"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// clusterCAFixture is what the CA assertions share: the worker's store, its
// installation, and the Network's data key in the clear.
type clusterCAFixture struct {
	store        *postgresadapter.KubernetesClusterCAStore
	installation deployment.ID
	scope        network.Scope
	cluster      publicid.ID
	dataKeyID    publicid.ID
	dataKey      kubeca.DataKey
	dnsName      string
}

// newClusterCA generates a CA for the fixture's cluster, sealed under its
// data key.
func (fixture clusterCAFixture) newClusterCA(t *testing.T, state kubeca.State, reason kubeca.Reason) *kubeca.Creation {
	t.Helper()
	ca, err := kubeca.NewCA(kubeca.CAParams{
		ClusterDNSName: fixture.dnsName, Subject: "prod",
		NotBefore: time.Now(), Lifetime: 2 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := mustPublicID(t)
	sealed, err := kubeca.SealCA(fixture.dataKey, ca, fixture.installation.String(), fixture.cluster.String(),
		id.String())
	if err != nil {
		t.Fatal(err)
	}
	certificate := ca.Certificate()
	return &kubeca.Creation{
		Cluster: fixture.cluster, ID: id, State: state, Reason: reason, DataKeyID: fixture.dataKeyID,
		Certificate: certificate.Raw, ClusterDNSName: fixture.dnsName, NotBefore: certificate.NotBefore,
		NotAfter: certificate.NotAfter, SealedKey: sealed,
	}
}

// change applies changes to the fixture's Network and returns what the
// worker read under the lock.
func (fixture clusterCAFixture) change(ctx context.Context, t *testing.T, changes kubeca.Changes) kubeca.Network {
	t.Helper()
	var seen kubeca.Network
	busy, err := fixture.store.Change(ctx, fixture.installation, fixture.scope,
		func(read kubeca.Network) (kubeca.Changes, error) {
			seen = read
			return changes, nil
		})
	if err != nil || busy {
		t.Fatalf("Change() = %v, %v", busy, err)
	}
	return seen
}

// assertKubernetesClusterCAs qualifies schema 238 on an active cluster:
// only the worker reads and writes CAs, under the Network's lock; every CA
// row change is a sealed audit event without key material; CAs only move
// forward and drop their sealed key when they stop signing; the schedule is
// bounded; heartbeats say whether a worker can sign.
func assertKubernetesClusterCAs(ctx context.Context, t *testing.T, admin, worker *pgx.Conn,
	workerPool *postgresadapter.Pool, scope network.Scope, clusterID kubecluster.ID,
) {
	t.Helper()
	assertClusterCAPrivileges(ctx, t, admin)
	store, err := postgresadapter.NewKubernetesClusterCAStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	var installationText string
	if err := admin.QueryRow(ctx, `SELECT deployment.installation_public_id::TEXT
FROM mesh.workspace AS workspace JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
WHERE workspace.public_id = $1::UUID`, scope.WorkspaceID().String()).Scan(&installationText); err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(installationText)
	if err != nil {
		t.Fatal(err)
	}
	fixture := clusterCAFixture{
		store: store, installation: installation, scope: scope,
		cluster: publicid.ID(clusterID),
	}

	// The new cluster is due at once.
	due, err := store.ListDue(ctx, installation, 256)
	if err != nil || !containsScope(due, scope) {
		t.Fatalf("ListDue() = %v, %v", due, err)
	}
	other, err := deployment.ParseID(mustPublicID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListDue(ctx, other, 10); err == nil {
		t.Fatal("another installation listed CA work")
	}

	// The Network's data key: the first stored wins.
	custody, err := kubecustody.NewFile(kubeca.DataKey(filledIntegrationKey(0x38)), nil)
	if err != nil {
		t.Fatal(err)
	}
	dataKey, wrapped, err := custody.NewDataKey(ctx, scope.NetworkID().String())
	if err != nil {
		t.Fatal(err)
	}
	dataKeyID := mustPublicID(t)
	stored, err := store.AddDataKey(ctx, installation, scope, dataKeyID, wrapped)
	if err != nil || stored.ID != dataKeyID || !stored.Active || stored.Wrapped.KeyID != wrapped.KeyID {
		t.Fatalf("AddDataKey() = %+v, %v", stored, err)
	}
	_, secondWrapped, err := custody.NewDataKey(ctx, scope.NetworkID().String())
	if err != nil {
		t.Fatal(err)
	}
	if again, err := store.AddDataKey(ctx, installation, scope, mustPublicID(t), secondWrapped); err != nil ||
		again.ID != dataKeyID || string(again.Wrapped.Ciphertext) != string(wrapped.Ciphertext) {
		t.Fatalf("a second data key = %+v, %v", again, err)
	}
	fixture.dataKeyID, fixture.dataKey = dataKeyID, dataKey

	// The worker reads the codes that name the cluster, and no CA yet.
	read := fixture.change(ctx, t, kubeca.Changes{})
	cluster := findCluster(t, read, fixture.cluster)
	if len(read.WorkspaceCode) != 12 || len(read.NetworkCode) != 12 || !cluster.Active || cluster.Name != "prod" ||
		len(cluster.CAs) != 0 || len(read.DataKeys) != 1 || read.Now.IsZero() {
		t.Fatalf("read = %+v", read)
	}
	fixture.dnsName = "prod.kube." + read.WorkspaceCode + "." + read.NetworkCode + ".mesh.test"

	// The first CA, active; the schedule is bounded to a day. Other
	// clusters of the Network are scheduled with it, as the worker batches
	// a Network.
	first := fixture.newClusterCA(t, kubeca.StateActive, kubeca.ReasonInitial)
	schedules := []kubeca.Schedule{{Cluster: fixture.cluster, At: time.Now().Add(10 * 24 * time.Hour)}}
	for _, other := range read.Clusters {
		if other.ID != fixture.cluster {
			schedules = append(schedules, kubeca.Schedule{Cluster: other.ID, At: time.Now().Add(time.Hour)})
		}
	}
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{{Create: first}}, Schedules: schedules})
	var nextAction time.Time
	if err := admin.QueryRow(ctx, `SELECT schedule.next_action_at FROM mesh_ops.kubernetes_cluster_ca_schedule AS schedule
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = schedule.kubernetes_cluster_id
WHERE cluster.public_id = $1::UUID`, clusterID.String()).Scan(&nextAction); err != nil ||
		time.Until(nextAction) > 25*time.Hour || time.Until(nextAction) < 23*time.Hour {
		t.Fatalf("next action at %v, %v", nextAction, err)
	}
	if due, err := store.ListDue(ctx, installation, 256); err != nil || containsScope(due, scope) {
		t.Fatalf("a scheduled Network is still due: %v, %v", due, err)
	}
	assertClusterCAEvents(ctx, t, admin, first.ID, "kubernetes_cluster.ca_created")

	// A second active CA is refused, and the whole change with it.
	duplicate := fixture.newClusterCA(t, kubeca.StateActive, kubeca.ReasonAdmin)
	next := fixture.newClusterCA(t, kubeca.StateNext, kubeca.ReasonScheduled)
	if busy, err := store.Change(ctx, installation, scope, func(kubeca.Network) (kubeca.Changes, error) {
		return kubeca.Changes{Steps: []kubeca.Step{{Create: next}, {Create: duplicate}}}, nil
	}); err == nil || busy {
		t.Fatalf("a second active CA: %v, %v", busy, err)
	}
	assertClusterCAState(ctx, t, admin, next.ID, "")

	// Rotation: a next CA is published, then takes over; the old one
	// retires and drops its sealed key.
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{{Create: next}}})
	read = fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{
		{Move: &kubeca.Move{CA: first.ID, Version: 1, To: kubeca.StateRetiring, Reason: kubeca.ReasonScheduled}},
		{Move: &kubeca.Move{CA: next.ID, Version: 1, To: kubeca.StateActive, Reason: kubeca.ReasonScheduled}},
	}})
	if cas := findCluster(t, read, fixture.cluster).CAs; len(cas) != 2 || cas[0].State != kubeca.StateActive ||
		cas[1].State != kubeca.StateNext || len(cas[0].SealedKey) == 0 {
		t.Fatalf("CAs before the rotation = %+v", cas)
	}
	read = fixture.change(ctx, t, kubeca.Changes{})
	cas := findCluster(t, read, fixture.cluster).CAs
	if len(cas) != 2 || cas[0].ID != first.ID || cas[0].State != kubeca.StateRetiring || cas[0].SealedKey != nil ||
		cas[0].Version != 2 || cas[0].RetiringAt.IsZero() || cas[1].State != kubeca.StateActive ||
		cas[1].Version != 2 || cas[1].ActivatedAt.IsZero() || len(cas[1].SealedKey) == 0 {
		t.Fatalf("CAs after the rotation = %+v", cas)
	}
	opened, err := kubeca.OpenCA(dataKey, cas[1].Certificate, cas[1].SealedKey, installation.String(),
		fixture.cluster.String(), next.ID.String())
	if err != nil || opened.Fingerprint() != sha256.Sum256(cas[1].Certificate) {
		t.Fatalf("the active CA does not open: %v", err)
	}
	assertClusterCAEvents(ctx, t, admin, first.ID, "kubernetes_cluster.ca_created", "kubernetes_cluster.ca_retiring")
	assertClusterCAEvents(ctx, t, admin, next.ID, "kubernetes_cluster.ca_created", "kubernetes_cluster.ca_activated")

	// A move from a version since changed is stale, and undoes the change.
	if _, err := store.Change(ctx, installation, scope, func(kubeca.Network) (kubeca.Changes, error) {
		return kubeca.Changes{Steps: []kubeca.Step{
			{Move: &kubeca.Move{CA: first.ID, Version: 2, To: kubeca.StateRetired, Reason: kubeca.ReasonScheduled}},
			{Move: &kubeca.Move{CA: next.ID, Version: 1, To: kubeca.StateRetired, Reason: kubeca.ReasonAdmin}},
		}}, nil
	}); !errors.Is(err, postgresadapter.ErrKubernetesClusterCAStale) {
		t.Fatalf("a stale move: %v", err)
	}
	assertClusterCAState(ctx, t, admin, first.ID, "retiring")

	// A Network another worker holds is busy, and nothing is planned.
	held, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('meshtransit/kubernetes-ca/' || $1, 0))`, scope.NetworkID().String()); err != nil {
		t.Fatal(err)
	}
	planned := false
	busy, err := store.Change(ctx, installation, scope, func(kubeca.Network) (kubeca.Changes, error) {
		planned = true
		return kubeca.Changes{}, nil
	})
	if err != nil || !busy || planned {
		t.Fatalf("Change() on a held Network = %v, %v, planned %v", busy, err, planned)
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// A CA only moves forward, and no row is deleted.
	assertClusterCAGuards(ctx, t, admin, first.ID)
	// The schedule of an active cluster never ends.
	if _, err := store.Change(ctx, installation, scope, func(kubeca.Network) (kubeca.Changes, error) {
		return kubeca.Changes{Schedules: []kubeca.Schedule{{Cluster: fixture.cluster, Done: true}}}, nil
	}); err == nil {
		t.Fatal("an active cluster's schedule ended")
	}
	// The retiring CA retires.
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{
		{Move: &kubeca.Move{CA: first.ID, Version: 2, To: kubeca.StateRetired, Reason: kubeca.ReasonScheduled}},
	}})
	assertClusterCAState(ctx, t, admin, first.ID, "retired")

	// A next CA may retire without ever signing.
	unused := fixture.newClusterCA(t, kubeca.StateNext, kubeca.ReasonScheduled)
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{{Create: unused}}})
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{
		{Move: &kubeca.Move{CA: unused.ID, Version: 1, To: kubeca.StateRetired, Reason: kubeca.ReasonAdmin}},
	}})
	assertClusterCAState(ctx, t, admin, unused.ID, "retired")
	assertClusterCAEvents(ctx, t, admin, unused.ID, "kubernetes_cluster.ca_created", "kubernetes_cluster.ca_retired")

	// A data key not the Network's active one seals nothing.
	stranger := fixture.newClusterCA(t, kubeca.StateNext, kubeca.ReasonScheduled)
	stranger.DataKeyID = mustPublicID(t)
	if _, err := store.Change(ctx, installation, scope, func(kubeca.Network) (kubeca.Changes, error) {
		return kubeca.Changes{Steps: []kubeca.Step{{Create: stranger}}}, nil
	}); err == nil {
		t.Fatal("a CA sealed under an unknown data key")
	}
	// Another installation writes nothing.
	if _, err := store.Change(ctx, other, scope, func(kubeca.Network) (kubeca.Changes, error) {
		return kubeca.Changes{}, nil
	}); err == nil {
		t.Fatal("another installation locked the Network")
	}
	if _, err := store.AddDataKey(ctx, other, scope, mustPublicID(t), wrapped); err == nil {
		t.Fatal("another installation stored a data key")
	}
	if _, err := store.Beat(ctx, other, mustPublicID(t), true, "v1", "file"); err == nil {
		t.Fatal("another installation beat")
	}

	assertClusterCARevisionBound(ctx, t, worker, fixture)
	assertClusterCAPostpone(ctx, t, admin, fixture)
	assertClusterCAHeartbeats(ctx, t, admin, store, installation)
}

// assertClusterCARevisionBound: evidence for a revision other than the
// Network's current one is refused with 40001, so the hash always covers
// the revision stored with the event.
func assertClusterCARevisionBound(ctx context.Context, t *testing.T, worker *pgx.Conn, fixture clusterCAFixture) {
	t.Helper()
	creation := fixture.newClusterCA(t, kubeca.StateNext, kubeca.ReasonScheduled)
	transaction, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var encoded string
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.create_kubernetes_cluster_ca_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::UUID,'next','scheduled',$7::UUID,$8::BYTEA,$9::TEXT,
    $10::TIMESTAMPTZ,$11::TIMESTAMPTZ,$12::BYTEA)::TEXT`, fixture.installation.String(),
		fixture.scope.WorkspaceID().String(), fixture.scope.NetworkID().String(), fixture.cluster.String(),
		creation.ID.String(), mustPublicID(t).String(), fixture.dataKeyID.String(), creation.Certificate,
		creation.ClusterDNSName, creation.NotBefore, creation.NotAfter, creation.SealedKey).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var proof struct {
		NetworkRevision int64  `json:"network_revision"`
		StreamID        int64  `json:"stream_id"`
		Sequence        int64  `json:"sequence"`
		PreviousHash    string `json:"previous_hash"`
		Payload         string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(encoded), &proof); err != nil || proof.NetworkRevision < 2 {
		t.Fatalf("proof %s: %v", encoded, err)
	}
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transaction.Exec(ctx, `SELECT mesh_ops.append_kubernetes_cluster_ca_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB,$9::BIGINT)`,
		creation.ID.String(), proof.StreamID, proof.Sequence, previous, make([]byte, 32), mustPublicID(t).String(),
		mustPublicID(t).String(), proof.Payload, proof.NetworkRevision-1)
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "40001" {
		t.Fatalf("evidence for an older revision: %v", err)
	}
}

// assertClusterCAPostpone: a Network the worker cannot plan is put off and
// its failure counted, without reading it; a later success clears it.
func assertClusterCAPostpone(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture) {
	t.Helper()
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_cluster_ca_schedule AS schedule
SET next_action_at = pg_catalog.clock_timestamp() - INTERVAL '1 minute'
FROM mesh.kubernetes_cluster AS cluster
WHERE cluster.id = schedule.kubernetes_cluster_id AND cluster.public_id = $1::UUID`,
		fixture.cluster.String()); err != nil {
		t.Fatal(err)
	}
	if busy, err := fixture.store.Postpone(ctx, fixture.installation, fixture.scope, time.Now()); err != nil || busy {
		t.Fatalf("Postpone() = %v, %v", busy, err)
	}
	read := fixture.change(ctx, t, kubeca.Changes{})
	cluster := findCluster(t, read, fixture.cluster)
	if cluster.Failures != 1 || time.Until(cluster.NextActionAt) < 30*time.Second {
		t.Fatalf("postponed cluster = %+v", cluster)
	}
	fixture.change(ctx, t, kubeca.Changes{
		Schedules: []kubeca.Schedule{{Cluster: fixture.cluster, At: time.Now().Add(time.Hour)}},
	})
	if cluster := findCluster(t, fixture.change(ctx, t, kubeca.Changes{}), fixture.cluster); cluster.Failures != 0 {
		t.Fatalf("a scheduled cluster keeps %d failures", cluster.Failures)
	}
}

func findCluster(t *testing.T, read kubeca.Network, id publicid.ID) kubeca.Cluster {
	t.Helper()
	for _, cluster := range read.Clusters {
		if cluster.ID == id {
			return cluster
		}
	}
	t.Fatalf("cluster %s is not scheduled: %+v", id, read.Clusters)
	return kubeca.Cluster{}
}

// assertClusterCAPrivileges: the worker runs the CA functions, the control
// plane none, and no role reads the tables.
func assertClusterCAPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var worker, runtime, table bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_worker', 'mesh_ops.lock_kubernetes_ca_network_v1(uuid,uuid,uuid)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_runtime', 'mesh_ops.lock_kubernetes_ca_network_v1(uuid,uuid,uuid)', 'EXECUTE')
      OR pg_catalog.has_function_privilege('mesh_runtime',
        'mesh_ops.beat_kubernetes_ca_worker_v1(uuid,uuid,boolean,text,text)', 'EXECUTE'),
    pg_catalog.has_table_privilege('mesh_worker', 'mesh.kubernetes_cluster_ca', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.kubernetes_cluster_ca', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.kubernetes_ca_data_key', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh_ops.kubernetes_ca_worker_heartbeat', 'SELECT')`).
		Scan(&worker, &runtime, &table); err != nil || !worker || runtime || table {
		t.Fatalf("CA privileges: worker %v, runtime %v, table %v, %v", worker, runtime, table, err)
	}
}

// assertClusterCAEvents checks a CA's sealed audit events, in order, carry
// no key material, and each has its outbox row.
func assertClusterCAEvents(ctx context.Context, t *testing.T, admin *pgx.Conn, ca publicid.ID, want ...string) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT event.action, event.payload::TEXT, event.permission
FROM mesh_audit.audit_event AS event
WHERE event.target_kind = 'kubernetes_cluster_ca' AND event.target_public_id = $1::UUID
ORDER BY event.event_identity_id`, ca.String())
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for rows.Next() {
		var action, payload, permission string
		if err := rows.Scan(&action, &payload, &permission); err != nil {
			t.Fatal(err)
		}
		if permission != "system.reconcile" || !strings.Contains(payload, `"fingerprint": "`) ||
			strings.Contains(payload, "sealed") || strings.Contains(payload, "ciphertext") ||
			strings.Contains(payload, "certificate\"") {
			t.Fatalf("CA event %s: %s (%s)", action, payload, permission)
		}
		actions = append(actions, action)
	}
	rows.Close()
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("CA %s events = %v, want %v", ca, actions, want)
	}
	var outbox int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
WHERE aggregate_kind = 'kubernetes_cluster_ca' AND aggregate_public_id = $1::UUID`, ca.String()).Scan(&outbox); err != nil ||
		outbox != len(want) {
		t.Fatalf("CA %s outbox rows %d, %v", ca, outbox, err)
	}
}

// assertClusterCAState checks a CA's state; "" means no such CA.
func assertClusterCAState(ctx context.Context, t *testing.T, admin *pgx.Conn, ca publicid.ID, want string) {
	t.Helper()
	var state string
	err := admin.QueryRow(ctx, `SELECT state FROM mesh.kubernetes_cluster_ca WHERE public_id = $1::UUID`,
		ca.String()).Scan(&state)
	if want == "" && !errors.Is(err, pgx.ErrNoRows) || want != "" && (err != nil || state != want) {
		t.Fatalf("CA %s state = %q, %v; want %q", ca, state, err, want)
	}
}

// assertClusterCAGuards: even the owner of the tables cannot move a CA
// back, change what it signs for, or delete it, nor change a data key.
func assertClusterCAGuards(ctx context.Context, t *testing.T, admin *pgx.Conn, retiring publicid.ID) {
	t.Helper()
	for _, statement := range []string{
		`UPDATE mesh.kubernetes_cluster_ca SET state = 'active', version = version + 1, retiring_at = NULL
WHERE public_id = $1::UUID`,
		`UPDATE mesh.kubernetes_cluster_ca SET cluster_dns_name = 'other.example', version = version + 1
WHERE public_id = $1::UUID`,
		`DELETE FROM mesh.kubernetes_cluster_ca WHERE public_id = $1::UUID`,
		`UPDATE mesh.kubernetes_ca_data_key SET key_id = 'other' WHERE id = (
    SELECT data_key_id FROM mesh.kubernetes_cluster_ca WHERE public_id = $1::UUID)`,
	} {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`,
			mustPublicID(t).String()); err != nil {
			t.Fatal(err)
		}
		_, err = transaction.Exec(ctx, statement, retiring.String())
		if rollbackErr := transaction.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err == nil || !strings.Contains(err.Error(), "invalid Kubernetes") &&
			!strings.Contains(err.Error(), "never deleted") {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// assertClusterCAHeartbeats: a ready worker is ready for 90 s, one without
// custody not at all.
func assertClusterCAHeartbeats(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.KubernetesClusterCAStore, installation deployment.ID,
) {
	t.Helper()
	instance := mustPublicID(t)
	readyUntil, err := store.Beat(ctx, installation, instance, true, "v1.2.3", "file")
	if err != nil || time.Until(readyUntil) < 80*time.Second || time.Until(readyUntil) > 100*time.Second {
		t.Fatalf("Beat(ready) = %v, %v", readyUntil, err)
	}
	if _, err := store.Beat(ctx, installation, mustPublicID(t), true, "v1.2.3", "none"); err == nil {
		t.Fatal("a worker without custody beat ready")
	}
	readyUntil, err = store.Beat(ctx, installation, instance, false, "v1.2.3", "none")
	if err != nil || time.Until(readyUntil) > time.Second {
		t.Fatalf("Beat(not ready) = %v, %v", readyUntil, err)
	}
	var beats int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_ca_worker_heartbeat
WHERE instance_public_id = $1::UUID AND custody = 'none' AND ready_until = updated_at`, instance.String()).
		Scan(&beats); err != nil || beats != 1 {
		t.Fatalf("heartbeats %d, %v", beats, err)
	}
}
