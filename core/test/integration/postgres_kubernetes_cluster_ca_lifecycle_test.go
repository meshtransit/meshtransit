//go:build integration

package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/adapter/kubecustody"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// assertDataKeyRewrapAndRetire: an operator wraps the Network's data key
// under a new custody key without touching a CA, then retires it; the CAs
// it sealed still open under it, and a new data key takes over new CAs
// (§17.1 C1). Returns the fixture with the new data key.
func assertDataKeyRewrapAndRetire(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture,
	operator kubeca.Operator,
) clusterCAFixture {
	t.Helper()
	network := fixture.scope.NetworkID().String()
	oldWrap := kubeca.DataKey(filledIntegrationKey(0x38))
	rotated, err := kubecustody.NewFile(kubeca.DataKey(filledIntegrationKey(0x39)), []kubeca.DataKey{oldWrap})
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := rotated.WrapDataKey(ctx, network, fixture.dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.RewrapDataKey(ctx, fixture.installation, fixture.scope, fixture.dataKeyID, 1, rewrapped,
		operator); err != nil {
		t.Fatalf("RewrapDataKey() = %v", err)
	}
	if err := fixture.store.RewrapDataKey(ctx, fixture.installation, fixture.scope, fixture.dataKeyID, 1, rewrapped,
		operator); !errors.Is(err, postgresadapter.ErrKubernetesClusterCAStale) {
		t.Fatalf("a stale rewrap: %v", err)
	}
	read := fixture.read(ctx, t)
	if len(read.DataKeys) != 1 || read.DataKeys[0].Version != 2 || read.DataKeys[0].Wrapped.KeyID != rewrapped.KeyID {
		t.Fatalf("data keys after the rewrap = %+v", read.DataKeys)
	}
	// Only the new wrap key is needed from now on.
	current, err := kubecustody.NewFile(kubeca.DataKey(filledIntegrationKey(0x39)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := current.OpenDataKey(ctx, network, read.DataKeys[0].Wrapped); err != nil ||
		opened != fixture.dataKey {
		t.Fatalf("the rewrapped data key does not open: %v", err)
	}
	// The data key is replaced in one change pair: retired and a new one
	// added, by the operator.
	dataKey, wrapped, err := current.NewDataKey(ctx, network)
	if err != nil {
		t.Fatal(err)
	}
	dataKeyID := mustPublicID(t)
	if err := fixture.store.RotateDataKey(ctx, fixture.installation, fixture.scope, fixture.dataKeyID, 2, dataKeyID,
		wrapped, operator); err != nil {
		t.Fatalf("RotateDataKey() = %v", err)
	}
	assertCAEvents(ctx, t, admin, "kubernetes_ca_data_key", fixture.dataKeyID, "system.operator",
		"kubernetes_ca_data_key.created", "kubernetes_ca_data_key.rewrapped", "kubernetes_ca_data_key.retired")
	assertCAEvents(ctx, t, admin, "kubernetes_ca_data_key", dataKeyID, "system.operator",
		"kubernetes_ca_data_key.created")

	// A retired data key is wrapped again too: its CAs still open.
	again, err := current.WrapDataKey(ctx, network, fixture.dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.RewrapDataKey(ctx, fixture.installation, fixture.scope, fixture.dataKeyID, 3, again,
		operator); err != nil {
		t.Fatalf("rewrapping a retired key: %v", err)
	}
	assertCAEvents(ctx, t, admin, "kubernetes_ca_data_key", fixture.dataKeyID, "system.operator",
		"kubernetes_ca_data_key.created", "kubernetes_ca_data_key.rewrapped", "kubernetes_ca_data_key.retired",
		"kubernetes_ca_data_key.rewrapped")

	// No CA is sealed under a retired data key.
	next := fixture.creation(t, fixture.newRoot(t, fixture.dnsName), publicid.ID{}, kubeca.StateNext,
		kubeca.ReasonAdmin)
	fixture.refused(ctx, t, "a CA under a retired data key", kubeca.Changes{Steps: []kubeca.Step{{Create: next}}})
	read = fixture.read(ctx, t)
	if len(read.DataKeys) != 2 || read.DataKeys[0].Active || !read.DataKeys[1].Active ||
		read.DataKeys[1].ID != dataKeyID {
		t.Fatalf("data keys after the retirement = %+v", read.DataKeys)
	}
	fixture.dataKeyID, fixture.dataKey = dataKeyID, dataKey
	return fixture
}

// assertClusterCARevisionBound: evidence for a revision other than the
// Network's current one is refused with 40001, so the hash always covers
// the revision stored with the event.
func assertClusterCARevisionBound(ctx context.Context, t *testing.T, worker *pgx.Conn, fixture clusterCAFixture) {
	t.Helper()
	creation := fixture.creation(t, fixture.newRoot(t, fixture.dnsName), publicid.ID{}, kubeca.StateNext,
		kubeca.ReasonScheduled)
	transaction, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var encoded string
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.create_kubernetes_cluster_ca_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::UUID,'root',NULL,'next','scheduled',$7::UUID,$8::BYTEA,$9::TEXT,
    $10::TIMESTAMPTZ,$11::TIMESTAMPTZ,$12::BYTEA,NULL,NULL)::TEXT`, fixture.installation.String(),
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
	_, err = transaction.Exec(ctx, `SELECT mesh_ops.append_kubernetes_ca_evidence_v1(
    'kubernetes_cluster_ca',$1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB,$9::BIGINT)`,
		creation.ID.String(), proof.StreamID, proof.Sequence, previous, make([]byte, 32), mustPublicID(t).String(),
		mustPublicID(t).String(), proof.Payload, proof.NetworkRevision-1)
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "40001" {
		t.Fatalf("evidence for an older revision: %v", err)
	}
}

// assertDeletedClusterCAs: a deleted cluster is due at once and gets no new
// CA; its CAs retire, intermediates first, and then its schedule ends, not
// before (TD-CORE-102).
func assertDeletedClusterCAs(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture,
	service *kubecluster.Service, owner accountsession.Session,
) {
	t.Helper()
	goneID := kubecluster.ID(mustPublicID(t))
	gone, err := service.Create(ctx, kubecluster.Creation{
		Session: owner, Scope: fixture.scope, ID: goneID,
		Name: "ca-gone", CorrelationID: newCorrelationID(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	read := fixture.read(ctx, t)
	fixture.cluster = publicid.ID(goneID)
	fixture.dnsName = "ca-gone.kube." + read.WorkspaceCode + "." + read.NetworkCode + ".mesh.internal"
	root := fixture.newRoot(t, fixture.dnsName)
	rootCreation := fixture.creation(t, root, publicid.ID{}, kubeca.StateActive, kubeca.ReasonInitial)
	intermediate := fixture.creation(t, newIntermediate(t, root), rootCreation.ID, kubeca.StateActive,
		kubeca.ReasonInitial)
	fixture.change(ctx, t, kubeca.Changes{
		Steps:     []kubeca.Step{{Create: rootCreation}, {Create: intermediate}},
		Schedules: []kubeca.Schedule{{Cluster: fixture.cluster, At: time.Now().Add(time.Hour)}},
	})
	fixture.refused(ctx, t, "ending an active cluster's schedule", kubeca.Changes{
		Schedules: []kubeca.Schedule{{Cluster: fixture.cluster, Done: true}},
	})
	if _, err := service.Delete(ctx, kubecluster.Deletion{
		Session: owner, Scope: fixture.scope, ClusterID: goneID,
		ExpectedVersion: gone.Version(), CorrelationID: newCorrelationID(t),
	}); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	cluster := findCluster(t, fixture.read(ctx, t), fixture.cluster)
	if cluster.Active || time.Until(cluster.NextActionAt) > time.Minute || len(cluster.CAs) != 2 {
		t.Fatalf("the deleted cluster = %+v", cluster)
	}
	late := fixture.creation(t, newIntermediate(t, root), rootCreation.ID, kubeca.StateActive, kubeca.ReasonAdmin)
	fixture.refused(ctx, t, "a CA for a deleted cluster", kubeca.Changes{Steps: []kubeca.Step{{Create: late}}})
	fixture.refused(ctx, t, "a root retired before its intermediate", kubeca.Changes{Steps: []kubeca.Step{
		move(rootCreation.ID, 1, kubeca.StateRetired, kubeca.ReasonClusterDeleted),
	}})
	fixture.change(ctx, t, kubeca.Changes{
		Steps: []kubeca.Step{
			move(intermediate.ID, 1, kubeca.StateRetired, kubeca.ReasonClusterDeleted),
			move(rootCreation.ID, 1, kubeca.StateRetired, kubeca.ReasonClusterDeleted),
		},
		Schedules: []kubeca.Schedule{{Cluster: fixture.cluster, Done: true}},
	})
	var scheduled int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_cluster_ca_schedule AS schedule
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = schedule.kubernetes_cluster_id
WHERE cluster.public_id = $1::UUID`, goneID.String()).Scan(&scheduled); err != nil || scheduled != 0 {
		t.Fatalf("the deleted cluster is still scheduled: %d, %v", scheduled, err)
	}
	assertCAEvents(ctx, t, admin, "kubernetes_cluster_ca", rootCreation.ID, "system.reconcile",
		"kubernetes_cluster.ca_created", "kubernetes_cluster.ca_retired")
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
	cluster := findCluster(t, fixture.read(ctx, t), fixture.cluster)
	if cluster.Failures != 1 || time.Until(cluster.NextActionAt) < 30*time.Second {
		t.Fatalf("postponed cluster = %+v", cluster)
	}
	fixture.change(ctx, t, kubeca.Changes{
		Schedules: []kubeca.Schedule{{Cluster: fixture.cluster, At: time.Now().Add(time.Hour)}},
	})
	if cluster := findCluster(t, fixture.read(ctx, t), fixture.cluster); cluster.Failures != 0 {
		t.Fatalf("a scheduled cluster keeps %d failures", cluster.Failures)
	}
}

// assertClusterCAHeartbeats: a worker says what it can do; a ready one is
// ready for 90 s, one without custody not at all; another installation's
// beat is refused.
func assertClusterCAHeartbeats(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.KubernetesClusterCAStore, installation, other deployment.ID,
) {
	t.Helper()
	instance := mustPublicID(t)
	capabilities := []string{"ca.lifecycle1"}
	readyUntil, err := store.Beat(ctx, installation, instance, true, "v1.2.3", "file", capabilities)
	if err != nil || time.Until(readyUntil) < 80*time.Second || time.Until(readyUntil) > 100*time.Second {
		t.Fatalf("Beat(ready) = %v, %v", readyUntil, err)
	}
	for name, beat := range map[string]func() error{
		"ready without custody": func() error {
			_, err := store.Beat(ctx, installation, mustPublicID(t), true, "v1.2.3", "none", capabilities)
			return err
		},
		"a bad capability": func() error {
			_, err := store.Beat(ctx, installation, mustPublicID(t), false, "v1.2.3", "none", []string{"Bad Cap"})
			return err
		},
		"another installation": func() error {
			_, err := store.Beat(ctx, other, mustPublicID(t), false, "v1.2.3", "none", capabilities)
			return err
		},
	} {
		if err := beat(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	readyUntil, err = store.Beat(ctx, installation, instance, false, "v1.2.3", "none", capabilities)
	if err != nil || time.Until(readyUntil) > time.Second {
		t.Fatalf("Beat(not ready) = %v, %v", readyUntil, err)
	}
	var beats int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_ca_worker_heartbeat
WHERE instance_public_id = $1::UUID AND custody = 'none' AND ready_until = updated_at
  AND capabilities = ARRAY['ca.lifecycle1']`, instance.String()).Scan(&beats); err != nil || beats != 1 {
		t.Fatalf("heartbeats %d, %v", beats, err)
	}
}

// assertCAWorkerPass runs the worker itself on the database: it gives a new
// cluster its root and intermediate; after an operator retires the root
// for a compromise, the next pass gives the cluster new ones.
func assertCAWorkerPass(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture,
	service *kubecluster.Service, owner accountsession.Session,
) {
	t.Helper()
	clusterID := kubecluster.ID(mustPublicID(t))
	if _, err := service.Create(ctx, kubecluster.Creation{
		Session: owner, Scope: fixture.scope, ID: clusterID,
		Name: "ca-worker", CorrelationID: newCorrelationID(t),
	}); err != nil {
		t.Fatal(err)
	}
	suffix, err := dnsname.ParseSuffix("mesh.internal")
	if err != nil {
		t.Fatal(err)
	}
	custody, err := kubecustody.NewFile(kubeca.DataKey(filledIntegrationKey(0x39)), nil)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := lifecycle.New(lifecycle.Options{
		DeploymentID: fixture.installation, Suffix: suffix, BatchSize: 16,
		PollInterval: time.Second, OperationTimeout: 20 * time.Second, Version: "integration",
		Policy: lifecycle.DefaultPolicy(),
	}, fixture.store,
		func(context.Context) (kubeca.Custody, string, error) { return custody, "file", nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	liveRoot := func() (kubeca.StoredCA, kubeca.StoredCA) {
		t.Helper()
		cluster := findCluster(t, fixture.read(ctx, t), publicid.ID(clusterID))
		var root, intermediate kubeca.StoredCA
		for _, ca := range cluster.CAs {
			switch {
			case ca.Kind == kubeca.KindRoot && ca.State == kubeca.StateActive:
				root = ca
			case ca.Kind == kubeca.KindIntermediate && ca.State == kubeca.StateActive:
				intermediate = ca
			}
		}
		if !root.ID.IsValid() || intermediate.IssuerID != root.ID {
			t.Fatalf("the worker left cluster CAs %+v (snapshot %+v)", cluster.CAs, worker.Snapshot())
		}
		return root, intermediate
	}
	worker.Pass(ctx)
	first, _ := liveRoot()
	if snapshot := worker.Snapshot(); snapshot.Created < 2 || snapshot.Misnamed != 0 || snapshot.SuffixMismatch {
		t.Fatalf("snapshot %+v", snapshot)
	}
	if err := lifecycle.RetireCA(ctx, fixture.store, fixture.installation, fixture.scope, first.ID,
		kubeca.ReasonCompromise, kubeca.Operator{Name: "soc@example.com", ChangeRef: "INC-9"}); err != nil {
		t.Fatalf("RetireCA() = %v", err)
	}
	assertClusterCAState(ctx, t, admin, first.ID, "retired")
	worker.Pass(ctx)
	second, _ := liveRoot()
	if second.ID == first.ID {
		t.Fatal("the worker did not replace the retired root")
	}
}
