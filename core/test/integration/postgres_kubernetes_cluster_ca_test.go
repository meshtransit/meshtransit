//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/adapter/kubecustody"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// clusterCAFixture is what the CA assertions share: the worker's store, its
// installation, and the Network's active data key in the clear.
type clusterCAFixture struct {
	store        *postgresadapter.KubernetesClusterCAStore
	installation deployment.ID
	scope        network.Scope
	cluster      publicid.ID
	dataKeyID    publicid.ID
	dataKey      kubeca.DataKey
	dnsName      string
}

// creation seals ca for the fixture's cluster under its data key.
func (fixture clusterCAFixture) creation(t *testing.T, ca kubeca.CA, issuer publicid.ID, state kubeca.State,
	reason kubeca.Reason,
) *kubeca.Creation {
	t.Helper()
	id := mustPublicID(t)
	sealed, err := kubeca.SealCA(fixture.dataKey, ca, fixture.installation.String(), fixture.cluster.String(),
		id.String())
	if err != nil {
		t.Fatal(err)
	}
	certificate := ca.Certificate()
	return &kubeca.Creation{
		Cluster: fixture.cluster, ID: id, Kind: ca.Kind(), IssuerID: issuer, State: state, Reason: reason,
		DataKeyID: fixture.dataKeyID, Certificate: certificate.Raw, ClusterDNSName: ca.ClusterDNSName(),
		NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter, SealedKey: sealed,
	}
}

func (fixture clusterCAFixture) newRoot(t *testing.T, name string) kubeca.CA {
	t.Helper()
	root, err := kubeca.NewRoot(kubeca.RootParams{
		ClusterDNSName: name, Subject: "prod root",
		NotBefore: time.Now(), Lifetime: kubeca.DefaultRootLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func newIntermediate(t *testing.T, root kubeca.CA) kubeca.CA {
	t.Helper()
	ca, err := root.NewIntermediate(kubeca.IntermediateParams{
		Subject: "prod", NotBefore: time.Now(),
		Lifetime: kubeca.DefaultIntermediateLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ca
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

// refused applies changes that must fail and leave nothing behind.
func (fixture clusterCAFixture) refused(ctx context.Context, t *testing.T, what string, changes kubeca.Changes) error {
	t.Helper()
	busy, err := fixture.store.Change(ctx, fixture.installation, fixture.scope,
		func(kubeca.Network) (kubeca.Changes, error) { return changes, nil })
	if err == nil || busy {
		t.Fatalf("%s: Change() = %v, %v", what, busy, err)
	}
	return err
}

func (fixture clusterCAFixture) read(ctx context.Context, t *testing.T) kubeca.Network {
	t.Helper()
	read, err := fixture.store.Read(ctx, fixture.installation, fixture.scope)
	if err != nil {
		t.Fatal(err)
	}
	return read
}

func move(ca publicid.ID, version int64, to kubeca.State, reason kubeca.Reason) kubeca.Step {
	return kubeca.Step{Move: &kubeca.Move{CA: ca, Version: version, To: to, Reason: reason}}
}

// assertKubernetesClusterCAs qualifies schemas 238 and 239 on an active
// cluster: only the worker reads and writes CAs and data keys, under the
// Network's lock; a cluster has a root and an intermediate signed by it;
// every change is a sealed audit event without key material, naming the
// operator when one made it; CAs only move forward and drop their sealed
// key when they stop signing; data keys are wrapped again and replaced
// without touching CAs; the suffix is recorded once.
func assertKubernetesClusterCAs(ctx context.Context, t *testing.T, admin, worker *pgx.Conn,
	workerPool *postgresadapter.Pool, service *kubecluster.Service, owner accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID,
) clusterCAFixture {
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
	other, err := deployment.ParseID(mustPublicID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	fixture := clusterCAFixture{store: store, installation: installation, scope: scope, cluster: publicid.ID(clusterID)}

	// The suffix is recorded once; a worker with another one is told.
	for _, claim := range []struct {
		suffix  string
		matched bool
	}{{"mesh.internal", true}, {"mesh.internal", true}, {"other.test", false}} {
		recorded, matched, err := store.ClaimDNSSuffix(ctx, installation, claim.suffix)
		if err != nil || recorded != "mesh.internal" || matched != claim.matched {
			t.Fatalf("ClaimDNSSuffix(%s) = %q, %v, %v", claim.suffix, recorded, matched, err)
		}
	}

	// The new cluster is due at once; another installation lists nothing.
	due, err := store.ListDue(ctx, installation, 256)
	if err != nil || !containsScope(due, scope) {
		t.Fatalf("ListDue() = %v, %v", due, err)
	}
	if _, err := store.ListDue(ctx, other, 10); err == nil {
		t.Fatal("another installation listed CA work")
	}

	// The Network's data key: the first stored wins, sealed in the audit
	// trail without its ciphertext.
	custody, err := kubecustody.NewFile(kubeca.DataKey(filledIntegrationKey(0x38)), nil)
	if err != nil {
		t.Fatal(err)
	}
	dataKey, wrapped, err := custody.NewDataKey(ctx, scope.NetworkID().String())
	if err != nil {
		t.Fatal(err)
	}
	dataKeyID := mustPublicID(t)
	if added, err := store.AddDataKey(ctx, installation, scope, dataKeyID, wrapped, kubeca.Operator{}); err != nil ||
		!added {
		t.Fatalf("AddDataKey() = %v, %v", added, err)
	}
	if added, err := store.AddDataKey(ctx, installation, scope, mustPublicID(t), wrapped, kubeca.Operator{}); err != nil ||
		added {
		t.Fatalf("a second data key = %v, %v", added, err)
	}
	if _, err := store.AddDataKey(ctx, other, scope, mustPublicID(t), wrapped, kubeca.Operator{}); err == nil {
		t.Fatal("another installation stored a data key")
	}
	assertCAEvents(ctx, t, admin, "kubernetes_ca_data_key", dataKeyID, "system.reconcile",
		"kubernetes_ca_data_key.created")
	fixture.dataKeyID, fixture.dataKey = dataKeyID, dataKey

	// The worker reads the codes that name the cluster, and no CA yet.
	read := fixture.read(ctx, t)
	cluster := findCluster(t, read, fixture.cluster)
	if len(read.WorkspaceCode) != 12 || len(read.NetworkCode) != 12 || !cluster.Active || cluster.Name != "prod" ||
		len(cluster.CAs) != 0 || len(read.DataKeys) != 1 || read.DataKeys[0].Version != 1 || read.Now.IsZero() {
		t.Fatalf("read = %+v", read)
	}
	fixture.dnsName = "prod.kube." + read.WorkspaceCode + "." + read.NetworkCode + ".mesh.internal"

	// The first root and intermediate; the schedule is bounded to a day.
	// Other clusters of the Network are scheduled with it, as the worker
	// batches a Network.
	root := fixture.newRoot(t, fixture.dnsName)
	rootCreation := fixture.creation(t, root, publicid.ID{}, kubeca.StateActive, kubeca.ReasonInitial)
	intermediate := newIntermediate(t, root)
	first := fixture.creation(t, intermediate, rootCreation.ID, kubeca.StateActive, kubeca.ReasonInitial)
	schedules := []kubeca.Schedule{{Cluster: fixture.cluster, At: time.Now().Add(10 * 24 * time.Hour)}}
	for _, scheduled := range read.Clusters {
		if scheduled.ID != fixture.cluster {
			schedules = append(schedules, kubeca.Schedule{Cluster: scheduled.ID, At: time.Now().Add(time.Hour)})
		}
	}
	fixture.change(ctx, t, kubeca.Changes{
		Steps: []kubeca.Step{{Create: rootCreation}, {Create: first}}, Schedules: schedules,
	})
	if due, err := store.ListDue(ctx, installation, 256); err != nil || containsScope(due, scope) {
		t.Fatalf("a scheduled Network is still due: %v, %v", due, err)
	}
	assertCAEvents(ctx, t, admin, "kubernetes_cluster_ca", rootCreation.ID, "system.reconcile",
		"kubernetes_cluster.ca_created")
	cas := findCluster(t, fixture.read(ctx, t), fixture.cluster).CAs
	if len(cas) != 2 || cas[0].Kind != kubeca.KindRoot || cas[1].Kind != kubeca.KindIntermediate ||
		cas[1].IssuerID != rootCreation.ID || cas[0].IssuerID.IsValid() {
		t.Fatalf("CAs = %+v", cas)
	}
	assertStoredChainSigns(t, fixture, cas[0], cas[1])

	// A second active intermediate is refused, and the whole change with it;
	// so is an intermediate of no active root, and a root that steps down
	// while its intermediate is active.
	second := fixture.creation(t, newIntermediate(t, root), rootCreation.ID, kubeca.StateActive, kubeca.ReasonAdmin)
	fixture.refused(ctx, t, "a second active intermediate", kubeca.Changes{Steps: []kubeca.Step{{Create: second}}})
	assertClusterCAState(ctx, t, admin, second.ID, "")
	// A CA outside the recorded suffix is refused, whatever the worker says.
	elsewhere := fixture.creation(t, fixture.newRoot(t, "prod.kube."+read.WorkspaceCode+"."+read.NetworkCode+
		".other.example.net"), publicid.ID{}, kubeca.StateNext, kubeca.ReasonAdmin)
	fixture.refused(ctx, t, "a CA outside the recorded suffix", kubeca.Changes{Steps: []kubeca.Step{{Create: elsewhere}}})
	orphan := fixture.creation(t, newIntermediate(t, root), mustPublicID(t), kubeca.StateActive, kubeca.ReasonAdmin)
	fixture.refused(ctx, t, "an intermediate of no root", kubeca.Changes{Steps: []kubeca.Step{{Create: orphan}}})
	fixture.refused(ctx, t, "a root over an active intermediate", kubeca.Changes{Steps: []kubeca.Step{
		move(rootCreation.ID, 1, kubeca.StateRetiring, kubeca.ReasonAdmin),
	}})

	// The intermediate hands over; the old one drops its sealed key.
	fixture.change(ctx, t, kubeca.Changes{Steps: []kubeca.Step{
		move(first.ID, 1, kubeca.StateRetiring, kubeca.ReasonScheduled), {Create: second},
	}})
	cas = findCluster(t, fixture.read(ctx, t), fixture.cluster).CAs
	if len(cas) != 3 || cas[1].ID != first.ID || cas[1].State != kubeca.StateRetiring || cas[1].SealedKey != nil ||
		cas[2].ID != second.ID || cas[2].State != kubeca.StateActive || len(cas[2].SealedKey) == 0 {
		t.Fatalf("CAs after the hand-over = %+v", cas)
	}
	assertCAEvents(ctx, t, admin, "kubernetes_cluster_ca", first.ID, "system.reconcile",
		"kubernetes_cluster.ca_created", "kubernetes_cluster.ca_retiring")

	// A move from a version since changed is stale, and undoes the change.
	if err := fixture.refused(ctx, t, "a stale move", kubeca.Changes{Steps: []kubeca.Step{
		move(first.ID, 2, kubeca.StateRetired, kubeca.ReasonScheduled),
		move(second.ID, 2, kubeca.StateRetiring, kubeca.ReasonAdmin),
	}}); !errors.Is(err, postgresadapter.ErrKubernetesClusterCAStale) {
		t.Fatalf("a stale move: %v", err)
	}
	assertClusterCAState(ctx, t, admin, first.ID, "retiring")

	assertClusterCABusy(ctx, t, admin, fixture)
	assertClusterCAGuards(ctx, t, admin, first.ID)

	// An operator retires the retiring intermediate: the event names them.
	operator := kubeca.Operator{Name: "alice@example.test", ChangeRef: "CHG-7"}
	fixture.change(ctx, t, kubeca.Changes{Operator: operator, Steps: []kubeca.Step{
		move(first.ID, 2, kubeca.StateRetired, kubeca.ReasonAdmin),
	}})
	assertCAEvents(ctx, t, admin, "kubernetes_cluster_ca", first.ID, "system.operator",
		"kubernetes_cluster.ca_created", "kubernetes_cluster.ca_retiring", "kubernetes_cluster.ca_retired")

	fixture = assertDataKeyRewrapAndRetire(ctx, t, admin, fixture, operator)
	assertClusterCARevisionBound(ctx, t, worker, fixture)
	assertKubernetesCAReads(ctx, t, service, owner, scope, clusterID, first.ID, operator)
	assertDeletedClusterCAs(ctx, t, admin, fixture, service, owner)
	assertClusterCAPostpone(ctx, t, admin, fixture)
	assertCAWorkerPass(ctx, t, admin, fixture, service, owner)
	assertClusterCAHeartbeats(ctx, t, admin, store, installation, other)
	return fixture
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

// assertStoredChainSigns opens the stored root and intermediate and signs a
// replica that verifies under the root alone.
func assertStoredChainSigns(t *testing.T, fixture clusterCAFixture, root, intermediate kubeca.StoredCA) {
	t.Helper()
	openedRoot, err := kubeca.OpenRoot(fixture.dataKey, root.Certificate, root.SealedKey,
		fixture.installation.String(), fixture.cluster.String(), root.ID.String())
	if err != nil {
		t.Fatalf("OpenRoot() = %v", err)
	}
	opened, err := kubeca.OpenIntermediate(fixture.dataKey, intermediate.Certificate, intermediate.SealedKey,
		fixture.installation.String(), fixture.cluster.String(), intermediate.ID.String(), openedRoot.Certificate())
	if err != nil {
		t.Fatalf("OpenIntermediate() = %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := opened.SignReplica(kubeca.ReplicaRequest{CSR: csr, ClusterDNSName: fixture.dnsName, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(issued.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(openedRoot.Certificate())
	intermediates.AddCert(opened.Certificate())
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		DNSName: fixture.dnsName,
	}); err != nil {
		t.Fatalf("the stored chain does not verify: %v", err)
	}
}

// assertClusterCAPrivileges: the worker runs the CA functions, the control
// plane none, and no role reads the tables.
func assertClusterCAPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var worker, runtime, table bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_worker', 'mesh_ops.lock_kubernetes_ca_network_v2(uuid,uuid,uuid)', 'EXECUTE')
      AND NOT pg_catalog.has_function_privilege('mesh_worker',
        'mesh_ops.kubernetes_ca_payload_internal_v1(text,bigint)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_runtime', 'mesh_ops.lock_kubernetes_ca_network_v2(uuid,uuid,uuid)', 'EXECUTE')
      OR pg_catalog.has_function_privilege('mesh_runtime',
        'mesh_ops.beat_kubernetes_ca_worker_v2(uuid,uuid,boolean,text,text,text[])', 'EXECUTE')
      OR pg_catalog.has_function_privilege('mesh_runtime',
        'mesh_ops.rewrap_kubernetes_ca_data_key_v1(uuid,uuid,uuid,uuid,bigint,uuid,text,text,bytea,text,text)', 'EXECUTE'),
    pg_catalog.has_table_privilege('mesh_worker', 'mesh.kubernetes_cluster_ca', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.kubernetes_cluster_ca', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_worker', 'mesh.kubernetes_ca_data_key_wrapping', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_worker', 'mesh_ops.kubernetes_ca_dns_suffix', 'SELECT')`).
		Scan(&worker, &runtime, &table); err != nil || !worker || runtime || table {
		t.Fatalf("CA privileges: worker %v, runtime %v, table %v, %v", worker, runtime, table, err)
	}
}

// assertCAEvents checks a row's sealed audit events, in order, carry no key
// material and each has its outbox row; the last has the given permission.
func assertCAEvents(ctx context.Context, t *testing.T, admin *pgx.Conn, kind string, row publicid.ID,
	lastPermission string, want ...string,
) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT event.action, event.payload::TEXT, event.permission
FROM mesh_audit.audit_event AS event
WHERE event.target_kind = $1 AND event.target_public_id = $2::UUID
ORDER BY event.event_identity_id`, kind, row.String())
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	var permission string
	for rows.Next() {
		var action, payload string
		if err := rows.Scan(&action, &payload, &permission); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, "sealed") || strings.Contains(payload, "ciphertext") ||
			strings.Contains(payload, `"certificate"`) {
			t.Fatalf("event %s: %s", action, payload)
		}
		if permission == "system.operator" && !strings.Contains(payload, `"changed_by": "`) {
			t.Fatalf("an operator's event %s does not name them: %s", action, payload)
		}
		actions = append(actions, action)
	}
	rows.Close()
	if strings.Join(actions, ",") != strings.Join(want, ",") || permission != lastPermission {
		t.Fatalf("%s %s events = %v (last %s), want %v (last %s)", kind, row, actions, permission, want,
			lastPermission)
	}
	var outbox int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
WHERE aggregate_kind = $1 AND aggregate_public_id = $2::UUID`, kind, row.String()).Scan(&outbox); err != nil ||
		outbox != len(want) {
		t.Fatalf("%s %s outbox rows %d, %v", kind, row, outbox, err)
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

// assertClusterCABusy: a Network another worker holds is busy, and nothing
// is planned.
func assertClusterCABusy(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture) {
	t.Helper()
	held, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Rollback(ctx) }()
	if _, err := held.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('meshtransit/kubernetes-ca/' || $1, 0))`, fixture.scope.NetworkID().String()); err != nil {
		t.Fatal(err)
	}
	planned := false
	busy, err := fixture.store.Change(ctx, fixture.installation, fixture.scope,
		func(kubeca.Network) (kubeca.Changes, error) {
			planned = true
			return kubeca.Changes{}, nil
		})
	if err != nil || !busy || planned {
		t.Fatalf("Change() on a held Network = %v, %v, planned %v", busy, err, planned)
	}
}

// assertClusterCAGuards: even the owner of the tables cannot move a CA
// back, change what it signs for, or delete it, nor change a wrapping.
func assertClusterCAGuards(ctx context.Context, t *testing.T, admin *pgx.Conn, retiring publicid.ID) {
	t.Helper()
	for _, statement := range []string{
		`UPDATE mesh.kubernetes_cluster_ca SET state = 'active', version = version + 1, retiring_at = NULL
WHERE public_id = $1::UUID`,
		`UPDATE mesh.kubernetes_cluster_ca SET cluster_dns_name = 'other.example', version = version + 1
WHERE public_id = $1::UUID`,
		`UPDATE mesh.kubernetes_cluster_ca SET issuer_ca_id = NULL, kind = 'root', version = version + 1
WHERE public_id = $1::UUID`,
		`DELETE FROM mesh.kubernetes_cluster_ca WHERE public_id = $1::UUID`,
		`UPDATE mesh.kubernetes_ca_data_key_wrapping SET key_id = 'other' WHERE data_key_id = (
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
