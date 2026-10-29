//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// assertKubernetesClusterPages pages a cluster's keys and requests one row
// at a time (schema 247): every row of the cluster's detail comes once,
// newest first; one row reads by ID; a session without the cluster
// permissions is forbidden and an unknown ID is not found (K1d d1a).
func assertKubernetesClusterPages(ctx context.Context, t *testing.T, admin *pgx.Conn, service *kubecluster.Service,
	store *postgresadapter.KubernetesClusterStore,
	owner, custom accountsession.Session, scope network.Scope, clusterID kubecluster.ID, detail kubecluster.Detail,
	recordOperations func()) {
	t.Helper()
	query := kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: clusterID, Limit: 1}
	keys := map[enrollment.CredentialID]bool{}
	var previous kubecluster.PageCursor
	for range len(detail.Keys) + 1 {
		page, err := service.ListJoinKeys(ctx, query)
		if err != nil || len(page.Keys) > 1 {
			t.Fatalf("ListJoinKeys(%+v) = %+v, %v", query.After, page, err)
		}
		for _, key := range page.Keys {
			if keys[key.ID()] || !previous.IsZero() && key.CreatedAt().After(previous.At) {
				t.Fatalf("key %s twice or out of order", key.ID())
			}
			keys[key.ID()] = true
			previous = kubecluster.PageCursor{At: key.CreatedAt(), ID: publicid.ID(key.ID())}
		}
		if page.Next.IsZero() {
			break
		}
		query.After = page.Next
	}
	for _, key := range detail.Keys {
		if !keys[key.ID()] {
			t.Fatalf("paging missed key %s (got %d keys)", key.ID(), len(keys))
		}
		read, err := service.ReadJoinKey(ctx, owner, scope, clusterID, key.ID())
		if err != nil || read.ID() != key.ID() || read.State() != key.State() {
			t.Fatalf("ReadJoinKey(%s) = %+v, %v", key.ID(), read, err)
		}
	}
	requests := map[kubecluster.RequestID]bool{}
	query = kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: clusterID, Limit: 2}
	for range len(detail.Requests) + 1 {
		page, err := service.ListReplicaRequests(ctx, query)
		if err != nil || len(page.Requests) > 2 {
			t.Fatalf("ListReplicaRequests(%+v) = %+v, %v", query.After, page, err)
		}
		for _, request := range page.Requests {
			if requests[request.ID()] || request.ClusterID() != clusterID {
				t.Fatalf("request %s twice or of another cluster", request.ID())
			}
			requests[request.ID()] = true
		}
		if page.Next.IsZero() {
			break
		}
		query.After = page.Next
	}
	if len(requests) != len(detail.Requests) {
		t.Fatalf("paged %d requests, the detail lists %d", len(requests), len(detail.Requests))
	}
	first := detail.Requests[0]
	if read, err := service.ReadReplicaRequest(ctx, owner, scope, clusterID, first.ID()); err != nil ||
		read.ID() != first.ID() {
		t.Fatalf("ReadReplicaRequest() = %+v, %v", read, err)
	}

	unknown := kubecluster.ID(mustPublicID(t))
	if _, err := service.ListJoinKeys(ctx, kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: unknown,
		Limit: 1}); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("an unknown cluster's keys: %v", err)
	}
	if _, err := service.ReadJoinKey(ctx, owner, scope, clusterID,
		enrollment.CredentialID(mustPublicID(t))); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("an unknown key: %v", err)
	}
	if _, err := service.ReadReplicaRequest(ctx, owner, scope, clusterID,
		kubecluster.RequestID(mustPublicID(t))); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("an unknown request: %v", err)
	}
	if _, err := service.ListReplicaRequests(ctx, kubecluster.PageQuery{Session: custom, Scope: scope,
		ClusterID: clusterID, Limit: 1}); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("a session without the cluster permissions paged requests: %v", err)
	}
	if _, err := service.ReadJoinKey(ctx, custom, scope, clusterID, detail.Keys[0].ID()); !errors.Is(err,
		kubecluster.ErrForbidden) {
		t.Fatalf("a session without the cluster permissions read a key: %v", err)
	}
	assertKubernetesReplicaReads(ctx, t, admin, service, owner, scope, clusterID, detail)
	// A reader of the Network without the cluster permissions (an auditor)
	// reads the replicas and CAs (Q139), not the keys.
	if _, err := service.ListOperations(ctx, kubecluster.OperationQuery{Session: custom, Scope: scope,
		ClusterID: clusterID, From: time.Now().Add(-time.Hour), To: time.Now(), Limit: 1}); !errors.Is(err,
		kubecluster.ErrForbidden) {
		t.Fatalf("a session without audit.read listed operations: %v", err)
	}
	removeAuditor := seedEnrollmentKeyRole(ctx, t, admin, custom, 1993, "auditor")
	defer removeAuditor()
	if _, err := service.ListJoinKeys(ctx, kubecluster.PageQuery{Session: custom, Scope: scope,
		ClusterID: clusterID, Limit: 1}); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("an auditor listed join keys: %v", err)
	}
	recordOperations()
	auditID := assertKubernetesOperationReads(ctx, t, admin, service, store, owner, custom, scope, clusterID)
	if _, err := service.ListReplicas(ctx, kubecluster.PageQuery{Session: custom, Scope: scope,
		ClusterID: clusterID, Limit: 1}); err != nil {
		t.Fatalf("a Network reader listed no replicas: %v", err)
	}
	if _, err := service.ListCertificateAuthorities(ctx, kubecluster.PageQuery{Session: custom, Scope: scope,
		ClusterID: clusterID, Limit: 1}); err != nil {
		t.Fatalf("a Network reader listed no CAs: %v", err)
	}
	assertKubernetesPagesStayInTheirCluster(ctx, t, service, owner, scope, clusterID, detail, auditID)
	assertKubernetesPagesBreakTies(ctx, t, admin, service, owner, scope, clusterID, len(detail.Requests))
}

// A key or request of one cluster is not found under another cluster of the
// same Network, and paging one cluster lists none of the other's.
func assertKubernetesPagesStayInTheirCluster(ctx context.Context, t *testing.T, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID, detail kubecluster.Detail,
	auditID publicid.ID) {
	t.Helper()
	other := kubecluster.ID(mustPublicID(t))
	if _, err := service.Create(ctx, kubecluster.Creation{Session: owner, Scope: scope, ID: other,
		Name: "pages-other", CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatalf("create another cluster: %v", err)
	}
	issued, err := service.IssueJoinKey(ctx, kubecluster.KeyRequest{Session: owner, Scope: scope,
		ClusterID: other, Uses: 1, CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatalf("issue a key of the other cluster: %v", err)
	}
	if _, err := service.ReadJoinKey(ctx, owner, scope, clusterID, issued.Key.ID()); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("another cluster's key read under this one: %v", err)
	}
	if _, err := service.ReadJoinKey(ctx, owner, scope, other, detail.Keys[0].ID()); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("this cluster's key read under another: %v", err)
	}
	if _, err := service.ReadReplicaRequest(ctx, owner, scope, other, detail.Requests[0].ID()); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("this cluster's request read under another: %v", err)
	}
	if _, err := service.ReadOperation(ctx, owner, scope, other, auditID); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("this cluster's operation read under another: %v", err)
	}
	if _, err := service.ReadReplica(ctx, owner, scope, other, detail.Replicas[0].DeviceID); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("this cluster's replica read under another: %v", err)
	}
	cas, err := service.ListCertificateAuthorities(ctx, kubecluster.PageQuery{Session: owner, Scope: scope,
		ClusterID: clusterID, Limit: 1})
	if err != nil || len(cas.CAs) != 1 {
		t.Fatalf("this cluster's CAs = %+v, %v", cas, err)
	}
	if _, err := service.ReadCertificateAuthority(ctx, owner, scope, other, cas.CAs[0].ID); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("this cluster's CA read under another: %v", err)
	}
	page, err := service.ListJoinKeys(ctx, kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: other,
		Limit: kubecluster.MaximumPageSize})
	if err != nil || len(page.Keys) != 1 || page.Keys[0].ID() != issued.Key.ID() || !page.Next.IsZero() {
		t.Fatalf("the other cluster's keys = %+v, %v", page, err)
	}
	requests, err := service.ListReplicaRequests(ctx, kubecluster.PageQuery{Session: owner, Scope: scope,
		ClusterID: other, Limit: kubecluster.MaximumPageSize})
	if err != nil || len(requests.Requests) != 0 || !requests.Next.IsZero() {
		t.Fatalf("the other cluster's requests = %+v, %v", requests, err)
	}
	if _, err := service.Delete(ctx, kubecluster.Deletion{Session: owner, Scope: scope, ClusterID: other,
		CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatalf("delete the other cluster: %v", err)
	}
}

// Requests sharing one created_at page by public ID, newest first, each
// exactly once: PostgreSQL's uuid order is the cursor's (review d1a M2).
func assertKubernetesPagesBreakTies(ctx context.Context, t *testing.T, admin *pgx.Conn,
	service *kubecluster.Service, owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID,
	count int) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.kubernetes_replica_request AS request
SET created_at = (SELECT pg_catalog.min(created_at) FROM mesh.kubernetes_replica_request
                  WHERE kubernetes_cluster_id = request.kubernetes_cluster_id)
WHERE request.kubernetes_cluster_id = (SELECT id FROM mesh.kubernetes_cluster WHERE public_id = $1::UUID)`,
		clusterID.String()); err != nil {
		t.Fatalf("tie the requests: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	query := kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: clusterID, Limit: 1}
	var seen []publicid.ID
	for range count + 1 {
		page, err := service.ListReplicaRequests(ctx, query)
		if err != nil || len(page.Requests) > 1 {
			t.Fatalf("ListReplicaRequests(%+v) = %+v, %v", query.After, page, err)
		}
		for _, request := range page.Requests {
			id := publicid.ID(request.ID())
			if len(seen) > 0 && seen[len(seen)-1].String() <= id.String() {
				t.Fatalf("tied requests out of order: %s after %s", id, seen[len(seen)-1])
			}
			seen = append(seen, id)
		}
		if page.Next.IsZero() {
			break
		}
		query.After = page.Next
	}
	if len(seen) != count {
		t.Fatalf("paged %d tied requests, want %d", len(seen), count)
	}
}

// The replica reads (schema 248) list the cluster's live gateway Devices,
// one by ID, and nothing for an unknown Device.
func assertKubernetesReplicaReads(ctx context.Context, t *testing.T, admin *pgx.Conn, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID, detail kubecluster.Detail) {
	t.Helper()
	// The gateway proved a pod token: the reads show when (review d1b M1).
	var proven time.Time
	if err := admin.QueryRow(ctx, `INSERT INTO mesh_ops.kubernetes_gateway_token_proof
    (device_id, workspace_id, network_id, first_proven_at)
SELECT device.id, device.workspace_id, device.network_id, pg_catalog.date_trunc('second', now())
FROM mesh.device AS device WHERE device.public_id = $1::UUID
ON CONFLICT (device_id) DO UPDATE SET first_proven_at = mesh_ops.kubernetes_gateway_token_proof.first_proven_at
RETURNING first_proven_at`, detail.Replicas[0].DeviceID.String()).Scan(&proven); err != nil {
		t.Fatalf("record a token proof: %v", err)
	}
	page, err := service.ListReplicas(ctx, kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: clusterID,
		Limit: kubecluster.MaximumPageSize})
	if err != nil || len(page.Replicas) != len(detail.Replicas) || !page.Next.IsZero() {
		t.Fatalf("ListReplicas() = %+v, %v", page, err)
	}
	for index, replica := range page.Replicas {
		want := detail.Replicas[index]
		if replica.DeviceID != want.DeviceID || replica.Name != want.Name || replica.Ordinal != want.Ordinal {
			t.Fatalf("replica %d = %+v, want %+v", index, replica, want)
		}
		read, err := service.ReadReplica(ctx, owner, scope, clusterID, replica.DeviceID)
		if err != nil || read.DeviceID != replica.DeviceID || !read.TokenFirstProvenAt.Equal(replica.TokenFirstProvenAt) {
			t.Fatalf("ReadReplica() = %+v, %v", read, err)
		}
		if index == 0 && !replica.TokenFirstProvenAt.Equal(proven) {
			t.Fatalf("the replica's first token proof = %v, want %v", replica.TokenFirstProvenAt, proven)
		}
	}
	if _, err := service.ReadReplica(ctx, owner, scope, clusterID, node.ID(mustPublicID(t))); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("an unknown replica: %v", err)
	}
}

// The CA reads (schema 248) page every CA of the cluster once, newest
// first, and tell a CA an operator retired, not who did.
func assertKubernetesCAReads(ctx context.Context, t *testing.T, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID, retired publicid.ID,
	operator kubeca.Operator) {
	t.Helper()
	query := kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: clusterID, Limit: 1}
	seen := map[publicid.ID]kubecluster.CertificateAuthority{}
	for range 64 {
		page, err := service.ListCertificateAuthorities(ctx, query)
		if err != nil || len(page.CAs) > 1 {
			t.Fatalf("ListCertificateAuthorities() = %+v, %v", page, err)
		}
		for _, ca := range page.CAs {
			if _, twice := seen[ca.ID]; twice || len(ca.Certificate) == 0 || len(ca.Fingerprint) != 64 {
				t.Fatalf("CA %+v twice or without its certificate", ca)
			}
			seen[ca.ID] = ca
		}
		if page.Next.IsZero() {
			break
		}
		query.After = page.Next
	}
	var roots, intermediates int
	for _, ca := range seen {
		switch ca.Kind {
		case kubecluster.CARoot:
			roots++
		case kubecluster.CAIntermediate:
			intermediates++
		}
	}
	if roots == 0 || intermediates == 0 {
		t.Fatalf("the CA reads hold %d roots and %d intermediates", roots, intermediates)
	}
	read, err := service.ReadCertificateAuthority(ctx, owner, scope, clusterID, retired)
	// An operator retired it: the read says so, never who (review d1b H1).
	if err != nil || read.State != "retired" || !read.ChangedByOperator ||
		read.RetiredAt.IsZero() || read.Kind != kubecluster.CAIntermediate || read.IssuerID == (publicid.ID{}) {
		t.Fatalf("ReadCertificateAuthority(retired) = %+v, %v", read, err)
	}
	if _, err := service.ReadCertificateAuthority(ctx, owner, scope, clusterID, mustPublicID(t)); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("an unknown CA: %v", err)
	}
}

// The operation reads (schema 249): an audit reader pages the cluster's
// recorded operations newest first, filters them, reads one by audit ID,
// sums the denials; a one-day range touches at most two partitions.
func assertKubernetesOperationReads(ctx context.Context, t *testing.T, admin *pgx.Conn,
	service *kubecluster.Service, store *postgresadapter.KubernetesClusterStore, owner, auditor accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID) publicid.ID {
	t.Helper()
	now := time.Now().UTC()
	query := kubecluster.OperationQuery{Session: auditor, Scope: scope, ClusterID: clusterID,
		From: now.Add(-kubecluster.MaximumOperationRange + time.Minute), To: now.Add(time.Minute), Limit: 1}
	var all []kubecluster.Operation
	for range 64 {
		page, err := service.ListOperations(ctx, query)
		if err != nil || page.Truncated {
			t.Fatalf("ListOperations() = %+v, %v", page, err)
		}
		all = append(all, page.Operations...)
		if page.Next.IsZero() {
			break
		}
		query.After = page.Next
	}
	if len(all) == 0 {
		t.Fatal("the cluster's recorded operations read as none")
	}
	for index, operation := range all {
		if index > 0 && !operation.ReceivedAt.Before(all[index-1].ReceivedAt) &&
			!(operation.ReceivedAt.Equal(all[index-1].ReceivedAt) && operation.AuditID.String() < all[index-1].AuditID.String()) {
			t.Fatalf("operations out of order at %d", index)
		}
		if !operation.GatewayDeviceID.IsValid() || len(operation.Groups) == 0 {
			t.Fatalf("operation %+v lacks its gateway or groups", operation)
		}
	}
	first := all[len(all)-1]
	read, err := service.ReadOperation(ctx, auditor, scope, clusterID, first.AuditID)
	if err != nil || read.AuditID != first.AuditID || read.Verb != first.Verb || read.OwnerRef != first.OwnerRef {
		t.Fatalf("ReadOperation() = %+v, %v", read, err)
	}
	if _, err := service.ReadOperation(ctx, auditor, scope, clusterID, mustPublicID(t)); !errors.Is(err,
		kubecluster.ErrNotFound) {
		t.Fatalf("an unknown audit ID: %v", err)
	}
	filtered := kubecluster.OperationQuery{Session: auditor, Scope: scope, ClusterID: clusterID,
		From: now.Add(-23 * time.Hour), To: now.Add(time.Minute), OwnerRef: first.OwnerRef, Class: first.Class,
		Limit: kubecluster.MaximumPageSize}
	page, err := service.ListOperations(ctx, filtered)
	if err != nil || len(page.Operations) == 0 {
		t.Fatalf("filtered ListOperations() = %+v, %v", page, err)
	}
	for _, operation := range page.Operations {
		if operation.OwnerRef != first.OwnerRef || operation.Class != first.Class {
			t.Fatalf("the filter kept %+v", operation)
		}
	}
	filtered.Class = "proxy"
	if page, err := service.ListOperations(ctx, filtered); err != nil || len(page.Operations) != 0 {
		t.Fatalf("a class with no operation kept %+v, %v", page, err)
	}
	if _, err := service.CountDenials(ctx, auditor, scope, clusterID, now.Add(-24*time.Hour),
		now.Add(time.Minute)); err != nil {
		t.Fatalf("CountDenials(): %v", err)
	}
	// An administrator holds audit.read in the Workspace: the Workspace
	// path of the reader (review d1c M2).
	if page, err := service.ListOperations(ctx, kubecluster.OperationQuery{Session: owner, Scope: scope,
		ClusterID: clusterID, From: now.Add(-time.Hour), To: now.Add(time.Minute), Limit: 1}); err != nil ||
		len(page.Operations) != 1 {
		t.Fatalf("a Workspace administrator's operations = %+v, %v", page, err)
	}
	assertKubernetesOperationScanBudget(ctx, t, store, auditor, scope, clusterID, now)
	var plan string
	if err := admin.QueryRow(ctx, `EXPLAIN (FORMAT JSON) SELECT operation.audit_id
FROM mesh_audit.kubernetes_operation AS operation
WHERE operation.kubernetes_cluster_id = 1 AND operation.received_at >= now() - INTERVAL '1 day'
  AND operation.received_at < now()
ORDER BY operation.received_at DESC, operation.audit_id DESC LIMIT 50000`).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if partitions := strings.Count(plan, `"Relation Name": "kubernetes_operation_`); partitions == 0 || partitions > 2 {
		t.Fatalf("a day of operations reads %d partitions: %s", partitions, plan)
	}
	return first.AuditID
}

// assertKubernetesOperationScanBudget pages a filter with a budget of one
// row (review d1c H1): pages stop at the budget, kept or not, and every
// kept row comes exactly once across the pages, also when the last row
// scanned is the one kept.
func assertKubernetesOperationScanBudget(ctx context.Context, t *testing.T,
	store *postgresadapter.KubernetesClusterStore, auditor accountsession.Session, scope network.Scope,
	clusterID kubecluster.ID, now time.Time) {
	t.Helper()
	query := kubecluster.OperationQuery{Session: auditor, Scope: scope, ClusterID: clusterID,
		From: now.Add(-23 * time.Hour), To: now.Add(time.Minute), Class: "exec", Limit: 10,
		ScanBudget: kubecluster.OperationScanBudget}
	whole, err := store.ListOperations(ctx, query)
	if err != nil || len(whole.Operations) == 0 || whole.Truncated || !whole.Next.IsZero() {
		t.Fatalf("the exec operations = %+v, %v", whole, err)
	}
	query.ScanBudget = 1
	seen := map[publicid.ID]int{}
	var keptAndTruncated, emptyAndTruncated bool
	for range 256 {
		page, err := store.ListOperations(ctx, query)
		if err != nil {
			t.Fatalf("a page of one scanned row: %v", err)
		}
		for _, operation := range page.Operations {
			seen[operation.AuditID]++
		}
		keptAndTruncated = keptAndTruncated || page.Truncated && len(page.Operations) == 1
		emptyAndTruncated = emptyAndTruncated || page.Truncated && len(page.Operations) == 0
		if page.Next.IsZero() {
			break
		}
		query.After = page.Next
	}
	for _, operation := range whole.Operations {
		if seen[operation.AuditID] != 1 {
			t.Fatalf("operation %s came %d times", operation.AuditID, seen[operation.AuditID])
		}
	}
	if len(seen) != len(whole.Operations) || !keptAndTruncated || !emptyAndTruncated {
		t.Fatalf("budget pages: %d kept of %d, kept and truncated %t, empty and truncated %t", len(seen),
			len(whole.Operations), keptAndTruncated, emptyAndTruncated)
	}
}

// recordClusterOperations records three operations through the cluster's
// gateway, for one standard Device of its Network (the K1b0 assertions
// erase theirs).
func recordClusterOperations(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, keys replicaKeys,
	gatewayDevice string) {
	t.Helper()
	gateway := hex.EncodeToString(fingerprintOf(keys)) + ":" + hex.EncodeToString(nodeKeyOf(keys))
	var peer string
	if err := admin.QueryRow(ctx, `SELECT peer.public_id::TEXT FROM mesh.device AS peer
JOIN mesh.device AS gateway ON gateway.workspace_id = peer.workspace_id AND gateway.network_id = peer.network_id
WHERE gateway.public_id = $1::UUID AND peer.kind <> 'kubernetes_gateway' AND peer.state = 'active'
  AND peer.deleted_at IS NULL
ORDER BY peer.id LIMIT 1`, gatewayDevice).Scan(&peer); err != nil {
		t.Fatalf("a standard Device of the gateway's Network: %v", err)
	}
	rows := make([]map[string]any, 0, 3)
	for index, class := range []string{"write", "write", "exec"} {
		sum := sha256.Sum256([]byte("pages-" + strconv.Itoa(index)))
		row := operationRow(t, gateway, peer, byte(200+index), hex.EncodeToString(sum[:]))
		row["class"] = class
		rows = append(rows, row)
	}
	for index, answer := range recordOperations(ctx, t, runtime, rows...) {
		if answer["outcome"] != "accepted" {
			t.Fatalf("operation %d answered %v", index, answer)
		}
	}
}
