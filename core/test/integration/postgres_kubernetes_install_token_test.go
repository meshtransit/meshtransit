//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
)

// assertKubernetesInstallTokens qualifies V1-12 step 1b (schema 307): a
// cluster that trusts no keys goes private_tofu only with approve and
// manage and the version the person saw; only such a cluster issues install
// tokens (up to a day, one use per replica); approval by code no longer
// anchors its trust; leaving private_tofu revokes its install tokens; and a
// cluster that already trusts keys keeps its mode.
func assertKubernetesInstallTokens(ctx context.Context, t *testing.T, admin *pgx.Conn, service *kubecluster.Service,
	store *postgresadapter.KubernetesClusterStore, owner, custom accountsession.Session, scope network.Scope,
	anchored kubecluster.ID) {
	t.Helper()
	tokens, err := kubecluster.NewInstallTokens(store, accountsession.SystemClock{}, integrationJoinSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	clusterID := kubecluster.ID(mustPublicID(t))
	cluster, err := service.Create(ctx, kubecluster.Creation{Session: owner, Scope: scope, ID: clusterID,
		Name: "tofu", CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatalf("Create(tofu) = %v", err)
	}
	request := kubecluster.InstallTokenRequest{Session: owner, Scope: scope, ClusterID: clusterID,
		Lifetime: 24 * time.Hour, Replicas: 2, CorrelationID: newCorrelationID(t)}
	if _, err := tokens.Issue(ctx, request); !errors.Is(err, kubecluster.ErrInstallTokensOff) {
		t.Fatalf("an install token for a cluster in code mode: %v", err)
	}
	change := kubecluster.TrustModeChange{Session: custom, Scope: scope, ClusterID: clusterID,
		Mode: kubecluster.TrustModePrivateTOFU, Version: cluster.Version(), CorrelationID: newCorrelationID(t)}
	if _, err := tokens.SetTrustMode(ctx, change); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("a role without kubernetes_cluster.manage set the trust mode: %v", err)
	}
	change.Session, change.Version = owner, cluster.Version()+7
	if _, err := tokens.SetTrustMode(ctx, change); !errors.Is(err, kubecluster.ErrConflict) {
		t.Fatalf("a stale version set the trust mode: %v", err)
	}
	change.Version, change.CorrelationID = cluster.Version(), newCorrelationID(t)
	set, err := tokens.SetTrustMode(ctx, change)
	if err != nil || !set.Changed || set.Mode != kubecluster.TrustModePrivateTOFU ||
		set.Cluster.Version() != cluster.Version()+1 {
		t.Fatalf("SetTrustMode(private_tofu) = %+v, %v", set, err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_cluster", clusterID.String(),
		"kubernetes_cluster.trust_mode_changed")
	change.Version, change.CorrelationID = set.Cluster.Version(), newCorrelationID(t)
	if same, err := tokens.SetTrustMode(ctx, change); err != nil || same.Changed {
		t.Fatalf("setting the same mode again = %+v, %v", same, err)
	}

	issued, err := tokens.Issue(ctx, request)
	if err != nil || issued.Replicas != 2 || issued.Key.Uses() != 2 ||
		issued.Key.ExpiresAt().Sub(issued.Key.CreatedAt()) != 24*time.Hour {
		t.Fatalf("Issue() = %+v, %v", issued, err)
	}
	assertKubernetesEvent(ctx, t, admin, "enrollment_credential", issued.Key.ID().String(),
		"kubernetes_join_key.preapproved_issued")
	var preapprovals int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.kubernetes_join_key_preapproval AS preapproval
		JOIN mesh.enrollment_credential AS credential ON credential.id = preapproval.enrollment_credential_id
		WHERE credential.public_id = $1::UUID AND preapproval.replicas = 2`,
		issued.Key.ID().String()).Scan(&preapprovals); err != nil || preapprovals != 1 {
		t.Fatalf("preapproval rows = %d, %v", preapprovals, err)
	}

	// Approval by code never anchors a private_tofu cluster's trust.
	plain, err := service.IssueJoinKey(ctx, kubecluster.KeyRequest{Session: owner, Scope: scope,
		ClusterID: clusterID, Uses: 1, CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatalf("IssueJoinKey(tofu) = %v", err)
	}
	keys := newReplicaKeys(t)
	ticket, err := store.OpenReplicaRequest(ctx, joinAttempt(t, plain.Presentation, keys))
	if err != nil {
		t.Fatalf("OpenReplicaRequest(tofu) = %v", err)
	}
	if _, err := service.Approve(ctx, kubecluster.Decision{Session: owner, Scope: scope, ClusterID: clusterID,
		RequestID: ticket.Request.ID(), CorrelationID: newCorrelationID(t)}, joinCode(t, ticket, keys)); !errors.Is(err,
		kubecluster.ErrInstallTokenTrust) {
		t.Fatalf("approval by code on a private_tofu cluster: %v", err)
	}

	// Back to code: the install token is revoked, the plain key is not.
	back := kubecluster.TrustModeChange{Session: owner, Scope: scope, ClusterID: clusterID,
		Mode: kubecluster.TrustModeCode, Version: set.Cluster.Version(), CorrelationID: newCorrelationID(t)}
	returned, err := tokens.SetTrustMode(ctx, back)
	if err != nil || !returned.Changed || returned.RevokedTokens != 1 {
		t.Fatalf("SetTrustMode(code) = %+v, %v", returned, err)
	}
	var tokenState, plainState string
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT state FROM mesh.enrollment_credential WHERE public_id = $1::UUID),
		(SELECT state FROM mesh.enrollment_credential WHERE public_id = $2::UUID)`,
		issued.Key.ID().String(), plain.Key.ID().String()).Scan(&tokenState, &plainState); err != nil ||
		tokenState != "revoked" || plainState != "active" {
		t.Fatalf("install token %q, plain key %q, %v", tokenState, plainState, err)
	}
	// In code mode again, the plain key's request is approved by its code.
	approved, err := service.Approve(ctx, kubecluster.Decision{Session: owner, Scope: scope, ClusterID: clusterID,
		RequestID: ticket.Request.ID(), CorrelationID: newCorrelationID(t)}, joinCode(t, ticket, keys))
	if err != nil || approved.Lifecycle().State() != kubecluster.RequestApproved {
		t.Fatalf("approval by code after the cluster went back to code mode = %+v, %v", approved, err)
	}

	// A cluster that already trusts keys keeps its mode.
	detail, err := service.Read(ctx, owner, scope, anchored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.SetTrustMode(ctx, kubecluster.TrustModeChange{Session: owner, Scope: scope,
		ClusterID: anchored, Mode: kubecluster.TrustModePrivateTOFU, Version: detail.Cluster.Version(),
		CorrelationID: newCorrelationID(t)}); !errors.Is(err, kubecluster.ErrTrustAnchored) {
		t.Fatalf("a cluster with a trust went private_tofu: %v", err)
	}
}
