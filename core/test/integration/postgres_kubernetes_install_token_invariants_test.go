//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

// assertKubernetesInstallTokenInvariants qualifies V1-12 step 1f: trust
// mode and install tokens need both approve and manage; a maker who loses
// either approves nothing more; keys are never pasted over an install-token
// cluster; the database keeps the token bounds and the 16 usable keys
// whatever Go sends; a contested cluster issues nothing; two first
// replicas pin one trust.
func assertKubernetesInstallTokenInvariants(ctx context.Context, t *testing.T, admin *pgx.Conn,
	service *kubecluster.Service, store *postgresadapter.KubernetesClusterStore, owner, member accountsession.Session,
	scope network.Scope) {
	t.Helper()
	tokens, err := kubecluster.NewInstallTokens(store, accountsession.SystemClock{}, integrationJoinSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	clusterID, _ := tofuCluster(ctx, t, service, tokens, owner, scope, "tofu-c")

	// Only manage, then only approve: neither sets the mode nor issues.
	request := kubecluster.InstallTokenRequest{Session: member, Scope: scope, ClusterID: clusterID, Replicas: 1,
		CorrelationID: newCorrelationID(t)}
	change := kubecluster.TrustModeChange{Session: member, Scope: scope, ClusterID: clusterID,
		Mode: kubecluster.TrustModeCode, Version: clusterVersion(ctx, t, admin, clusterID),
		CorrelationID: newCorrelationID(t)}
	for index, permission := range []string{"kubernetes_cluster.manage", "kubernetes_cluster.approve"} {
		remove := seedKubernetesNetworkPermission(ctx, t, admin, member, scope, int64(30901+index), permission)
		if _, err := tokens.Issue(ctx, request); !errors.Is(err, kubecluster.ErrForbidden) {
			t.Errorf("only %s issued an install token: %v", permission, err)
		}
		if _, err := tokens.SetTrustMode(ctx, change); !errors.Is(err, kubecluster.ErrForbidden) {
			t.Errorf("only %s set the trust mode: %v", permission, err)
		}
		remove()
	}

	// A maker with both issues; once they lose approve, their token
	// approves nothing.
	removeManage := seedKubernetesNetworkPermission(ctx, t, admin, member, scope, 30903, "kubernetes_cluster.manage")
	defer removeManage()
	removeApprove := seedKubernetesNetworkPermission(ctx, t, admin, member, scope, 30904, "kubernetes_cluster.approve")
	issued, err := tokens.Issue(ctx, request)
	if err != nil {
		removeApprove()
		t.Fatalf("a maker with approve and manage: %v", err)
	}
	removeApprove()
	join := newInstallTokenJoin(t, "meshgw-0", fixtureJWKS)
	ticket := join.open(ctx, t, store, issued.Presentation)
	if result := preapprove(ctx, t, store, issued.Key, ticket, newPodToken(t, newPodUID(t))); result.Outcome !=
		kubecluster.PreapprovalRefused || result.Reason != kubecluster.RefusedApprover {
		t.Fatalf("a maker without approve: Preapprove() = %+v", result)
	}

	// Keys are never pasted over a private_tofu cluster.
	jwks, err := kubejoin.ParseJWKS([]byte(fixtureJWKS))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceTrust(ctx, kubecluster.TrustReplacement{Session: owner, Scope: scope,
		ClusterID: clusterID, Issuer: fixtureIssuer, JWKS: jwks, Namespace: "mt-kube-k1", ServiceAccount: "meshgw",
		StatefulSet: "meshgw", Reason: "paste over an install-token cluster",
		CorrelationID: newCorrelationID(t)}); !errors.Is(err, kubecluster.ErrInstallTokenTrust) {
		t.Fatalf("a paste on a private_tofu cluster: %v", err)
	}

	assertInstallTokenBounds(ctx, t, store, owner, scope, clusterID)
	assertParallelPins(ctx, t, admin, service, store, tokens, owner, scope)
}

// assertInstallTokenBounds sends the store what Go would refuse: the
// database refuses it too, and counts install tokens in the 16 usable keys.
func assertInstallTokenBounds(ctx context.Context, t *testing.T, store *postgresadapter.KubernetesClusterStore,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID) {
	t.Helper()
	secrets := integrationJoinSecrets{}
	issue := func(lifetime time.Duration, replicas int) error {
		t.Helper()
		token, err := secrets.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := secrets.NewCredentialID()
		if err != nil {
			t.Fatal(err)
		}
		preapprovalID, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.IssueInstallToken(ctx, kubecluster.InstallTokenIssue{
			InstallTokenRequest: kubecluster.InstallTokenRequest{Session: owner, Scope: scope, ClusterID: clusterID,
				Lifetime: lifetime, Replicas: replicas, CorrelationID: newCorrelationID(t)},
			KeyID: keyID, PreapprovalID: preapprovalID, Token: token})
		return err
	}
	for name, test := range map[string]struct {
		lifetime time.Duration
		replicas int
	}{
		"299 seconds":    {299 * time.Second, 1},
		"86401 seconds":  {86401 * time.Second, 1},
		"no replica":     {time.Hour, 0},
		"six replicas":   {time.Hour, 6},
		"negative count": {time.Hour, -1},
	} {
		if err := issue(test.lifetime, test.replicas); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: IssueInstallToken() = %v, want ErrInvalid", name, err)
		}
	}
	// The cluster holds one usable install token (the maker's above was
	// spent on nothing: its use was refused). Fill up to 16, then one more.
	issuedCount := 0
	for issuedCount < 20 {
		err := issue(time.Hour, 1)
		if errors.Is(err, kubecluster.ErrLimitReached) {
			break
		}
		if err != nil {
			t.Fatalf("install token %d: %v", issuedCount+1, err)
		}
		issuedCount++
	}
	if issuedCount == 20 || issuedCount < 14 {
		t.Fatalf("issued %d install tokens before the limit", issuedCount)
	}
}

// assertParallelPins: two first replicas of a cluster race; one trust is
// pinned, the other replica is approved under it (same trust) or contests
// it (another trust), never a second pin.
func assertParallelPins(ctx context.Context, t *testing.T, admin *pgx.Conn, service *kubecluster.Service,
	store *postgresadapter.KubernetesClusterStore, tokens *kubecluster.InstallTokens, owner accountsession.Session,
	scope network.Scope) {
	t.Helper()
	clusterID, issued := tofuCluster(ctx, t, service, tokens, owner, scope, "tofu-d")
	joins := []installTokenJoin{newInstallTokenJoin(t, "meshgw-0", fixtureJWKS),
		newInstallTokenJoin(t, "meshgw-1", `{"keys":[`+fixtureOtherKey+`]}`)}
	tickets := make([]kubecluster.JoinTicket, len(joins))
	for index, join := range joins {
		tickets[index] = join.open(ctx, t, store, issued.Presentation)
	}
	results := make([]kubecluster.PreapprovalResult, len(joins))
	errs := make([]error, len(joins))
	var wait sync.WaitGroup
	for index := range joins {
		wait.Go(func() {
			results[index], errs[index] = store.Preapprove(ctx, kubecluster.Preapproval{KeyID: issued.Key.ID(),
				RequestID: tickets[index].Request.ID(), Pod: newPodToken(t, newPodUID(t))})
		})
	}
	wait.Wait()
	pinned, contested := 0, 0
	for index, result := range results {
		if errs[index] != nil {
			t.Fatalf("parallel Preapprove(%d) = %v", index, errs[index])
		}
		switch {
		case result.Outcome == kubecluster.PreapprovalApproved && result.TrustPinned:
			pinned++
		case result.Outcome == kubecluster.PreapprovalContested:
			contested++
		}
	}
	var trusts int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.kubernetes_cluster_signing_trust AS trust
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = trust.kubernetes_cluster_id
WHERE cluster.public_id = $1::UUID`, clusterID.String()).Scan(&trusts); err != nil {
		t.Fatal(err)
	}
	if pinned != 1 || contested != 1 || trusts != 1 {
		t.Fatalf("two first replicas: %d pinned, %d contested, %d trusts", pinned, contested, trusts)
	}
	// A contested cluster issues no install token.
	if _, err := tokens.Issue(ctx, kubecluster.InstallTokenRequest{Session: owner, Scope: scope,
		ClusterID: clusterID, Replicas: 1, CorrelationID: newCorrelationID(t)}); !errors.Is(err,
		kubecluster.ErrTrustContested) {
		t.Fatalf("an install token for a contested cluster: %v", err)
	}
}
