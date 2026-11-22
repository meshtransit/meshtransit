//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

// fixtureOtherKey is a second EC key: a JWKS with it is another trust.
const fixtureOtherKey = `{"kty":"EC","crv":"P-256","kid":"other",` +
	`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`

// installTokenJoin is a replica of the install-token tests: its keys, its
// pod and the JWKS its pod sends.
type installTokenJoin struct {
	keys replicaKeys
	pod  string
	jwks string
}

func newInstallTokenJoin(t *testing.T, pod, jwks string) installTokenJoin {
	t.Helper()
	return installTokenJoin{keys: newReplicaKeys(t), pod: pod, jwks: jwks}
}

func (join installTokenJoin) trust(t *testing.T) (kubejoin.Trust, kubecluster.JoinTrust) {
	t.Helper()
	jwks, err := kubejoin.ParseJWKS([]byte(join.jwks))
	if err != nil {
		t.Fatal(err)
	}
	raw := kubejoin.Trust{Issuer: fixtureIssuer, JWKS: jwks, Namespace: "mt-kube-k1", ServiceAccount: "meshgw",
		PodName: join.pod}
	// The token's signer: the first key (sorted by key ID).
	trust, err := kubecluster.NewJoinTrust(raw, jwks.Keys()[0].Thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	return raw, trust
}

func (join installTokenJoin) digest(t *testing.T) [32]byte {
	t.Helper()
	raw, _ := join.trust(t)
	digest, err := kubejoin.ClusterTrustDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func (join installTokenJoin) open(ctx context.Context, t *testing.T, store *postgresadapter.KubernetesClusterStore,
	presentation enrollment.JoinKeyPresentation) kubecluster.JoinTicket {
	t.Helper()
	attempt := joinAttempt(t, presentation, join.keys)
	_, attempt.Trust = join.trust(t)
	ticket, err := store.OpenReplicaRequest(ctx, attempt)
	if err != nil || !ticket.Created || !ticket.Preapproved {
		t.Fatalf("OpenReplicaRequest(%s) = %+v, %v", join.pod, ticket, err)
	}
	return ticket
}

func newPodToken(t *testing.T, uid string) kubecluster.PodToken {
	t.Helper()
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		t.Fatal(err)
	}
	return kubecluster.PodToken{PodUID: uid, JTI: hex.EncodeToString(jti[:]), ExpiresAt: time.Now().Add(time.Hour)}
}

func newPodUID(t *testing.T) string {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func preapprove(ctx context.Context, t *testing.T, store *postgresadapter.KubernetesClusterStore,
	key kubecluster.JoinKey, ticket kubecluster.JoinTicket, pod kubecluster.PodToken) kubecluster.PreapprovalResult {
	t.Helper()
	result, err := store.Preapprove(ctx, kubecluster.Preapproval{KeyID: key.ID(), RequestID: ticket.Request.ID(),
		Pod: pod})
	if err != nil {
		t.Fatalf("Preapprove(%s) = %v", ticket.Request.ID(), err)
	}
	return result
}

// tofuCluster makes a private_tofu cluster and an install token for two
// replicas.
func tofuCluster(ctx context.Context, t *testing.T, service *kubecluster.Service, tokens *kubecluster.InstallTokens,
	owner accountsession.Session, scope network.Scope, name string) (kubecluster.ID, kubecluster.IssuedInstallToken) {
	t.Helper()
	clusterID := kubecluster.ID(mustPublicID(t))
	cluster, err := service.Create(ctx, kubecluster.Creation{Session: owner, Scope: scope, ID: clusterID,
		Name: kubecluster.Name(name), CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatalf("Create(%s) = %v", name, err)
	}
	if _, err := tokens.SetTrustMode(ctx, kubecluster.TrustModeChange{Session: owner, Scope: scope,
		ClusterID: clusterID, Mode: kubecluster.TrustModePrivateTOFU, Version: cluster.Version(),
		CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatal(err)
	}
	issued, err := tokens.Issue(ctx, kubecluster.InstallTokenRequest{Session: owner, Scope: scope,
		ClusterID: clusterID, Replicas: 2, CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatal(err)
	}
	return clusterID, issued
}

// assertKubernetesInstallTokenApproval qualifies V1-12 step 1c (schema
// 309): the first install-token replica pins an unconfirmed trust in its
// maker's name; a pod token is spent once; one use per pod ordinal below
// the token's replicas, the same pod UID replacing its unfinished request;
// another trust contests (the gateway suspended, the tokens revoked); an
// administrator confirms, chooses a side (resume or revoke) or resets.
func assertKubernetesInstallTokenApproval(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, service *kubecluster.Service, store *postgresadapter.KubernetesClusterStore,
	owner accountsession.Session, scope network.Scope) {
	t.Helper()
	tokens, err := kubecluster.NewInstallTokens(store, accountsession.SystemClock{}, integrationJoinSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	trusts, err := kubecluster.NewTrusts(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	completions := newIntegrationJoinCompletions(t, runtimePool)
	clusterID, issued := tofuCluster(ctx, t, service, tokens, owner, scope, "tofu-a")
	key, presentation := issued.Key, issued.Presentation

	// The first replica pins the trust, unconfirmed, approved by the maker.
	first := newInstallTokenJoin(t, "meshgw-0", fixtureJWKS)
	firstTicket := first.open(ctx, t, store, presentation)
	firstPod := newPodToken(t, newPodUID(t))
	approved := preapprove(ctx, t, store, key, firstTicket, firstPod)
	approver, _, _, ok := approved.Request.Approval()
	if approved.Outcome != kubecluster.PreapprovalApproved || !approved.TrustPinned || !ok ||
		approver.String() != owner.PrincipalID().String() {
		t.Fatalf("first Preapprove() = %+v", approved)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_replica_request", firstTicket.Request.ID().String(),
		"kubernetes_replica_request.preapproved")
	assertKubernetesEvent(ctx, t, admin, "kubernetes_cluster", clusterID.String(), "kubernetes_cluster.trust_pinned")
	digest := first.digest(t)
	assertTrustRow(ctx, t, admin, clusterID, "unconfirmed", digest)
	// The trust read shows the unconfirmed trust, its digest, and the token
	// with the ordinal it admitted.
	read, err := trusts.Read(ctx, owner, scope, clusterID)
	if err != nil || read.Mode != kubecluster.TrustModePrivateTOFU || read.Trust == nil ||
		read.Trust.State != kubecluster.TrustUnconfirmed || read.Trust.Side.Digest != digest || !read.CanManage ||
		len(read.Tokens) != 1 || len(read.Tokens[0].UsedOrdinals) != 1 || read.Tokens[0].UsedOrdinals[0] != 0 ||
		read.ClusterVersion != clusterVersion(ctx, t, admin, clusterID) {
		t.Fatalf("Read() after the pin = %+v, %v", read, err)
	}
	// The cluster's signing read shows the pinned trust and its source.
	signing, err := service.ReadSigning(ctx, owner, scope, clusterID)
	if err != nil || signing.Trust == nil || signing.Trust.Source != kubecluster.TrustFromInstallToken {
		t.Fatalf("ReadSigning() of an install-token cluster = %+v, %v", signing.Trust, err)
	}
	completion, err := completions.CompleteReplicaRequest(ctx, firstTicket.Scope, firstTicket.Request.ID(),
		registrationIdentity(t, first.keys))
	if err != nil || completion.State != kubecluster.RequestCompleted {
		t.Fatalf("CompleteReplicaRequest(first) = %+v, %v", completion, err)
	}
	firstDevice := completion.Result.NodeID().String()

	refused := func(join installTokenJoin, pod kubecluster.PodToken, reason string) {
		t.Helper()
		ticket := join.open(ctx, t, store, presentation)
		result := preapprove(ctx, t, store, key, ticket, pod)
		if result.Outcome != kubecluster.PreapprovalRefused || result.Reason != reason ||
			result.Request.Lifecycle().State() != kubecluster.RequestCancelled {
			t.Fatalf("%s: Preapprove() = %+v, want refused %s", join.pod, result, reason)
		}
	}
	// A pod token is spent once.
	replay := firstPod
	replay.PodUID = newPodUID(t)
	refused(newInstallTokenJoin(t, "meshgw-1", fixtureJWKS), replay, kubecluster.RefusedTokenReplayed)
	// The token covers meshgw-0 and meshgw-1 only.
	refused(newInstallTokenJoin(t, "meshgw-2", fixtureJWKS), newPodToken(t, newPodUID(t)),
		kubecluster.RefusedPodOrdinal)
	// The second replica uses ordinal 1.
	secondUID := newPodUID(t)
	second := newInstallTokenJoin(t, "meshgw-1", fixtureJWKS)
	secondTicket := second.open(ctx, t, store, presentation)
	if result := preapprove(ctx, t, store, key, secondTicket, newPodToken(t, secondUID)); result.Outcome !=
		kubecluster.PreapprovalApproved || result.TrustPinned {
		t.Fatalf("second Preapprove() = %+v", result)
	}
	// Another pod for ordinal 1 is refused; the same pod restarted replaces
	// its unfinished request and spends nothing more.
	refused(newInstallTokenJoin(t, "meshgw-1", fixtureJWKS), newPodToken(t, newPodUID(t)),
		kubecluster.RefusedOrdinalUsed)
	restarted := newInstallTokenJoin(t, "meshgw-1", fixtureJWKS)
	restartedTicket := restarted.open(ctx, t, store, presentation)
	restartedPod := newPodToken(t, secondUID)
	if result := preapprove(ctx, t, store, key, restartedTicket, restartedPod); result.Outcome !=
		kubecluster.PreapprovalApproved {
		t.Fatalf("restarted Preapprove() = %+v", result)
	}
	// A copy of that pod's token, from other keys, is refused and leaves
	// the pod's approval alone.
	refused(newInstallTokenJoin(t, "meshgw-1", fixtureJWKS), restartedPod, kubecluster.RefusedTokenReplayed)
	var restartedState string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.kubernetes_replica_request WHERE public_id = $1::UUID`,
		restartedTicket.Request.ID().String()).Scan(&restartedState); err != nil || restartedState != "approved" {
		t.Fatalf("a replayed token changed the pod's approval to %q, %v", restartedState, err)
	}
	// A token expired on the database's clock is refused.
	expired := newPodToken(t, newPodUID(t))
	expired.ExpiresAt = time.Now().Add(time.Second)
	expiredTicket := newInstallTokenJoin(t, "meshgw-0", fixtureJWKS).open(ctx, t, store, presentation)
	time.Sleep(1100 * time.Millisecond)
	if _, err := store.Preapprove(ctx, kubecluster.Preapproval{KeyID: key.ID(),
		RequestID: expiredTicket.Request.ID(), Pod: expired}); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("an expired pod token reached the database: %v", err)
	}
	var secondState string
	var used int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT state FROM mesh.kubernetes_replica_request WHERE public_id = $1::UUID),
    (SELECT used_count FROM mesh.enrollment_credential WHERE public_id = $2::UUID)`,
		secondTicket.Request.ID().String(), key.ID().String()).Scan(&secondState, &used); err != nil ||
		secondState != "cancelled" || used != 2 {
		t.Fatalf("replaced request %q, token used %d, %v", secondState, used, err)
	}

	// Another trust (one key more) contests: the gateway is suspended, the
	// token revoked, the waiting approval cancelled.
	contender := newInstallTokenJoin(t, "meshgw-0", `{"keys":[`+fixtureJWKS[len(`{"keys":[`):len(fixtureJWKS)-2]+
		`,`+fixtureOtherKey+`]}`)
	contenderTicket := contender.open(ctx, t, store, presentation)
	contested := preapprove(ctx, t, store, key, contenderTicket, newPodToken(t, newPodUID(t)))
	if contested.Outcome != kubecluster.PreapprovalContested || len(contested.SuspendedDevices) != 1 ||
		contested.SuspendedDevices[0].String() != firstDevice || contested.RevokedTokens != 1 {
		t.Fatalf("contending Preapprove() = %+v", contested)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_cluster", clusterID.String(),
		"kubernetes_cluster.trust_contested")
	assertDeviceState(ctx, t, admin, firstDevice, "suspended", "trust_contested")
	if read, err := trusts.Read(ctx, owner, scope, clusterID); err != nil || read.Trust == nil ||
		read.Trust.State != kubecluster.TrustContested || read.Trust.Contested == nil ||
		read.Trust.Contested.Digest != contender.digest(t) || read.Trust.Side.Digest != digest {
		t.Fatalf("Read() of a contested trust = %+v, %v", read, err)
	}
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.kubernetes_replica_request WHERE public_id = $1::UUID`,
		restartedTicket.Request.ID().String()).Scan(&secondState); err != nil || secondState != "cancelled" {
		t.Fatalf("the approval waiting under a contested trust is %q, %v", secondState, err)
	}

	version := clusterVersion(ctx, t, admin, clusterID)
	decision := kubecluster.TrustDecision{Session: owner, Scope: scope, ClusterID: clusterID, Digest: digest,
		Version: version, CorrelationID: newCorrelationID(t)}
	if _, err := trusts.Confirm(ctx, decision); !errors.Is(err, kubecluster.ErrTrustContested) {
		t.Fatalf("confirming a contested trust: %v", err)
	}
	wrong := decision
	wrong.Digest = [32]byte{1}
	if _, err := trusts.Choose(ctx, wrong); !errors.Is(err, kubecluster.ErrTrustDigest) {
		t.Fatalf("choosing neither side: %v", err)
	}
	stale := decision
	stale.Version = version - 1
	if _, err := trusts.Choose(ctx, stale); !errors.Is(err, kubecluster.ErrConflict) {
		t.Fatalf("choosing on a stale version: %v", err)
	}
	chosen, err := trusts.Choose(ctx, decision)
	if err != nil || !chosen.Changed || len(chosen.ResumedDevices) != 1 || len(chosen.RevokedDevices) != 0 {
		t.Fatalf("Choose(pinned) = %+v, %v", chosen, err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_cluster", clusterID.String(), "kubernetes_cluster.trust_chosen")
	assertDeviceState(ctx, t, admin, firstDevice, "active", "")
	assertTrustRow(ctx, t, admin, clusterID, "confirmed", digest)

	// A confirmed trust admits the same identity, never another.
	issuedAgain, err := tokens.Issue(ctx, kubecluster.InstallTokenRequest{Session: owner, Scope: scope,
		ClusterID: clusterID, Replicas: 2, CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatal(err)
	}
	key, presentation = issuedAgain.Key, issuedAgain.Presentation
	refused(contender, newPodToken(t, newPodUID(t)), kubecluster.RefusedPodHeld)
	refused(installTokenJoin{keys: newReplicaKeys(t), pod: "meshgw-1", jwks: `{"keys":[` + fixtureOtherKey + `]}`},
		newPodToken(t, newPodUID(t)), kubecluster.RefusedDiffersFromTrust)
	if result := preapprove(ctx, t, store, key, newInstallTokenJoin(t, "meshgw-1", fixtureJWKS).open(ctx, t, store,
		presentation), newPodToken(t, newPodUID(t))); result.Outcome != kubecluster.PreapprovalApproved {
		t.Fatalf("Preapprove() under a confirmed trust = %+v", result)
	}

	// A reset suspends the gateways, revokes the tokens, removes the trust
	// and returns the cluster to code mode.
	if _, err := trusts.Reset(ctx, kubecluster.TrustReset{Session: owner, Scope: scope, ClusterID: clusterID,
		Reason: "  padded", Version: clusterVersion(ctx, t, admin, clusterID),
		CorrelationID: newCorrelationID(t)}); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("a padded reason: %v", err)
	}
	reset, err := trusts.Reset(ctx, kubecluster.TrustReset{Session: owner, Scope: scope, ClusterID: clusterID,
		Reason: "the cluster was rebuilt", Version: clusterVersion(ctx, t, admin, clusterID),
		CorrelationID: newCorrelationID(t)})
	if err != nil || !reset.Changed || len(reset.RevokedDevices) != 1 || len(reset.SuspendedDevices) != 0 ||
		reset.RevokedTokens != 1 {
		t.Fatalf("Reset() = %+v, %v", reset, err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_cluster", clusterID.String(), "kubernetes_cluster.trust_reset")
	assertDeviceState(ctx, t, admin, firstDevice, "revoked", "")
	var trusts309, mode string
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::TEXT FROM mesh.kubernetes_cluster_signing_trust AS trust
     JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = trust.kubernetes_cluster_id
     WHERE cluster.public_id = $1::UUID),
    (SELECT trust_mode FROM mesh.kubernetes_cluster WHERE public_id = $1::UUID)`,
		clusterID.String()).Scan(&trusts309, &mode); err != nil || trusts309 != "0" || mode != "code" {
		t.Fatalf("after reset: %s trusts, mode %q, %v", trusts309, mode, err)
	}

	assertChooseContender(ctx, t, admin, service, store, tokens, trusts, completions, owner, scope)
}

// assertChooseContender: choosing the contending side makes it the trust
// and revokes the gateway approved under the other.
func assertChooseContender(ctx context.Context, t *testing.T, admin *pgx.Conn, service *kubecluster.Service,
	store *postgresadapter.KubernetesClusterStore, tokens *kubecluster.InstallTokens, trusts *kubecluster.Trusts,
	completions *postgresadapter.KubernetesJoinCompletionStore, owner accountsession.Session, scope network.Scope) {
	t.Helper()
	clusterID, issued := tofuCluster(ctx, t, service, tokens, owner, scope, "tofu-b")
	first := newInstallTokenJoin(t, "meshgw-0", fixtureJWKS)
	ticket := first.open(ctx, t, store, issued.Presentation)
	if result := preapprove(ctx, t, store, issued.Key, ticket, newPodToken(t, newPodUID(t))); result.Outcome !=
		kubecluster.PreapprovalApproved {
		t.Fatalf("Preapprove() = %+v", result)
	}
	completion, err := completions.CompleteReplicaRequest(ctx, ticket.Scope, ticket.Request.ID(),
		registrationIdentity(t, first.keys))
	if err != nil {
		t.Fatal(err)
	}
	device := completion.Result.NodeID().String()
	contender := newInstallTokenJoin(t, "meshgw-1", `{"keys":[`+fixtureOtherKey+`,`+
		fixtureJWKS[len(`{"keys":[`):len(fixtureJWKS)-2]+`]}`)
	contenderTicket := contender.open(ctx, t, store, issued.Presentation)
	if result := preapprove(ctx, t, store, issued.Key, contenderTicket, newPodToken(t, newPodUID(t))); result.Outcome !=
		kubecluster.PreapprovalContested {
		t.Fatalf("contending Preapprove() = %+v", result)
	}
	chosen, err := trusts.Choose(ctx, kubecluster.TrustDecision{Session: owner, Scope: scope, ClusterID: clusterID,
		Digest: contender.digest(t), Version: clusterVersion(ctx, t, admin, clusterID),
		CorrelationID: newCorrelationID(t)})
	if err != nil || len(chosen.RevokedDevices) != 1 || chosen.RevokedDevices[0].String() != device ||
		len(chosen.ResumedDevices) != 0 {
		t.Fatalf("Choose(contender) = %+v, %v", chosen, err)
	}
	assertDeviceState(ctx, t, admin, device, "revoked", "")
	assertTrustRow(ctx, t, admin, clusterID, "confirmed", contender.digest(t))
	var keys int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device_node_key_epoch AS epoch
    JOIN mesh.device AS device ON device.id = epoch.device_id
    WHERE device.public_id = $1::UUID AND epoch.state = 'active'`, device).Scan(&keys); err != nil || keys != 0 {
		t.Fatalf("a revoked gateway keeps %d active node keys, %v", keys, err)
	}
}

func assertTrustRow(ctx context.Context, t *testing.T, admin *pgx.Conn, clusterID kubecluster.ID, state string,
	digest [32]byte) {
	t.Helper()
	var gotState, source string
	var gotDigest []byte
	if err := admin.QueryRow(ctx, `SELECT trust.state, trust.source, trust.digest
FROM mesh.kubernetes_cluster_signing_trust AS trust
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = trust.kubernetes_cluster_id
WHERE cluster.public_id = $1::UUID`, clusterID.String()).Scan(&gotState, &source, &gotDigest); err != nil ||
		gotState != state || source != "install_token" || [32]byte(gotDigest) != digest {
		t.Fatalf("trust %s %s %x, %v; want %s %x", gotState, source, gotDigest, err, state, digest)
	}
}

func assertDeviceState(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceID, state, reason string) {
	t.Helper()
	var gotState, gotReason string
	if err := admin.QueryRow(ctx, `SELECT state, COALESCE(suspended_reason, '') FROM mesh.device
WHERE public_id = $1::UUID`, deviceID).Scan(&gotState, &gotReason); err != nil || gotState != state ||
		gotReason != reason {
		t.Fatalf("Device %s is %s/%s, %v; want %s/%s", deviceID, gotState, gotReason, err, state, reason)
	}
}

func clusterVersion(ctx context.Context, t *testing.T, admin *pgx.Conn, clusterID kubecluster.ID) int64 {
	t.Helper()
	var version int64
	if err := admin.QueryRow(ctx, `SELECT version FROM mesh.kubernetes_cluster WHERE public_id = $1::UUID`,
		clusterID.String()).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}
