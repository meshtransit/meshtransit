//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

// secondFixtureJWKS is the fixture key and one more EC key, kid "second".
func secondFixtureJWKS(t *testing.T) (kubejoin.JWKS, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	raw := strings.Replace(fixtureJWKS, `]}`, `,{"kty":"EC","crv":"P-256","kid":"second","x":"`+x+`","y":"`+
		base64.RawURLEncoding.EncodeToString(point[33:65])+`"}]}`, 1)
	jwks, err := kubejoin.ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return jwks, x
}

// assertSigningTrustPaste qualifies schema 235 on the joined cluster: an
// administrator who manages and approves the cluster replaces its trust
// once per version, the same trust again changes nothing, the identity
// stays while a gateway runs, a reader may not, and the replacement is a
// sealed event that never holds the keys themselves. Two first pastes on a
// cluster without trust: one wins.
func assertSigningTrustPaste(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	service *kubecluster.Service, owner, reader accountsession.Session, scope network.Scope,
	clusterID kubecluster.ID, deviceID string) {
	t.Helper()
	fixture, err := kubejoin.ParseJWKS([]byte(fixtureJWKS))
	if err != nil {
		t.Fatal(err)
	}
	replacement := kubecluster.TrustReplacement{Session: owner, Scope: scope, ClusterID: clusterID,
		ExpectedVersion: 99, Issuer: fixtureIssuer, JWKS: fixture, Namespace: "mt-kube-k1",
		ServiceAccount: "meshgw", StatefulSet: "meshgw", Reason: "the same keys again",
		CorrelationID: newCorrelationID(t)}
	replaced := func(want int) {
		t.Helper()
		var events int
		// The trust is the event's aggregate: it keeps its ID across versions.
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS event
JOIN mesh.kubernetes_cluster_signing_trust AS trust ON trust.public_id = event.target_public_id
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = trust.kubernetes_cluster_id
WHERE event.action = 'kubernetes_cluster.signing_trust_replaced'
  AND cluster.public_id = $1::UUID`, clusterID.String()).Scan(&events); err != nil || events != want {
			t.Fatalf("signing_trust_replaced events = %d, %v; want %d", events, err, want)
		}
	}
	// The trust the first approval set, sent again: nothing changes,
	// whatever the version.
	if result, err := service.ReplaceTrust(ctx, replacement); err != nil || result.Changed ||
		result.Trust.Version != 1 {
		t.Fatalf("ReplaceTrust(same) = %+v, %v", result, err)
	}
	replaced(0)
	next, secondX := secondFixtureJWKS(t)
	replacement.JWKS, replacement.Reason, replacement.CorrelationID = next, "the cluster added a key",
		newCorrelationID(t)
	replacement.ExpectedVersion = 0
	if _, err := service.ReplaceTrust(ctx, replacement); !errors.Is(err, kubecluster.ErrTrustChanged) {
		t.Fatalf("ReplaceTrust(version 0 over a trust) = %v", err)
	}
	// The identity stays while the gateway runs.
	moved := replacement
	moved.ExpectedVersion, moved.Namespace, moved.CorrelationID = 1, "elsewhere", newCorrelationID(t)
	if _, err := service.ReplaceTrust(ctx, moved); !errors.Is(err, kubecluster.ErrIdentityBound) {
		t.Fatalf("ReplaceTrust(other namespace) = %v", err)
	}
	// A reader of the Network may not.
	removeRole := seedEnrollmentKeyRole(ctx, t, admin, reader, 1996, "auditor")
	readerReplacement := replacement
	readerReplacement.Session, readerReplacement.ExpectedVersion = reader, 1
	if _, err := service.ReplaceTrust(ctx, readerReplacement); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("a reader replaced the trust: %v", err)
	}
	// Replacing needs both permissions (owner decision Q3 B): either alone is refused,
	// writes nothing, and the read offers no replacement.
	for index, permission := range []string{"kubernetes_cluster.manage", "kubernetes_cluster.approve"} {
		removeGrant := seedKubernetesNetworkPermission(ctx, t, admin, reader, scope, int64(1997+index), permission)
		readerReplacement.CorrelationID = newCorrelationID(t)
		if _, err := service.ReplaceTrust(ctx, readerReplacement); !errors.Is(err, kubecluster.ErrForbidden) {
			t.Fatalf("%s alone replaced the trust: %v", permission, err)
		}
		// The grant took: one permission shows the unknown kids, a plain reader does not.
		if signing, err := service.ReadSigning(ctx, reader, scope, clusterID); err != nil || signing.CanReplaceTrust ||
			signing.UnknownKeyIDs == nil {
			t.Fatalf("%s alone: ReadSigning() = %+v, %v", permission, signing, err)
		}
		removeGrant()
	}
	replaced(0)
	replacement.ExpectedVersion, replacement.CorrelationID = 1, newCorrelationID(t)
	result, err := service.ReplaceTrust(ctx, replacement)
	if err != nil || !result.Changed || result.Trust.Version != 2 ||
		result.Trust.Source != kubecluster.TrustFromAdminPaste || len(result.Trust.Keys) != 2 ||
		result.Previous == nil || result.Previous.Version != 1 {
		t.Fatalf("ReplaceTrust(new keys) = %+v, %v", result, err)
	}
	replaced(1)
	// A retry after success, with the version it sent: nothing changes.
	replacement.CorrelationID = newCorrelationID(t)
	if again, err := service.ReplaceTrust(ctx, replacement); err != nil || again.Changed ||
		again.Trust.Version != 2 {
		t.Fatalf("ReplaceTrust(retry) = %+v, %v", again, err)
	}
	replaced(1)
	var payload string
	var sourceRequest *int64
	if err := admin.QueryRow(ctx, `SELECT event.payload::TEXT, trust.source_request_id
FROM mesh_audit.audit_event AS event
JOIN mesh.kubernetes_cluster_signing_trust AS trust ON trust.public_id = event.target_public_id
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = trust.kubernetes_cluster_id
WHERE event.action = 'kubernetes_cluster.signing_trust_replaced' AND cluster.public_id = $1::UUID`,
		clusterID.String()).Scan(&payload, &sourceRequest); err != nil {
		t.Fatal(err)
	}
	if sourceRequest != nil || !strings.Contains(payload, `"reason": "the cluster added a key"`) ||
		!strings.Contains(payload, `"previous_version": 1`) || !strings.Contains(payload, `"second"`) ||
		strings.Contains(payload, secondX) {
		t.Fatalf("replacement payload %s, source request %v", payload, sourceRequest)
	}

	// The read names the keys, who set them, and who may replace them.
	signing, err := service.ReadSigning(ctx, owner, scope, clusterID)
	if err != nil || !signing.CanReplaceTrust || signing.Trust == nil || len(signing.Trust.Keys) != 2 ||
		!signing.Trust.SetBy.IsValid() || signing.UnknownKeyIDs == nil {
		t.Fatalf("ReadSigning(owner) = %+v, %v", signing, err)
	}
	read, err := service.ReadSigning(ctx, reader, scope, clusterID)
	if err != nil || read.CanReplaceTrust || read.Trust == nil || read.Trust.SetBy.IsValid() ||
		read.UnknownKeyIDs != nil {
		t.Fatalf("ReadSigning(reader) = %+v, %v", read, err)
	}
	removeRole()

	// A token signed by a key the trust lacks names it, since the trust was
	// set.
	events, err := postgresadapter.NewKubernetesGatewayKeyEventStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := gatewayKeyFingerprints(ctx, t, admin, deviceID)
	if outcome, err := events.Record(ctx, current, kubecluster.KeyEventTokenUnknownKey, 0,
		"rotated-kid"); err != nil || outcome != kubecluster.KeyEventRecorded {
		t.Fatalf("Record(unknown key) = %v, %v", outcome, err)
	}
	signing, err = service.ReadSigning(ctx, owner, scope, clusterID)
	if err != nil || len(signing.UnknownKeyIDs) != 1 || signing.UnknownKeyIDs[0] != "rotated-kid" {
		t.Fatalf("ReadSigning() unknown kids = %v, %v", signing.UnknownKeyIDs, err)
	}

	// Two first pastes on a cluster without trust: one wins, one is told
	// the trust changed.
	fresh := kubecluster.ID(mustPublicID(t))
	if _, err := service.Create(ctx, kubecluster.Creation{Session: owner, Scope: scope, ID: fresh,
		Name: "paste-race", CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for index := range results {
		wg.Go(func() {
			first := replacement
			first.ClusterID, first.ExpectedVersion, first.CorrelationID = fresh, 0, publicid.ID(mustPublicID(t))
			if index == 1 {
				first.JWKS = fixture
			}
			_, results[index] = service.ReplaceTrust(ctx, first)
		})
	}
	wg.Wait()
	won, lost := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, kubecluster.ErrTrustChanged):
			lost++
		default:
			t.Fatalf("a first paste failed otherwise: %v", err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("first pastes: %d won, %d lost", won, lost)
	}
	if _, err := service.Delete(ctx, kubecluster.Deletion{Session: owner, Scope: scope, ClusterID: fresh,
		CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatalf("delete the race cluster: %v", err)
	}
}

// seedKubernetesNetworkPermission gives the session's principal a custom
// role on the scope's Network holding one permission, through the exact
// Network role resolver; the returned function removes it.
func seedKubernetesNetworkPermission(ctx context.Context, t *testing.T, admin *pgx.Conn,
	session accountsession.Session, scope network.Scope, id int64, permission string) func() {
	t.Helper()
	principal := publicid.ID(session.PrincipalID()).String()
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `INSERT INTO mesh.role_definition (id, public_id, deployment_id, workspace_id, role_key, display_name,
    kind, state, authority_generation)
OVERRIDING SYSTEM VALUE VALUES ($1::BIGINT, pg_catalog.uuidv7(), 1, 103, 'k1_only_' || $1::BIGINT::TEXT,
    'K1.1b only ' || $1::BIGINT::TEXT, 'custom', 'active', 1)`, args: []any{id}},
		{sql: `INSERT INTO mesh.role_permission (id, public_id, deployment_id, workspace_id, role_definition_id,
    permission_id)
OVERRIDING SYSTEM VALUE SELECT $1::BIGINT, pg_catalog.uuidv7(), 1, 103, $1::BIGINT, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = $2`, args: []any{id, permission}},
		{sql: `INSERT INTO mesh.role_binding (id, public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, role_definition_id, state, authority_generation, valid_from)
OVERRIDING SYSTEM VALUE SELECT $1::BIGINT, pg_catalog.uuidv7(), 1, 103, network.id, principal.id, membership.id,
    $1::BIGINT,
    'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
FROM mesh.principal AS principal
JOIN mesh.workspace_membership AS membership
  ON membership.workspace_id = 103 AND membership.principal_id = principal.id
JOIN mesh.network AS network ON network.public_id = $3::UUID
WHERE principal.public_id = $2::UUID`, args: []any{id, principal, scope.NetworkID().String()}},
	})
	return func() {
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
			{sql: `DELETE FROM mesh.role_binding WHERE id = $1`, args: []any{id}},
			{sql: `DELETE FROM mesh.role_permission WHERE id = $1`, args: []any{id}},
			{sql: `DELETE FROM mesh.role_definition WHERE id = $1`, args: []any{id}},
		})
	}
}
