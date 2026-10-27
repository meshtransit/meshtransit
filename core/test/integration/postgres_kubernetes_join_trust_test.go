//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// assertJoinTrust checks join v2 (schema 232, K1.1 design §6) through the
// production store, after the first replica set the cluster's trust: a
// request's trust never changes, a later replica must match the cluster's
// trust and hold a pod no live Device holds, and a request without trust is
// never approved.
func assertJoinTrust(ctx context.Context, t *testing.T, admin *pgx.Conn, service *kubecluster.Service,
	store *postgresadapter.KubernetesClusterStore, owner accountsession.Session, scope network.Scope,
	clusterID kubecluster.ID, first replicaKeys) {
	t.Helper()
	issued, err := service.IssueJoinKey(ctx, kubecluster.KeyRequest{Session: owner, Scope: scope,
		ClusterID: clusterID, Uses: 4, CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatalf("IssueJoinKey() = %v", err)
	}
	decision := func(ticket kubecluster.JoinTicket) kubecluster.Decision {
		return kubecluster.Decision{Session: owner, Scope: scope, ClusterID: clusterID,
			RequestID: ticket.Request.ID(), CorrelationID: newCorrelationID(t)}
	}
	var waiting []kubecluster.JoinTicket

	// The same keys with other signing material get their request back,
	// marked: the replica's own code cannot match it.
	replica := newReplicaKeys(t)
	ticket, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, replica))
	if err != nil || !ticket.Created || ticket.TrustConflict {
		t.Fatalf("OpenReplicaRequest() = %+v, %v", ticket, err)
	}
	waiting = append(waiting, ticket)
	other := joinAttempt(t, issued.Presentation, replica)
	other.Trust = fixtureTrust(t, replica, "https://other.example")
	again, err := store.OpenReplicaRequest(ctx, other)
	if err != nil || again.Created || !again.TrustConflict || again.Request.ID() != ticket.Request.ID() ||
		again.Nonce != ticket.Nonce {
		t.Fatalf("the same keys with other trust = %+v, %v", again, err)
	}
	if same, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, replica)); err != nil ||
		same.TrustConflict || same.Request.ID() != ticket.Request.ID() {
		t.Fatalf("the same keys with the same trust = %+v, %v", same, err)
	}

	// Another issuer than the cluster's: refused, nothing consumed.
	foreign := newReplicaKeys(t)
	attempt := joinAttempt(t, issued.Presentation, foreign)
	attempt.Trust = fixtureTrust(t, foreign, "https://other.example")
	foreignTicket, err := store.OpenReplicaRequest(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	waiting = append(waiting, foreignTicket)
	code, err := kubejoinCodeV2(foreign, foreignTicket, attempt.Trust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, decision(foreignTicket), code); !errors.Is(err, kubecluster.ErrSigningMismatch) {
		t.Fatalf("approving another issuer's replica: %v", err)
	}

	// The pod of the live gateway: refused.
	twin := twinOf(t, first)
	twinTicket, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, twin))
	if err != nil {
		t.Fatal(err)
	}
	waiting = append(waiting, twinTicket)
	if _, err := service.Approve(ctx, decision(twinTicket), joinCode(t, twinTicket, twin)); !errors.Is(err,
		kubecluster.ErrPodHeld) {
		t.Fatalf("approving a second replica of the gateway's pod: %v", err)
	}

	// Another namespace than the cluster's: refused too.
	elsewhere := newReplicaKeys(t)
	attempt = joinAttempt(t, issued.Presentation, elsewhere)
	attempt.Trust = fixtureTrustIn(t, elsewhere, fixtureIssuer, "default")
	elsewhereTicket, err := store.OpenReplicaRequest(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	waiting = append(waiting, elsewhereTicket)
	code, err = kubejoinCodeV2(elsewhere, elsewhereTicket, attempt.Trust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, decision(elsewhereTicket), code); !errors.Is(err,
		kubecluster.ErrSigningMismatch) {
		t.Fatalf("approving another namespace's replica: %v", err)
	}

	// A pod with an approval in progress is held; once that approval is
	// past its deadline, another replica of the pod is approved.
	holder := newReplicaKeys(t)
	holderTicket, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, holder))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, decision(holderTicket), joinCode(t, holderTicket, holder)); err != nil {
		t.Fatalf("approve the holder: %v", err)
	}
	contender := twinOf(t, holder)
	contenderTicket, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, contender))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, decision(contenderTicket), joinCode(t, contenderTicket, contender)); !errors.Is(
		err, kubecluster.ErrPodHeld) {
		t.Fatalf("approving a pod another approval holds: %v", err)
	}
	shiftReplicaRequest(ctx, t, admin, holderTicket.Request.ID().String(), "-1 hour")
	if _, err := service.Approve(ctx, decision(contenderTicket), joinCode(t, contenderTicket, contender)); err != nil {
		t.Fatalf("approving the pod after the holder's deadline: %v", err)
	}
	assertReplicaRequestState(ctx, t, admin, holderTicket.Request.ID().String(), "expired")
	// An approved request asked again with other trust is a conflict; it
	// expires afterwards, as the test leaves it.
	contenderOther := joinAttempt(t, issued.Presentation, contender)
	contenderOther.Trust = fixtureTrust(t, contender, "https://other.example")
	if conflict, err := store.OpenReplicaRequest(ctx, contenderOther); err != nil || !conflict.TrustConflict {
		t.Fatalf("an approved request asked again with other trust = %+v, %v", conflict, err)
	}
	shiftReplicaRequest(ctx, t, admin, contenderTicket.Request.ID().String(), "-1 hour")

	// Core 231 counts no wrong code on a request with trust: its v1 code
	// never matches, so the database refuses to count.
	assertLegacyCodeFailureRefused(ctx, t, admin, owner, scope, clusterID, ticket.Request.ID())

	// A request opened without trust (by Core 231) is cancelled when
	// approved, and replaced when its replica opens again with trust.
	legacy := newReplicaKeys(t)
	legacyID := openLegacyRequest(ctx, t, admin, scope, issued.Key.ID().String(), legacy)
	if _, err := service.Approve(ctx, kubecluster.Decision{Session: owner, Scope: scope, ClusterID: clusterID,
		RequestID: legacyID, CorrelationID: newCorrelationID(t)}, "AAAAA-AAAAA"); !errors.Is(err,
		kubecluster.ErrJoinAgain) {
		t.Fatalf("approving a request without trust: %v", err)
	}
	assertReplicaRequestState(ctx, t, admin, legacyID.String(), "cancelled")
	replaced := newReplicaKeys(t)
	replacedID := openLegacyRequest(ctx, t, admin, scope, issued.Key.ID().String(), replaced)
	reopened, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, replaced))
	if err != nil || !reopened.Created || reopened.Request.ID() == replacedID {
		t.Fatalf("reopening with trust = %+v, %v", reopened, err)
	}
	waiting = append(waiting, reopened)
	assertReplicaRequestState(ctx, t, admin, replacedID.String(), "cancelled")

	// Core 231's approval approves nothing.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `SELECT mesh_ops.approve_kubernetes_replica_request_v1(
    NULL::UUID,NULL::UUID,NULL::UUID,NULL::UUID,0,0,0,0,0,NULL::UUID,NULL::UUID,NULL::UUID,NULL::UUID,0,NULL::UUID)`)
	if err == nil || !strings.Contains(err.Error(), "MTK14") {
		t.Fatalf("approve v1: %v", err)
	}
	_ = tx.Rollback(ctx)

	for _, open := range waiting {
		if _, err := service.Reject(ctx, decision(open)); err != nil {
			t.Fatalf("reject a test request: %v", err)
		}
	}
}

// openLegacyRequest opens a request with schema 225's function, as Core 231
// does, without trust. A fixture: written past the audit triggers, which
// Core 231 feeds with its own evidence.
func openLegacyRequest(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope, keyID string,
	keys replicaKeys) kubecluster.RequestID {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.set_network_scope($1::UUID, $2::UUID)`, scope.WorkspaceID().String(),
		scope.NetworkID().String()); err != nil {
		t.Fatal(err)
	}
	id := kubecluster.RequestID(mustPublicID(t))
	machine, machineFingerprint := keys.machine.Bytes(), keys.machine.Fingerprint()
	nodeKey, nodeFingerprint := keys.node.Bytes(), keys.node.Fingerprint()
	nonce := mustPublicID(t)
	if _, err := tx.Exec(ctx, `SELECT mesh_ops.open_kubernetes_replica_request_v1(
    $1::UUID, $2::UUID, $3, $4, $5, $6, 'meshgw-0', '{}'::JSONB, $7, pg_catalog.uuidv7())`, keyID, id.String(),
		machine[:], machineFingerprint[:], nodeKey[:], nodeFingerprint[:],
		append(nonce[:], nonce[:]...)); err != nil {
		t.Fatalf("open a request without trust: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

func kubejoinCodeV2(keys replicaKeys, ticket kubecluster.JoinTicket, trust kubecluster.JoinTrust) (string, error) {
	code, err := kubejoinComputeV2(keys, ticket, trust.Digest())
	if err != nil {
		return "", err
	}
	return code, nil
}

// twinOf returns new keys whose replica names the same pod as keys'.
func twinOf(t *testing.T, keys replicaKeys) replicaKeys {
	t.Helper()
	twin := newReplicaKeys(t)
	twinMachine, machine := twin.machine.Bytes(), keys.machine.Bytes()
	twinMachine[0], twinMachine[1] = machine[0], machine[1]
	var err error
	if twin.machine, err = node.NewMachineKey(twinMachine); err != nil {
		t.Fatal(err)
	}
	if fixturePodName(twin) != fixturePodName(keys) {
		t.Fatal("the twin names another pod")
	}
	return twin
}

// assertLegacyCodeFailureRefused calls schema 224's wrong-code counter, as
// Core 231 does, on a request with trust: MTK14, nothing counted.
func assertLegacyCodeFailureRefused(ctx context.Context, t *testing.T, admin *pgx.Conn,
	session accountsession.Session, scope network.Scope, clusterID kubecluster.ID, requestID kubecluster.RequestID) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`,
		scope.WorkspaceID().String(), scope.NetworkID().String()); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `SELECT mesh_ops.record_kubernetes_join_code_failure_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
    $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID)`,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String(), requestID.String(),
		mustPublicID(t).String())
	if err == nil || !strings.Contains(err.Error(), "MTK14") {
		t.Fatalf("Core 231 counted a wrong code on a request with trust: %v", err)
	}
}
