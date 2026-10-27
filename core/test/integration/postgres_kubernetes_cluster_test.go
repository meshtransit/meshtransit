//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

type integrationJoinSecrets struct{}

func (integrationJoinSecrets) NewToken() (enrollment.CredentialToken, error) {
	return enrollment.GenerateCredentialToken()
}

func (integrationJoinSecrets) NewCredentialID() (enrollment.CredentialID, error) {
	id, err := publicid.New()
	return enrollment.CredentialID(id), err
}

func newIntegrationKubernetesClusters(t *testing.T, runtimePool *postgresadapter.Pool) (
	*kubecluster.Service, *postgresadapter.KubernetesClusterStore) {
	t.Helper()
	keyID, err := enrollment.NewDigestKeyID("integration-enrollment-key-v1")
	if err != nil {
		t.Fatal(err)
	}
	material := filledIntegrationKey(0x61)
	digestKey, err := enrollment.NewDigestKey(keyID, material[:])
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := enrollment.NewCredentialKeyring(digestKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresadapter.NewKubernetesClusterStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second},
		keyring)
	if err != nil {
		t.Fatal(err)
	}
	service, err := kubecluster.NewService(store, accountsession.SystemClock{}, integrationJoinSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	return service, store
}

// replicaKeys are one replica's machine and node keys.
type replicaKeys struct {
	machine node.MachineKey
	node    node.Key
}

func newReplicaKeys(t *testing.T) replicaKeys {
	t.Helper()
	var machine, nodeKey [32]byte
	if _, err := rand.Read(machine[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nodeKey[:]); err != nil {
		t.Fatal(err)
	}
	machineKey, err := node.NewMachineKey(machine)
	if err != nil {
		t.Fatal(err)
	}
	return replicaKeys{machine: machineKey, node: node.Key(nodeKey)}
}

func joinAttempt(t *testing.T, presentation enrollment.JoinKeyPresentation, keys replicaKeys) kubecluster.JoinAttempt {
	t.Helper()
	hostname, err := node.ParseHostname("meshgw-0")
	if err != nil {
		t.Fatal(err)
	}
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return kubecluster.JoinAttempt{
		Presentation: presentation, MachineKey: keys.machine, NodeKey: keys.node, Hostname: hostname,
		Reported: []byte(`{"namespace":"mt-kube","pod":"meshgw-0"}`), RequestID: kubecluster.RequestID(id),
		Nonce: nonce, Trust: fixtureTrust(t, keys, fixtureIssuer),
	}
}

const fixtureIssuer = "https://kubernetes.default.svc.cluster.local"

// fixtureJWKS is the EC key of RFC 7517 Appendix A.1: the stores never see a
// token, only the signing material Core verified (K1.1).
const fixtureJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"fixture",` +
	`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`

// fixturePodName names a replica's pod after its keys, so every replica of
// a test has its own pod and its code can be computed again.
func fixturePodName(keys replicaKeys) string {
	machine := keys.machine.Bytes()
	return fmt.Sprintf("meshgw-%d", int(machine[0])<<8|int(machine[1]))
}

// fixtureTrust is the trust a replica with keys would send, under issuer.
func fixtureTrust(t *testing.T, keys replicaKeys, issuer string) kubecluster.JoinTrust {
	t.Helper()
	return fixtureTrustIn(t, keys, issuer, "mt-kube-k1")
}

// fixtureTrustIn is fixtureTrust in another namespace.
func fixtureTrustIn(t *testing.T, keys replicaKeys, issuer, namespace string) kubecluster.JoinTrust {
	t.Helper()
	jwks, err := kubejoin.ParseJWKS([]byte(fixtureJWKS))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := jwks.Key("fixture")
	trust, err := kubecluster.NewJoinTrust(kubejoin.Trust{Issuer: issuer, JWKS: jwks, Namespace: namespace,
		ServiceAccount: "meshgw", PodName: fixturePodName(keys)}, signer.Thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

// kubejoinComputeV2 is the code v2 the replica with keys prints for ticket.
func kubejoinComputeV2(keys replicaKeys, ticket kubecluster.JoinTicket, digest [32]byte) (string, error) {
	code, err := kubejoin.ComputeV2(kubejoin.Inputs{
		MachineKey: keys.machine.Bytes(), NodeKey: keys.node.Bytes(),
		ClusterID: [16]byte(publicid.ID(ticket.ClusterID)), RequestNonce: ticket.Nonce,
	}, digest)
	return code.String(), err
}

func joinCode(t *testing.T, ticket kubecluster.JoinTicket, keys replicaKeys) string {
	t.Helper()
	code, err := kubejoin.ComputeV2(kubejoin.Inputs{
		MachineKey: keys.machine.Bytes(), NodeKey: keys.node.Bytes(),
		ClusterID: [16]byte(publicid.ID(ticket.ClusterID)), RequestNonce: ticket.Nonce,
	}, fixtureTrust(t, keys, fixtureIssuer).Digest())
	if err != nil {
		t.Fatal(err)
	}
	return code.String()
}

// assertPostgreSQLKubernetesClusters qualifies K1a1.1 through the production
// store on Network 203: only a role with kubernetes_cluster.manage creates
// clusters and keys; a join key never enrolls through the ordinary path;
// a replica's request holds no Device and is approved only by its code,
// which consumes one use of the key; wrong codes count and the fifth
// cancels; rejected, cancelled and revoked requests stay decided; the
// waiting queue is bounded; a cluster with open requests cannot be deleted;
// and only migrator-owned functions write gateway Devices.
func assertPostgreSQLKubernetesClusters(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	service, store := newIntegrationKubernetesClusters(t, runtimePool)
	members := newNetworkMemberFixture(t, runtimePool)
	custom, owner := members.owner, members.confirmer
	scope := members.scope

	clusterID := kubecluster.ID(mustPublicID(t))
	creation := kubecluster.Creation{Session: custom, Scope: scope, ID: clusterID, Name: "prod",
		Description: "EKS Singapore", CorrelationID: newCorrelationID(t)}
	if _, err := service.Create(ctx, creation); !errors.Is(err, kubecluster.ErrForbidden) {
		t.Fatalf("a role without kubernetes_cluster.manage created a cluster: %v", err)
	}
	removeRole := seedEnrollmentKeyRole(ctx, t, admin, owner, 1992, "admin")
	defer removeRole()
	creation.Session = owner
	cluster, err := service.Create(ctx, creation)
	if err != nil || cluster.ID() != clusterID || cluster.Name() != "prod" || cluster.Replicas() != 0 {
		t.Fatalf("Create() = %+v, %v", cluster, err)
	}
	duplicate := creation
	duplicate.ID, duplicate.CorrelationID = kubecluster.ID(mustPublicID(t)), newCorrelationID(t)
	if _, err := service.Create(ctx, duplicate); !errors.Is(err, kubecluster.ErrConflict) {
		t.Fatalf("a second cluster named prod: %v", err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_cluster", clusterID.String(), "kubernetes_cluster.created")

	for name, request := range map[string]kubecluster.KeyRequest{
		"over an hour":  {Lifetime: 2 * time.Hour, Uses: 1},
		"nine uses":     {Lifetime: time.Hour, Uses: 9},
		"no use at all": {Lifetime: time.Hour},
	} {
		request.Session, request.Scope, request.ClusterID, request.CorrelationID = owner, scope, clusterID,
			newCorrelationID(t)
		if _, err := service.IssueJoinKey(ctx, request); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: IssueJoinKey() error = %v, want ErrInvalid", name, err)
		}
	}
	issued, err := service.IssueJoinKey(ctx, kubecluster.KeyRequest{Session: owner, Scope: scope,
		ClusterID: clusterID, Uses: 2, CorrelationID: newCorrelationID(t)})
	if err != nil || issued.Key.Uses() != 2 || issued.Key.State() != kubecluster.KeyActive ||
		issued.Key.ExpiresAt().Sub(issued.Key.CreatedAt()) != time.Hour {
		t.Fatalf("IssueJoinKey() = %+v, %v", issued.Key, err)
	}
	keyID := issued.Key.ID()
	assertKubernetesEvent(ctx, t, admin, "enrollment_credential", keyID.String(), "kubernetes_join_key.issued")

	assertJoinKeyRefusedByEnrollment(ctx, t, admin, keyID)
	assertGatewayWritersRefused(ctx, t, admin, clusterID)
	assertGatewayDeviceGuards(ctx, t, admin, clusterID)
	assertGatewayReferenceCoverage(ctx, t, admin)
	assertKubernetesGroupReferenceCoverage(ctx, t, admin)

	// An enrollment key's ID and secret, presented as a join key, open nothing.
	enrollmentKeys := newIntegrationEnrollmentKeyService(t, runtimePool)
	enrollmentKey, err := enrollmentKeys.Issue(ctx, owner, enrollmentkey.IssueRequest{Scope: scope,
		DeviceLifetime: enrollment.NeverExpiringDeviceLifetime(), CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatalf("issue an enrollment key: %v", err)
	}
	disguised, err := enrollment.NewJoinKeyPresentation(enrollmentKey.Key().ID(), enrollmentKey.Presentation().Token())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenReplicaRequest(ctx, joinAttempt(t, disguised, newReplicaKeys(t))); !errors.Is(err,
		kubecluster.ErrJoinRefused) {
		t.Fatalf("an enrollment key opened a replica request: %v", err)
	}
	// A machine key a Device already holds opens nothing either.
	var heldMachine []byte
	if err := admin.QueryRow(ctx, `SELECT public_key FROM mesh.device_machine_key_epoch
WHERE workspace_id = 103 AND network_id = 203 ORDER BY id LIMIT 1`).Scan(&heldMachine); err != nil {
		t.Fatalf("read a held machine key: %v", err)
	}
	held := newReplicaKeys(t)
	if held.machine, err = node.NewMachineKey([32]byte(heldMachine)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, held)); !errors.Is(err,
		kubecluster.ErrKeysInUse) {
		t.Fatalf("a held machine key opened a replica request: %v", err)
	}

	// A wrong secret, or an enrollment key's ID, opens nothing.
	wrongToken, err := enrollment.GenerateCredentialToken()
	if err != nil {
		t.Fatal(err)
	}
	wrongSecret, err := enrollment.NewJoinKeyPresentation(keyID, wrongToken)
	if err != nil {
		t.Fatal(err)
	}
	first := newReplicaKeys(t)
	if _, err := store.OpenReplicaRequest(ctx, joinAttempt(t, wrongSecret, first)); !errors.Is(err,
		kubecluster.ErrJoinRefused) {
		t.Fatalf("a wrong secret opened a request: %v", err)
	}
	attempt := joinAttempt(t, issued.Presentation, first)
	ticket, err := store.OpenReplicaRequest(ctx, attempt)
	if err != nil || !ticket.Created || ticket.ClusterID != clusterID ||
		ticket.Request.Lifecycle().State() != kubecluster.RequestPending {
		t.Fatalf("OpenReplicaRequest() = %+v, %v", ticket, err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_replica_request", ticket.Request.ID().String(),
		"kubernetes_replica_request.opened")
	again, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, first))
	if err != nil || again.Created || again.Request.ID() != ticket.Request.ID() || again.Nonce != ticket.Nonce {
		t.Fatalf("the same keys asking again = %+v, %v", again, err)
	}
	borrowed := newReplicaKeys(t)
	borrowed.node = first.node
	if _, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, borrowed)); !errors.Is(err,
		kubecluster.ErrKeysInUse) {
		t.Fatalf("another machine with the same node key: %v", err)
	}
	assertNoGatewayDevice(ctx, t, admin, clusterID)
	completions := newIntegrationJoinCompletions(t, runtimePool)
	if waiting, err := completions.CompleteReplicaRequest(ctx, ticket.Scope, ticket.Request.ID(),
		registrationIdentity(t, first)); err != nil || waiting.State != kubecluster.RequestPending {
		t.Fatalf("completing a waiting request = %+v, %v", waiting, err)
	}

	// Another Network's scope sees nothing of this one's requests.
	otherNetwork, err := network.NewScope(scope.WorkspaceID(), network.ID(mustPublicID(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(ctx, kubecluster.Decision{Session: owner, Scope: otherNetwork,
		ClusterID: clusterID, RequestID: ticket.Request.ID(), CorrelationID: newCorrelationID(t)},
		joinCode(t, ticket, first)); !errors.Is(err, kubecluster.ErrForbidden) && !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("another Network approved the request: %v", err)
	}
	decision := kubecluster.Decision{Session: owner, Scope: scope, ClusterID: clusterID,
		RequestID: ticket.Request.ID(), CorrelationID: newCorrelationID(t)}
	if _, err := service.Approve(ctx, decision, "not a code"); !errors.Is(err, kubecluster.ErrInvalid) {
		t.Fatalf("a malformed code: %v", err)
	}
	var wrong *kubecluster.WrongCodeError
	for attemptNumber := 1; attemptNumber <= 2; attemptNumber++ {
		decision.CorrelationID = newCorrelationID(t)
		if _, err := service.Approve(ctx, decision, "AAAAA-AAAAA"); !errors.As(err, &wrong) ||
			wrong.Remaining != kubecluster.MaximumCodeAttempts-attemptNumber {
			t.Fatalf("wrong code %d: %v", attemptNumber, err)
		}
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_replica_request", ticket.Request.ID().String(),
		"kubernetes_replica_request.code_failed")
	decision.CorrelationID = newCorrelationID(t)
	approved, err := service.Approve(ctx, decision, joinCode(t, ticket, first))
	ordinal, hostname, reserved := approved.Reservation()
	if err != nil || approved.Lifecycle().State() != kubecluster.RequestApproved || !reserved ||
		ordinal != 0 || hostname != "prod-0" {
		t.Fatalf("Approve() = %+v, %v", approved, err)
	}
	if _, _, deadline, ok := approved.Approval(); !ok || time.Until(deadline) > 15*time.Minute {
		t.Fatalf("approval deadline = %v, %v", deadline, ok)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_replica_request", ticket.Request.ID().String(),
		"kubernetes_replica_request.approved")
	decision.CorrelationID = newCorrelationID(t)
	if _, err := service.Approve(ctx, decision, joinCode(t, ticket, first)); !errors.Is(err,
		kubecluster.ErrNotWaiting) {
		t.Fatalf("approving twice: %v", err)
	}
	assertNoGatewayDevice(ctx, t, admin, clusterID)
	// Past its completion deadline the request answers expired, and the
	// answer writes nothing: open and approve move such rows.
	shiftReplicaRequest(ctx, t, admin, ticket.Request.ID().String(), "-1 hour")
	if _, err := completions.CompleteReplicaRequest(ctx, ticket.Scope, ticket.Request.ID(),
		registrationIdentity(t, first)); !errors.Is(err, kubecluster.ErrExpired) {
		t.Fatalf("completing past the deadline: %v", err)
	}
	assertReplicaRequestState(ctx, t, admin, ticket.Request.ID().String(), "approved")
	assertNoGatewayDevice(ctx, t, admin, clusterID)
	shiftReplicaRequest(ctx, t, admin, ticket.Request.ID().String(), "1 hour")
	policyGroup := ensureKubernetesPolicyGroup(ctx, t, admin, runtimePool, owner, scope, clusterID)
	gatewayDevice := assertReplicaCompletes(ctx, t, admin, completions, ticket, first)
	assertGatewayJoinedItsGroup(ctx, t, admin, policyGroup, gatewayDevice)
	assertGatewaySessionProof(ctx, t, admin, runtime, runtimePool, first, gatewayDevice)
	assertGatewayRotationTokens(ctx, t, admin, runtime, first, gatewayDevice)
	assertJoinTrust(ctx, t, admin, service, store, owner, scope, clusterID, first)
	assertGatewayMachineKeyRotation(ctx, t, admin, runtime, runtimePool, first, gatewayDevice)
	assertGatewayKeyEvents(ctx, t, admin, runtimePool, service, owner, scope, clusterID, gatewayDevice)
	assertGatewayTokenAuditAndSigning(ctx, t, admin, runtime, runtimePool, service, owner, custom, scope,
		clusterID, gatewayDevice)
	assertKubernetesPolicyGroupGuards(ctx, t, admin, policyGroup, gatewayDevice)
	assertMapListsKubernetesGateways(ctx, t, admin, scope, gatewayDevice, "prod")
	assertMapMarksKubernetesReplicas(ctx, t, admin, runtimePool, scope, gatewayDevice, "prod")

	// A second replica: its own code does not approve the first's request,
	// and it is rejected.
	second := newReplicaKeys(t)
	secondTicket, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, second))
	if err != nil || !secondTicket.Created {
		t.Fatalf("second request = %+v, %v", secondTicket, err)
	}
	decision.RequestID, decision.CorrelationID = secondTicket.Request.ID(), newCorrelationID(t)
	if _, err := service.Approve(ctx, decision, joinCode(t, ticket, first)); !errors.As(err, &wrong) {
		t.Fatalf("the first replica's code approved the second request: %v", err)
	}
	assertDatabaseChecksTheCode(ctx, t, admin, owner, scope, clusterID, secondTicket.Request.ID())
	decision.CorrelationID = newCorrelationID(t)
	rejected, err := service.Reject(ctx, decision)
	if err != nil || rejected.Lifecycle().State() != kubecluster.RequestRejected {
		t.Fatalf("Reject() = %+v, %v", rejected, err)
	}
	decision.CorrelationID = newCorrelationID(t)
	if _, err := service.Approve(ctx, decision, joinCode(t, secondTicket, second)); !errors.Is(err,
		kubecluster.ErrNotWaiting) {
		t.Fatalf("approving a rejected request: %v", err)
	}

	// Five wrong codes cancel; the key had one use left and still has it.
	third := newReplicaKeys(t)
	thirdTicket, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, third))
	if err != nil {
		t.Fatal(err)
	}
	decision.RequestID = thirdTicket.Request.ID()
	for attemptNumber := 1; attemptNumber <= kubecluster.MaximumCodeAttempts; attemptNumber++ {
		decision.CorrelationID = newCorrelationID(t)
		view, err := service.Approve(ctx, decision, "BBBBB-BBBBB")
		if !errors.As(err, &wrong) || wrong.Remaining != kubecluster.MaximumCodeAttempts-attemptNumber {
			t.Fatalf("wrong code %d: %+v, %v", attemptNumber, view, err)
		}
		if attemptNumber == kubecluster.MaximumCodeAttempts && view.Lifecycle().State() != kubecluster.RequestCancelled {
			t.Fatalf("the fifth wrong code left the request %s", view.Lifecycle().State())
		}
	}

	// The waiting queue holds twice the key's uses: 4 here.
	// The first carries the largest report a pod may send: stored as JSONB it
	// grows, and every read of the cluster must still decode it.
	largest := map[string]string{}
	for index := range kubecluster.MaximumReportedFields {
		largest[fmt.Sprintf("k%02d", index)] = strings.Repeat("v", 110)
	}
	largestReport, err := json.Marshal(largest)
	if err != nil || len(largestReport) > kubecluster.MaximumReportedBytes {
		t.Fatalf("largest report = %d bytes, %v", len(largestReport), err)
	}
	for index := range 4 {
		attempt := joinAttempt(t, issued.Presentation, newReplicaKeys(t))
		if index == 0 {
			attempt.Reported = largestReport
		}
		_, err := store.OpenReplicaRequest(ctx, attempt)
		if index < 4 && err != nil {
			t.Fatalf("waiting request %d: %v", index, err)
		}
	}
	if _, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, newReplicaKeys(t))); !errors.Is(
		err, kubecluster.ErrQueueFull) {
		t.Fatalf("a fifth waiting request: %v", err)
	}

	if _, err := service.Delete(ctx, kubecluster.Deletion{Session: owner, Scope: scope, ClusterID: clusterID,
		CorrelationID: newCorrelationID(t)}); !errors.Is(err, kubecluster.ErrConflict) {
		t.Fatalf("deleting a cluster with open requests: %v", err)
	}
	revoked, err := service.RevokeJoinKey(ctx, kubecluster.KeyRevocation{Session: owner, Scope: scope,
		ClusterID: clusterID, KeyID: keyID, CorrelationID: newCorrelationID(t)})
	if err != nil || revoked.State() != kubecluster.KeyRevoked {
		t.Fatalf("RevokeJoinKey() = %+v, %v", revoked, err)
	}
	var open int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.kubernetes_replica_request
WHERE kubernetes_cluster_id = (SELECT id FROM mesh.kubernetes_cluster WHERE public_id = $1::UUID)
  AND state IN ('pending', 'approved')`, clusterID.String()).Scan(&open); err != nil || open != 0 {
		t.Fatalf("open requests after revoking the key = %d, %v", open, err)
	}
	if _, err := store.OpenReplicaRequest(ctx, joinAttempt(t, issued.Presentation, newReplicaKeys(t))); !errors.Is(
		err, kubecluster.ErrKeyNotUsable) {
		t.Fatalf("a revoked key opened a request: %v", err)
	}
	detail, err := service.Read(ctx, owner, scope, clusterID)
	// Two keys: this one, revoked, and the one assertJoinTrust issued.
	if err != nil || len(detail.Keys) != 2 || len(detail.Requests) < 3 || len(detail.Replicas) != 1 ||
		detail.Replicas[0].DeviceID.String() != gatewayDevice || detail.Replicas[0].Name != "prod-0" ||
		detail.Replicas[0].Ordinal != 0 || detail.Cluster.Replicas() != 1 {
		t.Fatalf("Read() = %+v, %v", detail, err)
	}
	removeGatewayDevice(ctx, t, admin, gatewayDevice)
	assertRetiredGatewayKey(ctx, t, runtime, first)
	assertRemovedGatewayKeyEvent(ctx, t, admin, runtimePool, gatewayDevice)
	// A pod whose gateway is gone gets a final answer, not its Device again.
	if _, err := completions.CompleteReplicaRequest(ctx, ticket.Scope, ticket.Request.ID(),
		registrationIdentity(t, first)); !errors.Is(err, kubecluster.ErrNotWaiting) {
		t.Fatalf("completing a request whose Device is gone: %v", err)
	}
	deleted, err := service.Delete(ctx, kubecluster.Deletion{Session: owner, Scope: scope, ClusterID: clusterID,
		CorrelationID: newCorrelationID(t)})
	if err != nil || deleted.State() != kubecluster.StateDeleted {
		t.Fatalf("Delete() = %+v, %v", deleted, err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_cluster", clusterID.String(), "kubernetes_cluster.deleted")
	var groupState string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.device_group WHERE public_id = $1::UUID`,
		policyGroup.String()).Scan(&groupState); err != nil || groupState != "deleted" {
		t.Fatalf("the deleted cluster's group is %q, %v", groupState, err)
	}
}

// assertJoinKeyRefusedByEnrollment: the ordinary intake finds no Network for
// a join key, and the ordinary credential lock does not see it.
func assertJoinKeyRefusedByEnrollment(ctx context.Context, t *testing.T, admin *pgx.Conn,
	keyID enrollment.CredentialID) {
	t.Helper()
	var found int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_registration_intake_scope($1::UUID)`, keyID.String()).Scan(&found); err != nil || found != 0 {
		t.Fatalf("the ordinary intake resolved a join key: %d, %v", found, err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
    (SELECT workspace.public_id FROM mesh.workspace AS workspace WHERE workspace.id = 103),
    (SELECT network.public_id FROM mesh.network AS network WHERE network.id = 203))`); err != nil {
		t.Fatal(err)
	}
	for _, function := range []string{"lock_registration_credential", "lock_registration_credential_v2"} {
		if _, err := tx.Exec(ctx, `SAVEPOINT lock_check`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.`+function+`($1::UUID)`, keyID.String()); err == nil {
			t.Fatalf("%s returned a join key", function)
		}
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT lock_check`); err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoGatewayDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, clusterID kubecluster.ID) {
	t.Helper()
	var devices int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device AS device
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = device.kubernetes_cluster_id
WHERE cluster.public_id = $1::UUID`, clusterID.String()).Scan(&devices); err != nil || devices != 0 {
		t.Fatalf("gateway Devices before completion = %d, %v", devices, err)
	}
}

// assertGatewayWritersRefused: mesh_runtime, which may insert profiles,
// credentials and Devices for ordinary registration, can insert neither a
// gateway Device nor a credential on a gateway profile, nor one on a
// profile it cannot see. The guard fires before any other check.
func assertGatewayWritersRefused(ctx context.Context, t *testing.T, admin *pgx.Conn, clusterID kubecluster.ID) {
	t.Helper()
	var profileID int64
	if err := admin.QueryRow(ctx, `SELECT profile.id FROM mesh.enrollment_profile AS profile
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = profile.kubernetes_cluster_id
WHERE cluster.public_id = $1::UUID`, clusterID.String()).Scan(&profileID); err != nil {
		t.Fatalf("read the cluster's profile: %v", err)
	}
	for name, statement := range map[string]string{
		"a credential on the gateway profile": `INSERT INTO mesh.enrollment_credential (enrollment_profile_id)
VALUES (` + fmt.Sprint(profileID) + `)`,
		"a credential on an unknown profile": `INSERT INTO mesh.enrollment_credential (enrollment_profile_id)
VALUES (-1)`,
		"a gateway Device": `INSERT INTO mesh.device (kind) VALUES ('kubernetes_gateway')`,
	} {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`)
		if err == nil {
			_, err = tx.Exec(ctx, statement)
		}
		_ = tx.Rollback(ctx)
		if err == nil || !strings.Contains(err.Error(), "written only by its functions") {
			t.Errorf("mesh_runtime wrote %s: %v", name, err)
		}
	}
}

// assertGatewayDeviceGuards turns one Device into a gateway, with triggers
// off for that one statement, inside a transaction that is rolled back: its identity, owner and name do not
// change, it is never suspended, it is revoked; no reference guard lets a
// row name it, by ID, public ID or in an array, and a guard naming an
// unknown column refuses everything.
func assertGatewayDeviceGuards(ctx context.Context, t *testing.T, admin *pgx.Conn, clusterID kubecluster.ID) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, arguments ...any) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT guard`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, statement, arguments...)
		if err != nil {
			if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT guard`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT guard`); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	var deviceID int64
	var devicePublicID string
	if err := tx.QueryRow(ctx, `SELECT id, public_id::TEXT FROM mesh.device
WHERE workspace_id = 103 AND network_id = 203 AND state = 'active' AND NOT is_ephemeral AND deleted_at IS NULL
ORDER BY id LIMIT 1`).Scan(&deviceID, &devicePublicID); err != nil {
		t.Fatalf("pick a Device: %v", err)
	}
	if err := exec(`SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE mesh.device AS device SET kind = 'kubernetes_gateway', ownership = 'workspace',
    owner_principal_id = mesh_ops.workspace_device_principal_internal_v1(103),
    custodian_principal_id = mesh_ops.workspace_device_principal_internal_v1(103),
    hostname_locked = TRUE, suspended_reason = NULL, handover_principal_id = NULL,
    kubernetes_cluster_id = (SELECT id FROM mesh.kubernetes_cluster WHERE public_id = $2::UUID),
    kubernetes_ordinal = 63, version = device.version + 1
WHERE device.id = $1`, deviceID, clusterID.String()); err != nil {
		t.Fatalf("make a gateway Device: %v", err)
	}
	if err := exec(`SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"rename":   `UPDATE mesh.device SET hostname = hostname || 'x', version = version + 1 WHERE id = $1`,
		"suspend":  `UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin', version = version + 1 WHERE id = $1`,
		"expire":   `UPDATE mesh.device SET state = 'expired', version = version + 1 WHERE id = $1`,
		"transfer": `UPDATE mesh.device SET ownership = 'member', version = version + 1 WHERE id = $1`,
		"ordinal":  `UPDATE mesh.device SET kubernetes_ordinal = 62, version = version + 1 WHERE id = $1`,
		"kind": `UPDATE mesh.device SET kind = 'standard', kubernetes_cluster_id = NULL, kubernetes_ordinal = NULL,
    version = version + 1 WHERE id = $1`,
	} {
		if err := exec(statement, deviceID); err == nil || !strings.Contains(err.Error(), "MTL01") &&
			!strings.Contains(err.Error(), "only revoked or deleted") {
			t.Errorf("%s of a gateway Device: %v", name, err)
		}
	}
	if err := exec(`CREATE TEMP TABLE kubernetes_guard_probe (
    device_id BIGINT, device_public_id UUID, device_ids BIGINT[]) ON COMMIT DROP`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`CREATE TRIGGER kubernetes_guard_probe BEFORE INSERT ON kubernetes_guard_probe
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1(
    'device_id', 'device_public_id', 'device_ids')`); err != nil {
		t.Fatal(err)
	}
	for name, row := range map[string][]any{
		"by ID":        {deviceID, nil, nil},
		"by public ID": {nil, devicePublicID, nil},
		"in an array":  {nil, nil, []int64{-1, deviceID}},
	} {
		if err := exec(`INSERT INTO kubernetes_guard_probe VALUES ($1, $2::UUID, $3)`, row...); err == nil {
			t.Errorf("a row naming a gateway Device %s was accepted", name)
		}
	}
	if err := exec(`INSERT INTO kubernetes_guard_probe VALUES (-1, NULL, ARRAY[-2]::BIGINT[])`); err != nil {
		t.Fatalf("a row naming no gateway was refused: %v", err)
	}
	if err := exec(`CREATE TRIGGER kubernetes_guard_misspelt BEFORE INSERT ON kubernetes_guard_probe
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_gateway_reference_v1('devise_id')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO kubernetes_guard_probe VALUES (-1, NULL, NULL)`); err == nil {
		t.Fatal("a guard naming an unknown column let a row through")
	}
	if err := exec(`UPDATE mesh.device SET state = 'revoked', version = version + 1 WHERE id = $1`, deviceID); err != nil {
		t.Fatalf("revoking a gateway Device: %v", err)
	}
}

// assertGatewayReferenceCoverage: every table with a foreign key to
// mesh.device, and every Device column named by public ID or in an array,
// has the reference guard, except the listed ones.
func assertGatewayReferenceCoverage(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	exempt := map[string]string{
		"mesh.device_alias_client_version": "what its client supports, reported on every map open",
		"mesh.device_dns_label":            "the Device's own mesh name, written when it is created",
		"mesh.device_machine_key_epoch":    "a gateway has key epochs like any Device",
		"mesh.device_node_key_epoch":       "a gateway has key epochs like any Device",
		"mesh.enrollment_credential_use":   "a gateway uses its join key like any Device",
		"mesh.node_address_lease":          "a gateway has addresses like any Device",
		"mesh.pending_registration":        "registration bookkeeping",
		"mesh.kubernetes_replica_request":  "the request that created the gateway",
	}
	rows, err := admin.Query(ctx, `SELECT DISTINCT constraint_row.conrelid::REGCLASS::TEXT
FROM pg_catalog.pg_constraint AS constraint_row
WHERE constraint_row.confrelid = 'mesh.device'::REGCLASS AND constraint_row.contype = 'f'
UNION
SELECT table_schema || '.' || table_name FROM information_schema.columns
WHERE table_schema = 'mesh' AND table_name IN ('network_dns_name', 'exit_pool_serving', 'network_dns_zone')`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(tables) < 20 {
		t.Fatalf("tables referring to Devices: %d, %v", len(tables), err)
	}
	for _, table := range tables {
		if _, ok := exempt[table]; ok {
			continue
		}
		var guarded bool
		// Schema 230 guards compiled rules, group members and DNS zones with
		// their own functions.
		if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
WHERE tgrelid = $1::REGCLASS AND NOT tgisinternal
  AND tgfoid::REGPROC::TEXT IN ('mesh_ops.refuse_kubernetes_gateway_reference_v1',
      'mesh_ops.refuse_kubernetes_policy_rule_v1', 'mesh_ops.enforce_kubernetes_group_member_v1',
      'mesh_ops.refuse_kubernetes_dns_reference_v1'))`, table).Scan(&guarded); err != nil {
			t.Fatal(err)
		}
		if !guarded {
			t.Errorf("%s refers to Devices without the gateway guard", table)
		}
	}
}

// assertDatabaseChecksTheCode: the approval function itself refuses a wrong
// code (MTK09), whatever the caller checked, called as mesh_runtime.
func assertDatabaseChecksTheCode(ctx context.Context, t *testing.T, admin *pgx.Conn,
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
	_, err = tx.Exec(ctx, `SELECT mesh_ops.approve_kubernetes_replica_request_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
    $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::BIGINT,$15::UUID)`,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String(), requestID.String(),
		int64(12345), mustPublicID(t).String())
	if err == nil || !strings.Contains(err.Error(), "MTK09") {
		t.Fatalf("the database approved a wrong code: %v", err)
	}
}

func newIntegrationJoinCompletions(t *testing.T,
	runtimePool *postgresadapter.Pool) *postgresadapter.KubernetesJoinCompletionStore {
	t.Helper()
	store, err := postgresadapter.NewKubernetesJoinCompletionStore(runtimePool,
		postgresadapter.RegistrationTransactionOptions{StatementTimeout: 5 * time.Second, LockTimeout: time.Second,
			IdleTimeout: 10 * time.Second, AddressCandidateLimit: 256})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func registrationIdentity(t *testing.T, keys replicaKeys) node.RegistrationIdentity {
	t.Helper()
	identity, err := node.NewRegistrationIdentity(keys.machine, keys.node)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// assertReplicaCompletes: the approved request completes into a gateway
// Device that belongs to the Workspace, never expires, has the reserved
// name and ordinal and an address, without counting its key's use twice;
// completing again returns the same Device; other keys find nothing.
func assertReplicaCompletes(ctx context.Context, t *testing.T, admin *pgx.Conn,
	completions *postgresadapter.KubernetesJoinCompletionStore, ticket kubecluster.JoinTicket,
	keys replicaKeys) string {
	t.Helper()
	completion, err := completions.CompleteReplicaRequest(ctx, ticket.Scope, ticket.Request.ID(),
		registrationIdentity(t, keys))
	if err != nil || completion.State != kubecluster.RequestCompleted ||
		completion.Result.Hostname().String() != "prod-0" {
		t.Fatalf("CompleteReplicaRequest() = %+v, %v", completion, err)
	}
	deviceID := completion.Result.NodeID().String()
	var kind, ownership, hostname string
	var ordinal int
	var neverExpires, locked bool
	var leases, uses, used int
	if err := admin.QueryRow(ctx, `SELECT device.kind, device.ownership, device.hostname, device.kubernetes_ordinal,
    device.expires_at = mesh_ops.device_never_expires_v1(), device.hostname_locked,
    (SELECT pg_catalog.count(*) FROM mesh.node_address_lease AS lease WHERE lease.device_id = device.id),
    (SELECT pg_catalog.count(*) FROM mesh.enrollment_credential_use AS credential_use
     WHERE credential_use.device_id = device.id AND credential_use.kubernetes_replica_request_id IS NOT NULL),
    (SELECT credential.used_count FROM mesh.enrollment_credential AS credential
     WHERE credential.id = device.registered_by_credential_id)
FROM mesh.device AS device WHERE device.public_id = $1::UUID`, deviceID).Scan(&kind, &ownership, &hostname,
		&ordinal, &neverExpires, &locked, &leases, &uses, &used); err != nil {
		t.Fatalf("read the gateway Device: %v", err)
	}
	if kind != "kubernetes_gateway" || ownership != "workspace" || hostname != "prod-0" || ordinal != 0 ||
		!neverExpires || !locked || leases == 0 || uses != 1 || used != 1 {
		t.Fatalf("gateway Device = %s %s %s ordinal %d never %t locked %t leases %d uses %d used %d", kind,
			ownership, hostname, ordinal, neverExpires, locked, leases, uses, used)
	}
	again, err := completions.CompleteReplicaRequest(ctx, ticket.Scope, ticket.Request.ID(),
		registrationIdentity(t, keys))
	if err != nil || again.State != kubecluster.RequestCompleted || again.Result.NodeID() != completion.Result.NodeID() {
		t.Fatalf("completing again = %+v, %v", again, err)
	}
	if _, err := completions.CompleteReplicaRequest(ctx, ticket.Scope, ticket.Request.ID(),
		registrationIdentity(t, newReplicaKeys(t))); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("other keys completed the request: %v", err)
	}
	assertKubernetesEvent(ctx, t, admin, "device", deviceID, "kubernetes_replica.enrolled")
	return deviceID
}

// shiftReplicaRequest moves a request's times by interval, skipping
// triggers: its deadline passes without waiting.
func shiftReplicaRequest(ctx context.Context, t *testing.T, admin *pgx.Conn, requestID, interval string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.kubernetes_replica_request
SET created_at = created_at + $2::INTERVAL, updated_at = updated_at + $2::INTERVAL,
    approved_at = approved_at + $2::INTERVAL, completion_deadline = completion_deadline + $2::INTERVAL
WHERE public_id = $1::UUID`, requestID, interval); err != nil {
		t.Fatalf("shift the request: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertReplicaRequestState(ctx context.Context, t *testing.T, admin *pgx.Conn, requestID, want string) {
	t.Helper()
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.kubernetes_replica_request WHERE public_id = $1::UUID`,
		requestID).Scan(&state); err != nil || state != want {
		t.Fatalf("request state = %q, %v; want %q", state, err, want)
	}
}

// removeGatewayDevice deletes the test's gateway Device so its cluster can
// be deleted.
func removeGatewayDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, deviceID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Device deletion is not this test's subject: skip its triggers and
	// evidence, and leave only the state the cluster's deletion reads.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.device SET state = 'deleted', deleted_at = pg_catalog.now(),
    version = version + 1 WHERE public_id = $1::UUID`, deviceID); err != nil {
		t.Fatalf("delete the gateway Device: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertKubernetesEvent(ctx context.Context, t *testing.T, admin *pgx.Conn, kind, id, action string) {
	t.Helper()
	var events int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
WHERE target_kind = $1 AND target_public_id = $2::UUID AND action = $3`, kind, id, action).Scan(&events); err != nil ||
		events == 0 {
		t.Fatalf("%s event of %s %s: %d, %v", action, kind, id, events, err)
	}
}

func mustPublicID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
