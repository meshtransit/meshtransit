//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// assertGatewayRatchetSuspension checks schema 253 against the gateway
// Device assertGatewayTokenRatchet left ratcheted, its timestamp at 6,000:
// an approver's suspension lets sessions without a token through until it
// ends, a token proven meanwhile or a resume ends it, older Core holds the
// ratchet throughout, and each change is an audited authority change.
func assertGatewayRatchetSuspension(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, keys replicaKeys, deviceID string, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID,
) {
	t.Helper()
	store, err := postgresadapter.NewMTCPTimestampStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	if granted, err := store.RatchetSuspensionsGranted(ctx); err != nil || !granted {
		t.Fatalf("RatchetSuspensionsGranted() = %t, %v", granted, err)
	}
	device, err := node.ParseID(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	machine := keys.machine.Fingerprint()
	nodeKey := keys.node.Bytes()
	change := func(duration time.Duration, reason string) (kubecluster.RatchetChangeResult, error) {
		return service.ChangeTokenRatchet(ctx, kubecluster.RatchetChange{Session: owner, Scope: scope,
			ClusterID: clusterID, DeviceID: device, Duration: duration, Reason: reason, ChangeRef: "INC-253",
			CorrelationID: newCorrelationID(t)})
	}
	commit := func(timestamp int64, proven bool, mode kubecluster.GatewayTokenMode,
		want kubecluster.GatewayTimestampResult) postgresadapter.GatewayTimestampCommit {
		t.Helper()
		got, err := store.CommitGatewayTimestampV3(ctx, machine, nodeKey[:], timestamp, proven, mode)
		if err != nil || got.Result != want || !got.Ratcheted {
			t.Fatalf("CommitGatewayTimestampV3(%d, %t, %s) = %+v, %v; want %s", timestamp, proven, mode, got, err,
				want)
		}
		return got
	}
	suspendedUntil := func() time.Time {
		t.Helper()
		until, err := store.ReadRatchetSuspension(ctx, machine, nodeKey[:])
		if err != nil {
			t.Fatal(err)
		}
		return until
	}
	latestChange := func(action string) string {
		t.Helper()
		var id string
		if err := admin.QueryRow(ctx, `SELECT public_id::TEXT FROM mesh_ops.kubernetes_gateway_ratchet_change
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID) AND action = $2
ORDER BY id DESC LIMIT 1`, deviceID, action).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	// Never suspended: v3 holds the ratchet as v2 does, and v4 reads no end.
	if check, err := store.AcceptTimestampV4(ctx, machine, nodeKey[:], 8_500); err != nil || !check.TokenRatcheted ||
		!check.SuspendedUntil.IsZero() {
		t.Fatalf("AcceptTimestampV4() before a suspension = %+v, %v", check, err)
	}
	commit(8_500, false, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampTokenRequired)
	commit(8_500, false, kubecluster.GatewayTokenRequired, kubecluster.GatewayTimestampTokenRequired)
	if got := commit(8_500, true, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampCommitted); !got.
		SuspendedUntil.IsZero() {
		t.Fatalf("a proven session carried a deadline: %+v", got)
	}

	// Suspended: the handshake reads the end, a session without a token
	// commits under ratchet with it as its deadline; required still refuses,
	// observe goes on without one.
	suspended, err := change(10*time.Minute, "meshgw downgraded")
	if err != nil || !suspended.Changed || time.Until(suspended.SuspendedUntil) < 9*time.Minute ||
		time.Until(suspended.SuspendedUntil) > 11*time.Minute {
		t.Fatalf("suspend = %+v, %v", suspended, err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_gateway_ratchet_change", latestChange("suspended"),
		"kubernetes_gateway.token_ratchet_suspended")
	check, err := store.AcceptTimestampV4(ctx, machine, nodeKey[:], 9_000)
	if err != nil || !check.Accepted || !check.TokenRatcheted || !check.SuspendedUntil.Equal(suspended.SuspendedUntil) {
		t.Fatalf("AcceptTimestampV4() = %+v, %v", check, err)
	}
	if got := commit(9_000, false, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampCommitted); !got.
		SuspendedUntil.Equal(suspended.SuspendedUntil) {
		t.Fatalf("a session without a token carries %v, want %v", got.SuspendedUntil, suspended.SuspendedUntil)
	}
	commit(9_001, false, kubecluster.GatewayTokenRequired, kubecluster.GatewayTimestampTokenRequired)
	if got := commit(9_001, false, kubecluster.GatewayTokenObserve, kubecluster.GatewayTimestampCommitted); !got.
		SuspendedUntil.IsZero() {
		t.Fatalf("observe carried a deadline: %+v", got)
	}
	if !suspendedUntil().Equal(suspended.SuspendedUntil) {
		t.Fatal("the session read another end")
	}
	replica, err := service.ReadReplica(ctx, owner, scope, clusterID, device)
	if err != nil || !replica.RatchetSuspendedUntil.Equal(suspended.SuspendedUntil) {
		t.Fatalf("ReadReplica() = %+v, %v", replica, err)
	}
	page, err := service.ListReplicas(ctx, kubecluster.PageQuery{Session: owner, Scope: scope, ClusterID: clusterID,
		Limit: 10})
	if err != nil || !page.CanChangeRatchet || len(page.Replicas) == 0 {
		t.Fatalf("ListReplicas() = %+v, %v", page, err)
	}
	// Older Core (v2) ignores the suspension: closed.
	var result string
	if err := runtime.QueryRow(ctx, `SELECT result FROM mesh_ops.commit_mtcp_gateway_timestamp_v2($1, $2, 9002,
FALSE, 'ratchet')`, machine[:], nodeKey[:]).Scan(&result); err != nil || result != "token_required" {
		t.Fatalf("v2 while suspended = %s, %v", result, err)
	}

	// A token proven meanwhile ends the suspension at once.
	if got := commit(9_100, true, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampCommitted); !got.
		SuspendedUntil.IsZero() || !suspendedUntil().IsZero() {
		t.Fatalf("a proven token left the suspension: %+v, %v", got, suspendedUntil())
	}
	commit(9_101, false, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampTokenRequired)

	// A resume ends it; with nothing suspended it changes nothing.
	if _, err := change(time.Hour, "suspend to resume"); err != nil {
		t.Fatal(err)
	}
	resumed, err := change(0, "meshgw fixed")
	if err != nil || !resumed.Changed || !resumed.SuspendedUntil.IsZero() || !suspendedUntil().IsZero() {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_gateway_ratchet_change", latestChange("resumed"),
		"kubernetes_gateway.token_ratchet_resumed")
	if again, err := change(0, "nothing to resume"); err != nil || again.Changed {
		t.Fatalf("resume again = %+v, %v", again, err)
	}
	commit(9_200, false, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampTokenRequired)

	// Past its end the ratchet holds again by the database's clock.
	if _, err := change(5*time.Minute, "expires"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_token_proof
SET ratchet_suspended_at = pg_catalog.clock_timestamp() - INTERVAL '10 minutes',
    ratchet_suspended_until = pg_catalog.clock_timestamp() - INTERVAL '1 second'
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, deviceID); err != nil {
		t.Fatal(err)
	}
	if check, err := store.AcceptTimestampV4(ctx, machine, nodeKey[:], 9_300); err != nil ||
		!check.SuspendedUntil.IsZero() {
		t.Fatalf("an ended suspension at the handshake = %+v, %v", check, err)
	}
	commit(9_300, false, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTimestampTokenRequired)
	if replica, err := service.ReadReplica(ctx, owner, scope, clusterID, device); err != nil ||
		!replica.RatchetSuspendedUntil.IsZero() {
		t.Fatalf("an ended suspension read = %+v, %v", replica, err)
	}

	// Bounds the database keeps whatever the API sends.
	var pgError *pgconn.PgError
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_token_proof
SET ratchet_suspended_at = pg_catalog.clock_timestamp(),
    ratchet_suspended_until = pg_catalog.clock_timestamp() + INTERVAL '25 hours'
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, deviceID); !errors.As(err, &pgError) ||
		pgError.Code != "23514" {
		t.Fatalf("a suspension over a day: %v", err)
	}
	if _, err := runtime.Exec(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.kubernetes_gateway_ratchet_change`); !errors.As(
		err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("the runtime role read the change table: %v", err)
	}

	// Ten changes a person an hour: four so far.
	for count := 5; count <= 10; count++ {
		if _, err := change(5*time.Minute, "count"); err != nil {
			t.Fatalf("change %d: %v", count, err)
		}
	}
	if _, err := change(5*time.Minute, "one too many"); !errors.Is(err, kubecluster.ErrRatchetRateLimited) {
		t.Fatalf("the eleventh change: %v", err)
	}
	// A resume closes the door: never refused, whatever the count.
	if resumed, err := change(0, "close it"); err != nil || !resumed.Changed || !suspendedUntil().IsZero() {
		t.Fatalf("a resume past the limit = %+v, %v", resumed, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_ratchet_change
SET recorded_at = recorded_at - INTERVAL '2 hours'`); err != nil {
		t.Fatal(err)
	}
	// A join with a pod token ends a suspension, as a proven session does.
	if _, err := change(time.Hour, "before a join"); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.RatchetGatewayToken(ctx, machine, nodeKey[:]); err != nil || !ok || !suspendedUntil().IsZero() {
		t.Fatalf("a join left the suspension: %t, %v, %v", ok, err, suspendedUntil())
	}
	// Leave the Device ratcheted and unsuspended, its changes forgotten, for
	// the checks that follow.
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_token_proof
SET ratchet_suspended_at = NULL, ratchet_suspended_until = NULL
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.kubernetes_gateway_ratchet_change
SET recorded_at = recorded_at - INTERVAL '2 hours'`); err != nil {
		t.Fatal(err)
	}
}

// assertGatewayNotRatchetedYet: a Device that never proved a pod token has
// nothing to suspend (MTK43), and an unknown replica is not found.
func assertGatewayNotRatchetedYet(ctx context.Context, t *testing.T, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID, deviceID string) {
	t.Helper()
	device, err := node.ParseID(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	change := kubecluster.RatchetChange{Session: owner, Scope: scope, ClusterID: clusterID, DeviceID: device,
		Duration: time.Hour, Reason: "too early", ChangeRef: "INC-253", CorrelationID: newCorrelationID(t)}
	if _, err := service.ChangeTokenRatchet(ctx, change); !errors.Is(err, kubecluster.ErrNotRatcheted) {
		t.Fatalf("suspending a Device never ratcheted: %v", err)
	}
	change.DeviceID, change.CorrelationID = node.ID(mustPublicID(t)), newCorrelationID(t)
	if _, err := service.ChangeTokenRatchet(ctx, change); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("suspending an unknown replica: %v", err)
	}
}
