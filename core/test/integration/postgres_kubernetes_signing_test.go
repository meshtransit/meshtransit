//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
)

// assertGatewayTokenAuditAndSigning qualifies schema 233 on the joined
// gateway: a refused rotation token becomes a sealed
// kubernetes_gateway.rotation_token_refused event, limited per key and
// reason; the cluster's v2 read keeps summing only the older actions; the
// signing read shows the trust, the gateway's pod and last rotation, and,
// for its administrators only, the waiting requests and the token warnings.
func assertGatewayTokenAuditAndSigning(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn,
	runtimePool *postgresadapter.Pool, service *kubecluster.Service, owner, reader accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, deviceID string) {
	t.Helper()
	store, err := postgresadapter.NewKubernetesGatewayKeyEventStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.Read(ctx, owner, scope, clusterID)
	if err != nil || before.KeyWarnings == nil || len(before.KeyWarnings.Devices) != 1 {
		t.Fatalf("Read() before = %+v, %v", before.KeyWarnings, err)
	}
	current, _ := gatewayKeyFingerprints(ctx, t, admin, deviceID)
	record := func(reason kubecluster.KeyEventReason, want kubecluster.KeyEventOutcome) {
		t.Helper()
		if outcome, err := store.Record(ctx, current, reason, 0); err != nil || outcome != want {
			t.Fatalf("Record(%s) = %v, %v; want %v", reason, outcome, err, want)
		}
	}
	record(kubecluster.KeyEventTokenMissing, kubecluster.KeyEventRecorded)
	record(kubecluster.KeyEventTokenMissing, kubecluster.KeyEventLimited)
	record(kubecluster.KeyEventTrustMissing, kubecluster.KeyEventRecorded)
	var sealed int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS event
WHERE event.target_kind = 'kubernetes_gateway_key_event' AND event.payload ->> 'device_id' = $1
  AND event.action = 'kubernetes_gateway.rotation_token_refused'`, deviceID).Scan(&sealed); err != nil || sealed != 2 {
		t.Fatalf("sealed token events = %d, %v", sealed, err)
	}
	// v1 keeps the reasons it had: older Core never writes the new ones.
	if _, err := admin.Exec(ctx, `SELECT mesh_ops.record_kubernetes_gateway_key_event_v1(
    $1::BYTEA, 'token_missing', 0, pg_catalog.uuidv7(), pg_catalog.uuidv7())`, current[:]); err == nil {
		t.Fatal("record v1 took a token reason")
	}

	// Core 232, still running during the rollout, records through v1 as the
	// runtime role: the wrapper answers it as before (here limited, as the
	// key's events above spent the window).
	transaction, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var outcome string
	err = transaction.QueryRow(ctx, `SELECT mesh_ops.record_kubernetes_gateway_key_event_v1(
    $1::BYTEA, 'session_fight', 0, pg_catalog.uuidv7(), pg_catalog.uuidv7()) ->> 'outcome'`,
		current[:]).Scan(&outcome)
	if rollbackErr := transaction.Rollback(ctx); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if err != nil || (outcome != "limited" && outcome != "recorded") {
		t.Fatalf("Core 232's record = %q, %v", outcome, err)
	}

	// The v2 read does not see them.
	after, err := service.Read(ctx, owner, scope, clusterID)
	if err != nil || after.KeyWarnings == nil || len(after.KeyWarnings.Devices) != 1 ||
		after.KeyWarnings.Devices[0] != before.KeyWarnings.Devices[0] {
		t.Fatalf("Read() after = %+v, %v; before %+v", after.KeyWarnings, err, before.KeyWarnings)
	}

	signing, err := service.ReadSigning(ctx, owner, scope, clusterID)
	if err != nil || signing.Trust == nil || signing.Trust.Version != 1 ||
		signing.Trust.Source != kubecluster.TrustFromReplicaApproval || signing.Trust.Issuer == "" ||
		len(signing.Trust.KeyThumbprints) == 0 || signing.Trust.SetAt.IsZero() {
		t.Fatalf("ReadSigning() trust = %+v, %v", signing.Trust, err)
	}
	var replica *kubecluster.ReplicaSigning
	for index := range signing.Replicas {
		if signing.Replicas[index].DeviceID.String() == deviceID {
			replica = &signing.Replicas[index]
		}
	}
	// The gateway rotated its keys since it joined, with its pod token.
	if replica == nil || replica.PodName == "" || replica.LastTokenRotation.IsZero() {
		t.Fatalf("ReadSigning() replicas = %+v", signing.Replicas)
	}
	if signing.Requests == nil || len(signing.Requests) > kubecluster.MaximumSigningRequests ||
		signing.RequestsTruncated {
		t.Fatalf("ReadSigning() requests = %+v", signing.Requests)
	}
	for _, request := range signing.Requests {
		if request.CodeVersion == 2 && (request.PodName == "" || request.Issuer == "") {
			t.Fatalf("ReadSigning() request = %+v", request)
		}
	}
	warnings := signing.TokenWarnings
	if warnings == nil || len(warnings.Devices) != 1 || warnings.Truncated ||
		warnings.Devices[0].DeviceID.String() != deviceID || warnings.Devices[0].Last24h != 2 ||
		warnings.Devices[0].LastReason != kubecluster.KeyEventTrustMissing {
		t.Fatalf("ReadSigning() token warnings = %+v", warnings)
	}

	// A reader of the Network (an auditor) sees the trust and the pods only.
	removeRole := seedEnrollmentKeyRole(ctx, t, admin, reader, 1994, "auditor")
	defer removeRole()
	read, err := service.ReadSigning(ctx, reader, scope, clusterID)
	if err != nil || read.Trust == nil || len(read.Replicas) != len(signing.Replicas) || read.Requests != nil ||
		read.TokenWarnings != nil {
		t.Fatalf("reader's ReadSigning() = %+v, %v", read, err)
	}
}
