//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

// assertFlowlogReceiverStatus qualifies schema 270 (design §16e, C67–C71)
// through the runtime role: a report writes the logging Network's status
// and drops entries without settings, the minute's limit holds back an
// unchanged entry but not a new test result, a report from the future and
// a 65th instance are refused, the gate opens only for the version and key
// a fresh instance reported, and nothing moves the Network revision.
func assertFlowlogReceiverStatus(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, scope network.Scope,
) {
	t.Helper()
	store, err := postgresadapter.NewFlowlogReceiverStore(runtimePool, nil)
	if err != nil {
		t.Fatal(err)
	}
	gates, err := postgresadapter.NewFlowlogGateStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256([]byte("receiver noise key"))
	if gate, err := gates.ReadReceiverGate(ctx, connectionlog.ReceiverProtocolVersion, fingerprint); err != nil ||
		gate.Accepting != 0 {
		t.Fatalf("the gate before any report = %+v, %v", gate, err)
	}
	revision := connectionLogRevision(ctx, t, admin, scope)
	quiet := network.ID(mustIntegrationPublicID(t, "01890f00-0000-7000-8000-000000000204"))
	report := connectionlog.ReceiverReport{
		Instance: [16]byte{1, 2, 3}, AcceptedVersions: []int{1}, NoiseFingerprints: [][32]byte{fingerprint},
		SealingKeyIDs: []string{"meshflow-test"}, ReportedAt: time.Now().Add(-time.Second),
		Networks: []connectionlog.ReceiverNetworkStatus{
			{
				Workspace: scope.WorkspaceID(), Network: scope.NetworkID(), TestedETag: bytes.Repeat([]byte{4}, 16),
				TestResult: connectionlog.TestOK, TestedAt: time.Now().Add(-time.Minute),
				DeliveryError: connectionlog.DeliveryNone, Lost: 3,
			},
			{Workspace: scope.WorkspaceID(), Network: quiet, TestResult: connectionlog.ReceiverUnspecified,
				DeliveryError: connectionlog.ReceiverUnspecified},
			{Workspace: workspace.ID(newConnectionLogID(t)), Network: scope.NetworkID(),
				TestResult: connectionlog.ReceiverUnspecified, DeliveryError: connectionlog.ReceiverUnspecified},
		},
	}
	result, err := store.ReportStatus(ctx, report)
	if err != nil || result.Written != 1 || result.Dropped != 2 || result.Throttled != 0 {
		t.Fatalf("ReportStatus() = %+v, %v", result, err)
	}
	var tag []byte
	var testResult string
	var lost int64
	if err := admin.QueryRow(ctx, `SELECT status.tested_etag, status.test_result, status.lost_24h
FROM mesh.network_connection_log_status AS status
JOIN mesh.network_connection_log AS settings ON settings.network_id = status.network_id
WHERE settings.public_id = $1::UUID`, scope.NetworkID().String()).Scan(&tag, &testResult, &lost); err != nil ||
		!bytes.Equal(tag, report.Networks[0].TestedETag) || testResult != connectionlog.TestOK || lost != 3 {
		t.Fatalf("the written status: %x %s %d, %v", tag, testResult, lost, err)
	}
	// Within the minute, the same result waits; a new one is written.
	report.Networks = report.Networks[:1]
	report.ReportedAt = time.Now()
	if result, err := store.ReportStatus(ctx, report); err != nil || result.Throttled != 1 || result.Written != 0 {
		t.Fatalf("an unchanged entry within the minute = %+v, %v", result, err)
	}
	report.Networks[0].TestResult = connectionlog.TestAccessDenied
	report.ReportedAt = time.Now().Add(time.Millisecond)
	if result, err := store.ReportStatus(ctx, report); err != nil || result.Written != 1 {
		t.Fatalf("a new test result = %+v, %v", result, err)
	}
	// An older report never overwrites a newer one, even past the minute.
	older := report
	older.Networks = []connectionlog.ReceiverNetworkStatus{report.Networks[0]}
	older.Networks[0].TestResult = connectionlog.TestUnreachable
	older.ReportedAt = report.ReportedAt.Add(-time.Hour)
	if result, err := store.ReportStatus(ctx, older); err != nil || result.Throttled != 1 {
		t.Fatalf("an older report = %+v, %v", result, err)
	}
	future := report
	future.ReportedAt = time.Now().Add(10 * time.Minute)
	if _, err := store.ReportStatus(ctx, future); !errors.Is(err, postgresadapter.ErrFlowlogReportStaleClock) {
		t.Fatalf("a report from the future: %v", err)
	}
	if after := connectionLogRevision(ctx, t, admin, scope); after != revision {
		t.Fatalf("a report moved the Network revision %d → %d", revision, after)
	}
	assertFlowlogGate(ctx, t, gates, fingerprint)
	assertTooManyReceivers(ctx, t, admin, store, report)
}

func assertFlowlogGate(ctx context.Context, t *testing.T, gates *postgresadapter.FlowlogGateStore,
	fingerprint [32]byte,
) {
	t.Helper()
	for name, test := range map[string]struct {
		version     int
		fingerprint [32]byte
		accepting   int
	}{
		"the version and key": {connectionlog.ReceiverProtocolVersion, fingerprint, 1},
		"a version not taken": {2, fingerprint, 0},
		"a key no one holds":  {connectionlog.ReceiverProtocolVersion, sha256.Sum256([]byte("other")), 0},
	} {
		gate, err := gates.ReadReceiverGate(ctx, test.version, test.fingerprint)
		if err != nil || gate.Fresh < 1 || gate.Accepting != test.accepting || gate.Newest.IsZero() {
			t.Errorf("%s: gate = %+v, %v", name, gate, err)
		}
	}
}

// assertTooManyReceivers fills the deployment with 64 fresh instances: a
// new one is refused, a known one still reports, and once the others go
// stale a new one is taken again.
func assertTooManyReceivers(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.FlowlogReceiverStore, report connectionlog.ReceiverReport,
) {
	t.Helper()
	if _, err := admin.Exec(ctx, `INSERT INTO mesh.connection_log_receiver (instance_id, accepted_versions,
    noise_fingerprints, sealing_key_ids, reported_at, received_at)
SELECT pg_catalog.decode(pg_catalog.lpad(pg_catalog.to_hex(1000 + filler), 32, '0'), 'hex'), ARRAY[1],
    ARRAY[pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')], ARRAY[]::TEXT[], pg_catalog.now(), pg_catalog.now()
FROM pg_catalog.generate_series(1, 63) AS filler`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, `DELETE FROM mesh.connection_log_receiver
WHERE instance_id <> $1::BYTEA`, report.Instance[:]); err != nil {
			t.Error(err)
		}
	}()
	stranger := report
	stranger.Instance = [16]byte{9}
	stranger.Networks = nil
	stranger.ReportedAt = time.Now()
	if _, err := store.ReportStatus(ctx, stranger); !errors.Is(err, postgresadapter.ErrFlowlogTooManyReceivers) {
		t.Fatalf("a 65th instance: %v", err)
	}
	known := stranger
	known.Instance = report.Instance
	if _, err := store.ReportStatus(ctx, known); err != nil {
		t.Fatalf("a known instance among 64: %v", err)
	}
	// Instances that stopped reporting no longer count (review s4c3 H2).
	if _, err := admin.Exec(ctx, `UPDATE mesh.connection_log_receiver
SET received_at = pg_catalog.now() - INTERVAL '20 minutes' WHERE instance_id <> $1::BYTEA`, report.Instance[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReportStatus(ctx, stranger); err != nil {
		t.Fatalf("a new instance among stale ones: %v", err)
	}
}
