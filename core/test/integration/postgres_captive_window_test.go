//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/captivewindow"
	"meshtransit.net/core/internal/domain/network"
)

// assertPostgreSQLCaptiveWindows qualifies schema 212: a Device's captive
// portal window is recorded once by its ID, with one sealed system event
// on its Network's stream that names no portal; a Device records at most 48
// windows a day.
func assertPostgreSQLCaptiveWindows(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewCaptiveWindowStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	device := activeFixtureDevices(ctx, t, admin, 1)[0]
	newWindow := func(end captivewindow.End) captivewindow.Window {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		closed := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
		return captivewindow.Window{ID: hex.EncodeToString(id[:]), OpenedAt: closed.Add(-2 * time.Minute),
			ClosedAt: closed, End: end}
	}
	window := newWindow(captivewindow.EndTunnelBack)
	if outcome, err := store.Record(ctx, scope, device, window); err != nil || outcome != captivewindow.OutcomeAudited {
		t.Fatalf("record a window = %v, %v", outcome, err)
	}
	if outcome, err := store.Record(ctx, scope, device, window); err != nil || outcome != captivewindow.OutcomeKnown {
		t.Fatalf("record it again = %v, %v", outcome, err)
	}
	var events int
	var payload string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*), pg_catalog.max(event.payload::TEXT)
FROM mesh_audit.audit_event AS event
WHERE event.action = 'device.captive_window' AND event.payload ->> 'window_id' = $1`,
		window.ID).Scan(&events, &payload); err != nil {
		t.Fatal(err)
	}
	if events != 1 || !strings.Contains(payload, `"ended": "tunnel_back"`) || !strings.Contains(payload, `"seconds": 120`) ||
		strings.Contains(payload, "portal") {
		t.Fatalf("audit events %d, payload %s", events, payload)
	}
	for range 47 {
		if outcome, err := store.Record(ctx, scope, device, newWindow(captivewindow.EndExpired)); err != nil ||
			outcome != captivewindow.OutcomeAudited {
			t.Fatalf("record within the budget = %v, %v", outcome, err)
		}
	}
	if outcome, err := store.Record(ctx, scope, device, newWindow(captivewindow.EndClosed)); err != nil ||
		outcome != captivewindow.OutcomeLimited {
		t.Fatalf("record past the budget = %v, %v", outcome, err)
	}
}
