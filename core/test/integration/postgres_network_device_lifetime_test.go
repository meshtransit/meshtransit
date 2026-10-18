//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/devicelifetime"
	"meshtransit.net/core/internal/domain/publicid"
)

// assertNetworkDeviceLifetime qualifies schema 179: a Network chooses how
// long Devices that sign in live, under network.read and network.update, with
// a version check, one audit record per change, and the choice mirrored for
// binaries that read only node_lifetime_seconds. scope must hold the
// browser suite's interactive profile; noSignIn has none.
func assertNetworkDeviceLifetime(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	scope, noSignIn, foreign network.Scope,
) {
	t.Helper()
	store, err := postgresadapter.NewNetworkDeviceLifetimeStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := devicelifetime.NewService(store, integrationClock{})
	if err != nil {
		t.Fatal(err)
	}
	// The browser suite's profile predates the choice and keeps its own hour.
	state, err := service.Read(ctx, session, scope)
	if err != nil || !state.Default || state.NeverExpires || state.Lifetime != time.Hour {
		t.Fatalf("initial Device lifetime = %+v, %v", state, err)
	}
	if _, err := service.Read(ctx, session, noSignIn); !errors.Is(err, devicelifetime.ErrNoInteractiveProfile) {
		t.Fatalf("Network without sign-in read error = %v, want ErrNoInteractiveProfile", err)
	}
	if _, err := service.Read(ctx, session, foreign); !errors.Is(err, devicelifetime.ErrForbidden) {
		t.Fatalf("foreign Network read error = %v, want ErrForbidden", err)
	}
	update := func(version int64, lifetime time.Duration, never bool) (devicelifetime.Result, error) {
		correlation, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		return service.Update(ctx, devicelifetime.Command{Session: session, Scope: scope, ExpectedVersion: version,
			Lifetime: lifetime, NeverExpires: never, CorrelationID: correlation})
	}
	if _, err := update(state.Version+5, 7*24*time.Hour, false); !errors.Is(err, devicelifetime.ErrVersionConflict) {
		t.Fatalf("stale version error = %v, want ErrVersionConflict", err)
	}
	week, err := update(state.Version, 7*24*time.Hour, false)
	if err != nil || !week.Changed || week.State.Default || week.State.Lifetime != 7*24*time.Hour ||
		week.State.Version != state.Version+1 {
		t.Fatalf("set 7 days = %+v, %v", week, err)
	}
	assertStoredDeviceLifetime(ctx, t, admin, scope, 604800, sql.NullInt64{Int64: 604800, Valid: true}, false)
	again, err := update(week.State.Version, 7*24*time.Hour, false)
	if err != nil || again.Changed || again.State.Version != week.State.Version {
		t.Fatalf("unchanged 7 days = %+v, %v", again, err)
	}
	never, err := update(week.State.Version, 0, true)
	if err != nil || !never.Changed || !never.State.NeverExpires || never.State.Lifetime != 0 {
		t.Fatalf("set never = %+v, %v", never, err)
	}
	// Older binaries read only node_lifetime_seconds: never becomes 180 days.
	assertStoredDeviceLifetime(ctx, t, admin, scope, 15552000, sql.NullInt64{}, true)
	readBack, err := service.Read(ctx, session, scope)
	if err != nil || readBack != never.State {
		t.Fatalf("read back = %+v, %v; want %+v", readBack, err, never.State)
	}
	// Leave the profile as the browser suite made it: one hour.
	restored, err := update(never.State.Version, time.Hour, false)
	if err != nil || !restored.Changed || restored.State.Lifetime != time.Hour {
		t.Fatalf("restore one hour = %+v, %v", restored, err)
	}
	assertStoredDeviceLifetime(ctx, t, admin, scope, 3600, sql.NullInt64{Int64: 3600, Valid: true}, false)
	var events int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
WHERE action = 'network.device_lifetime.updated' AND target_public_id = $1::UUID`,
		scope.NetworkID().String()).Scan(&events); err != nil || events != 3 {
		t.Fatalf("Device lifetime audit events = %d, %v; want 3", events, err)
	}
	// The runtime role cannot change the profile behind the function.
	assertRuntimeCannotSetDeviceLifetime(ctx, t, admin)
}

func assertStoredDeviceLifetime(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope,
	wantLegacy int64, wantChosen sql.NullInt64, wantNever bool) {
	t.Helper()
	var legacy int64
	var chosen sql.NullInt64
	var never bool
	if err := admin.QueryRow(ctx, `SELECT profile.node_lifetime_seconds, profile.device_lifetime_seconds,
    profile.device_never_expires
FROM mesh.enrollment_profile AS profile
JOIN mesh.network AS network ON network.id = profile.network_id
WHERE network.public_id = $1::UUID AND profile.interactive_authorization_enabled
  AND profile.state = 'active' AND profile.deleted_at IS NULL`, scope.NetworkID().String()).Scan(
		&legacy, &chosen, &never); err != nil {
		t.Fatal(err)
	}
	if legacy != wantLegacy || chosen != wantChosen || never != wantNever {
		t.Fatalf("stored lifetime = %d/%+v/%v, want %d/%+v/%v", legacy, chosen, never, wantLegacy, wantChosen, wantNever)
	}
}

func assertRuntimeCannotSetDeviceLifetime(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	_, err = transaction.Exec(ctx, `UPDATE mesh.enrollment_profile SET device_never_expires = TRUE`)
	if err == nil {
		t.Fatal("runtime role changed device_never_expires directly")
	}
}
