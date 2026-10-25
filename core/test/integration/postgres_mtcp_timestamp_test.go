//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
)

// assertPostgreSQLMTCPTimestamp qualifies schema 137: a machine key bound
// to an active Device accepts only strictly increasing ClientHello
// timestamps, shared by every replica; unbound keys are left to the
// per-replica cache.
func assertPostgreSQLMTCPTimestamp(ctx context.Context, t *testing.T, pool *postgresadapter.Pool,
	command registrationapp.Command) {
	t.Helper()
	store, err := postgresadapter.NewMTCPTimestampStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := control.NewAuthenticatedMachine(command.Identity.MachineKey())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := machine.BindNodeKey(command.Identity.NodeKey())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := identity.MachineFingerprint()
	nodeKey := identity.NodeKey().Bytes()
	now := time.Now().UnixMilli()
	for _, step := range []struct {
		name      string
		nodeKey   []byte
		timestamp int64
		want      bool
	}{
		{"first", nodeKey[:], now, true},
		{"replay", nodeKey[:], now, false},
		{"older", nodeKey[:], now - 1, false},
		{"newer", nodeKey[:], now + 1, true},
		{"unbound node key", make([]byte, 32), now - 5, true},
		{"no node key", nil, now - 5, true},
	} {
		check, err := store.AcceptTimestamp(ctx, fingerprint, step.nodeKey, step.timestamp)
		if err != nil || check.Accepted != step.want || check.Gateway || check.MachineState != "current" {
			t.Fatalf("%s: %+v, %v; want accepted %t", step.name, check, err, step.want)
		}
	}
}
