//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
)

// assertKubernetesAccessSettings qualifies schema 262 (K2 §29.1): a
// cluster's access contact reads as none until set, a change advances the
// Network revision and the map reads it, the same contact writes nothing,
// and a stale version is refused. It leaves the contact as it found it.
func assertKubernetesAccessSettings(ctx context.Context, t *testing.T, admin *pgx.Conn, service *kubecluster.Service,
	owner accountsession.Session, scope network.Scope, clusterID kubecluster.ID) {
	t.Helper()
	read, err := service.ReadAccessSettings(ctx, owner, scope, clusterID)
	if err != nil || read.Version != 0 || read.AccessContact != "" {
		t.Fatalf("ReadAccessSettings() = %+v, %v", read, err)
	}
	revision := func() int64 {
		t.Helper()
		var value int64
		if err := admin.QueryRow(ctx, `SELECT revision.network_revision FROM mesh_ops.network_revision AS revision
JOIN mesh.network AS network ON network.id = revision.network_id WHERE network.public_id = $1::UUID`,
			scope.NetworkID().String()).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	replace := func(expected int64, contact string) (kubecluster.AccessSettingsResult, error) {
		return service.ReplaceAccessSettings(ctx, kubecluster.AccessSettingsReplacement{Session: owner, Scope: scope,
			ClusterID: clusterID, ExpectedVersion: expected, AccessContact: contact,
			CorrelationID: newCorrelationID(t)})
	}
	before := revision()
	set, err := replace(0, "#k8s-access on Slack")
	if err != nil || !set.Changed || set.Settings.Version != 1 || set.Settings.AccessContact != "#k8s-access on Slack" ||
		revision() != before+1 {
		t.Fatalf("set = %+v, %v (revision %d after %d)", set, err, revision(), before)
	}
	if same, err := replace(1, "#k8s-access on Slack"); err != nil || same.Changed || revision() != before+1 {
		t.Fatalf("the same contact = %+v, %v", same, err)
	}
	if _, err := replace(0, "#other"); !errors.Is(err, kubecluster.ErrConflict) {
		t.Fatalf("a stale version: %v", err)
	}
	// The version is checked before the no-op: a stale request with the
	// same contact is still stale.
	if _, err := replace(0, "#k8s-access on Slack"); !errors.Is(err, kubecluster.ErrConflict) {
		t.Fatalf("a stale version with the same contact: %v", err)
	}
	// The database refuses what Go refuses (review d4b L1).
	for contact, want := range map[string]bool{
		"#k8s-access":            true,
		"":                       true,
		"line" + "\n" + "break":  false,
		"rtl\u202eoverride":      false,
		"c1\u0085control":        false,
		"zero\u200bwidth":        false,
		"\u00a0leading":          false,
		"trailing\u3000":         false,
		strings.Repeat("a", 257): false,
	} {
		var valid bool
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.kubernetes_access_contact_is_valid_v1($1)`, contact).Scan(
			&valid); err != nil || valid != want {
			t.Errorf("contact %q: valid %t, %v", contact, valid, err)
		}
	}
	var events int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
WHERE action = 'kubernetes_cluster.access_settings_replaced' AND target_public_id = $1::UUID`,
		clusterID.String()).Scan(&events); err != nil || events != 1 {
		t.Fatalf("access settings events = %d, %v", events, err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', network.workspace_id::TEXT, TRUE),
    pg_catalog.set_config('mesh.network_id', network.id::TEXT, TRUE)
FROM mesh.network AS network WHERE network.public_id = $1::UUID`, scope.NetworkID().String()); err != nil {
		t.Fatal(err)
	}
	var name, contact string
	err = tx.QueryRow(ctx, `SELECT cluster_name, access_contact FROM mesh_ops.load_map_network_kubernetes_contacts_v1()`).Scan(
		&name, &contact)
	_ = tx.Rollback(ctx)
	if err != nil || name != "prod" || contact != "#k8s-access on Slack" {
		t.Fatalf("map contacts = %s %s, %v", name, contact, err)
	}
	if cleared, err := replace(1, ""); err != nil || !cleared.Changed || cleared.Settings.AccessContact != "" {
		t.Fatalf("cleared = %+v, %v", cleared, err)
	}
}
