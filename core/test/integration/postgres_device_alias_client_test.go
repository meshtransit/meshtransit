//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
)

func assertPostgreSQLDeviceAliasClientVersion(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, pool *postgresadapter.Pool, command registrationapp.Command) {
	t.Helper()
	store, err := postgresadapter.NewMapSessionStore(pool, postgresadapter.MapSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules, RelayDirectory: integrationRelayDirectory(t), EnableDeviceAliases: true})
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
	key := identity.NodeKey().Bytes()
	for _, version := range []uint8{1, 1, 0, 1} {
		if err := store.ObserveDeviceAliasVersion(ctx, identity, version); err != nil {
			t.Fatalf("observe compatibility: %v", err)
		}
		var count int
		var observed int
		var pinned bool
		if err := admin.QueryRow(ctx, `SELECT count(*)::INTEGER,min(claim.alias_version),bool_and(claim.session_generation=device.session_generation
   AND claim.machine_key_epoch=device.current_machine_key_epoch AND claim.node_key_epoch=device.current_node_key_epoch)
   FROM mesh.device_alias_client_version AS claim JOIN mesh.device AS device ON device.workspace_id=claim.workspace_id
   AND device.network_id=claim.network_id AND device.id=claim.device_id WHERE claim.node_public_key=$1::BYTEA`, key[:]).Scan(&count, &observed, &pinned); err != nil {
			t.Fatal(err)
		}
		if count != 1 || observed != int(version) || !pinned {
			t.Fatal("compatibility is duplicate, stale or not epoch bound")
		}
	}
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback compatibility fixture: %v", err)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id','999',TRUE),pg_catalog.set_config('mesh.network_id','888',TRUE)`); err != nil {
		t.Fatal(err)
	}
	var accepted bool
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.observe_device_alias_version_v1($1::BYTEA,$2::BYTEA,1)`, fingerprint[:], key[:]).Scan(&accepted); err != nil || !accepted {
		t.Fatalf("derive identity despite poisoned scope: %v", err)
	}
	var ws, net string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_setting('mesh.workspace_id'),pg_catalog.current_setting('mesh.network_id')`).Scan(&ws, &net); err != nil {
		t.Fatal(err)
	}
	if ws != "999" || net != "888" {
		t.Fatal("observer leaked derived scope")
	}
	foreignKey := [32]byte{99}
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.observe_device_alias_version_v1($1::BYTEA,$2::BYTEA,1)`, fingerprint[:], foreignKey[:]).Scan(&accepted); err != nil || accepted {
		t.Fatalf("foreign key compatibility admitted: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"mesh_runtime", "mesh_worker", "mesh_observer", "mesh_share_writer", "mesh_direct_map_reader"} {
		var readable, writable bool
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege($1::TEXT,'mesh.device_alias_client_version','SELECT'),
   pg_catalog.has_table_privilege($1::TEXT,'mesh.device_alias_client_version','INSERT,UPDATE,DELETE')`, role).Scan(&readable, &writable); err != nil {
			t.Fatal(err)
		}
		if readable || writable {
			t.Fatal("serving role has compatibility table access")
		}
	}
	var safe bool
	if err := admin.QueryRow(ctx, `SELECT NOT owner.rolcanlogin AND NOT owner.rolbypassrls AND NOT owner.rolsuper AND procedure.prosecdef
 FROM pg_catalog.pg_proc AS procedure JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
 JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner WHERE namespace.nspname='mesh_ops'
 AND procedure.proname='observe_device_alias_version_v1' AND owner.rolname='mesh_device_alias_observer'`).Scan(&safe); err != nil || !safe {
		t.Fatalf("unsafe compatibility owner: %v", err)
	}
}
