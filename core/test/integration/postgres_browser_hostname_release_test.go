//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// browserHostnameRelease signs in fresh Devices for one person and logs
// them out, to qualify when a revoked Device gives up its hostname.
type browserHostnameRelease struct {
	ctx        context.Context
	t          *testing.T
	admin      *pgx.Conn
	intents    *postgresadapter.BrowserIntentStore
	approvals  *postgresadapter.BrowserApprovalStore
	completion *postgresadapter.BrowserCompletionStore
	logout     *control.DeviceLogoutService
	deployment deployment.ID
	epoch      int64
	session    accountsession.Digest
	network    network.ID
}

func (release browserHostnameRelease) register(seed byte, hostname node.Hostname) (registration.Result, node.RegistrationIdentity) {
	release.t.Helper()
	result, identity, err := release.tryRegister(seed, hostname)
	if err != nil || result.Disposition() != registration.DispositionCreated {
		release.t.Fatalf("new Device = %+v/%v", result, err)
	}
	return result, identity
}

// tryRegister signs in a fresh Device and returns what completing it gave.
func (release browserHostnameRelease) tryRegister(seed byte, hostname node.Hostname) (
	registration.Result, node.RegistrationIdentity, error) {
	release.t.Helper()
	machineKey, err := node.NewMachineKey([32]byte{0: seed, 1: 0xa1})
	if err != nil {
		release.t.Fatal(err)
	}
	nodeKey, err := node.NewKey([32]byte{0: seed, 1: 0xb2})
	if err != nil {
		release.t.Fatal(err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		release.t.Fatal(err)
	}
	id, err := publicid.New()
	if err != nil {
		release.t.Fatal(err)
	}
	intentID, err := enrollment.ParseBrowserIntentID(id.String())
	if err != nil {
		release.t.Fatal(err)
	}
	nonce, err := enrollment.NewBrowserIntentNonce()
	if err != nil {
		release.t.Fatal(err)
	}
	token, err := release.intents.Issue(release.ctx, release.deployment, release.epoch, identity,
		hostname, intentID, nonce, time.Now().Add(5*time.Minute))
	if err != nil {
		release.t.Fatal(err)
	}
	if approved, err := release.approvals.Approve(release.ctx, release.session, token.Encoded(), release.network); err != nil || !approved {
		release.t.Fatalf("approval = %v: %v", approved, err)
	}
	result, found, err := release.completion.Complete(release.ctx, identity, hostname, token.Encoded())
	if err == nil && !found {
		release.t.Fatal("an approved sign-in completed nothing")
	}
	return result, identity, err
}

func (release browserHostnameRelease) logOut(identity node.RegistrationIdentity) {
	release.t.Helper()
	machine, err := control.NewAuthenticatedMachine(identity.MachineKey())
	if err != nil {
		release.t.Fatal(err)
	}
	if _, err := release.logout.Logout(release.ctx, machine, identity.NodeKey()); err != nil {
		release.t.Fatalf("logout: %v", err)
	}
}

// hostnameKey reads a Device's hostname key and state.
func (release browserHostnameRelease) hostnameKey(device node.ID) (string, string) {
	release.t.Helper()
	var key, state string
	if err := release.admin.QueryRow(release.ctx, `SELECT hostname_key, state FROM mesh.device
WHERE public_id=$1::UUID`, device.String()).Scan(&key, &state); err != nil {
		release.t.Fatal(err)
	}
	return key, state
}

// changeRevokedDevice applies audited fixture statements to a revoked
// Device of the fixture Network; together they advance its version once.
func (release browserHostnameRelease) changeRevokedDevice(device node.ID, suffix string, statements ...string) {
	release.t.Helper()
	var version, revision int64
	if err := release.admin.QueryRow(release.ctx, `SELECT version FROM mesh.device WHERE public_id=$1::UUID`,
		device.String()).Scan(&version); err != nil {
		release.t.Fatal(err)
	}
	if err := release.admin.QueryRow(release.ctx, `SELECT network_revision FROM mesh_ops.network_revision
WHERE workspace_id=103 AND network_id=203`).Scan(&revision); err != nil {
		release.t.Fatal(err)
	}
	commitAuditedAuthorityFixture(release.ctx, release.t, release.admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-00000000" + suffix,
		eventPublicID:  "01890f02-0000-7000-8000-00000000" + suffix,
		outboxPublicID: "01890f03-0000-7000-8000-00000000" + suffix,
		streamID:       203, aggregateKind: "device", aggregatePublicID: device.String(),
		aggregateVersion: version + 1, networkRevision: revision + 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "browser.hostname.release.fixture", permission: "system.bootstrap",
		outboxEventClass: "browser.hostname.release.fixture",
	}, func(tx pgx.Tx) {
		for _, statement := range statements {
			if _, err := tx.Exec(release.ctx, statement, device.String()); err != nil {
				release.t.Fatal(err)
			}
		}
		if _, err := tx.Exec(release.ctx, `SELECT * FROM mesh_ops.set_network_scope(
'01890f00-0000-7000-8000-000000000103'::UUID,'01890f00-0000-7000-8000-000000000203'::UUID)`); err != nil {
			release.t.Fatal(err)
		}
		if _, err := tx.Exec(release.ctx, `SELECT * FROM mesh_ops.advance_network_inventory_revision()`); err != nil {
			release.t.Fatal(err)
		}
	})
}

// assertPostgreSQLBrowserHostnameRelease qualifies H3: a revoked Device
// gives up its hostname at once to its own owner, to anyone else a day
// after its revocation, and keeps its row and state either way.
func assertPostgreSQLBrowserHostnameRelease(
	ctx context.Context, t *testing.T, admin *pgx.Conn, runtime *postgresadapter.Pool,
	intents *postgresadapter.BrowserIntentStore, approvals *postgresadapter.BrowserApprovalStore,
	completion *postgresadapter.BrowserCompletionStore,
	deploymentID deployment.ID, epoch int64, session accountsession.Digest, networkID network.ID,
) {
	t.Helper()
	logoutStore, err := postgresadapter.NewDeviceLogoutStore(runtime, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	logout, err := control.NewDeviceLogoutService(logoutStore)
	if err != nil {
		t.Fatal(err)
	}
	release := browserHostnameRelease{ctx: ctx, t: t, admin: admin, intents: intents, approvals: approvals,
		completion: completion, logout: logout, deployment: deploymentID, epoch: epoch, session: session,
		network: networkID}
	hostname, err := node.ParseHostname("release-check")
	if err != nil {
		t.Fatal(err)
	}

	// Signing in again after logging out keeps the name.
	first, firstIdentity := release.register(0x51, hostname)
	if first.Hostname() != hostname {
		t.Fatalf("first Device got %s", first.Hostname())
	}
	release.logOut(firstIdentity)
	second, secondIdentity := release.register(0x52, hostname)
	if second.Hostname() != hostname {
		t.Fatalf("the same owner did not get the name back at once: %s", second.Hostname())
	}
	if key, state := release.hostnameKey(first.NodeID()); key != "released:"+first.NodeID().String() || state != "revoked" {
		t.Fatalf("released Device has hostname key %q, state %q", key, state)
	}

	// Another owner waits for the address hold to end.
	release.logOut(secondIdentity)
	release.changeRevokedDevice(second.NodeID(), "1701", `UPDATE mesh.device SET owner_principal_id=(
    SELECT principal.id FROM mesh.principal AS principal
    WHERE principal.id <> (SELECT owner_principal_id FROM mesh.device WHERE public_id=$1::UUID)
    ORDER BY principal.id LIMIT 1),
    version=version+1, updated_at=pg_catalog.clock_timestamp()
WHERE public_id=$1::UUID`)
	third, _ := release.register(0x53, hostname)
	if third.Hostname() == hostname {
		t.Fatal("another owner took the name of a Device revoked a moment ago")
	}
	if key, _ := release.hostnameKey(second.NodeID()); key != hostname.String() {
		t.Fatalf("the name was released too early: %q", key)
	}
	release.changeRevokedDevice(second.NodeID(), "1702", `UPDATE mesh.device_machine_key_epoch AS machine
SET valid_from=machine.valid_from-INTERVAL '2 days', valid_until=machine.valid_until-INTERVAL '2 days',
    version=machine.version+1, updated_at=pg_catalog.clock_timestamp()
FROM mesh.device AS device
WHERE device.public_id=$1::UUID AND machine.device_id=device.id
  AND machine.epoch=device.current_machine_key_epoch`, `UPDATE mesh.device SET version=version+1,
updated_at=pg_catalog.clock_timestamp() WHERE public_id=$1::UUID`)
	fourth, _ := release.register(0x54, hostname)
	if fourth.Hostname() != hostname {
		t.Fatalf("a day after the revocation another owner got %s", fourth.Hostname())
	}
	if key, state := release.hostnameKey(second.NodeID()); key != "released:"+second.NodeID().String() || state != "revoked" {
		t.Fatalf("released Device has hostname key %q, state %q", key, state)
	}
	assertPostgreSQLNewDeviceLimit(release, fourth.NodeID())
}

// assertPostgreSQLNewDeviceLimit signs this person in on new Devices up to
// registration.NewDeviceLimit within the window, revoked ones included, and
// checks that the next one is refused without writing anything.
func assertPostgreSQLNewDeviceLimit(release browserHostnameRelease, own node.ID) {
	release.t.Helper()
	recent := func() int {
		release.t.Helper()
		var count int
		if err := release.admin.QueryRow(release.ctx, `SELECT pg_catalog.count(*) FROM mesh.device AS device
WHERE device.registered_by_principal_id=(SELECT owner_principal_id FROM mesh.device WHERE public_id=$1::UUID)
  AND device.workspace_id=103 AND device.network_id=203 AND device.registered_by_kind='principal'
  AND device.created_at > pg_catalog.now() - INTERVAL '24 hours'`, own.String()).Scan(&count); err != nil {
			release.t.Fatal(err)
		}
		return count
	}
	count := recent()
	if count >= registration.NewDeviceLimit {
		release.t.Fatalf("%d recent Devices before the limit check", count)
	}
	// Logged out as they go: revoked Devices still count, and the fixture
	// Network's later map checks see no extra peers.
	for seed := byte(0x60); count < registration.NewDeviceLimit; seed++ {
		hostname, err := node.ParseHostname(fmt.Sprintf("limit-check-%d", seed))
		if err != nil {
			release.t.Fatal(err)
		}
		_, identity := release.register(seed, hostname)
		release.logOut(identity)
		count++
	}
	hostname, err := node.ParseHostname("limit-check-over")
	if err != nil {
		release.t.Fatal(err)
	}
	if _, _, err := release.tryRegister(0x9f, hostname); !errors.Is(err, registration.ErrNewDeviceLimit) {
		release.t.Fatalf("a new Device over the limit: %v", err)
	}
	if got := recent(); got != registration.NewDeviceLimit {
		release.t.Fatalf("%d recent Devices after the refusal, want %d", got, registration.NewDeviceLimit)
	}
}
