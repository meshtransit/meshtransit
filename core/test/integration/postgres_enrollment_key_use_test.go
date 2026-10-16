//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// assertEnrollmentKeyUse follows keys the production store issued: one
// enrolls a Device that lives exactly the fixed lifetime it chose and
// belongs to its creator; the list then shows it used with that Device,
// also when the use was a resume; revoking it leaves the Device active; an
// expired key lists as expired; a credential of another profile cannot be
// revoked as a key; and a Network holds at most 100 usable keys, all of
// which the list shows first.
func assertEnrollmentKeyUse(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	service *enrollmentkey.Service, issuer accountsession.Session, scope network.Scope) {
	t.Helper()
	fixed, err := enrollment.NewDeviceLifetime(72 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(ctx, issuer, enrollmentkey.IssueRequest{
		Scope: scope, Description: "router", DeviceLifetime: fixed, CorrelationID: newCorrelationID(t),
	})
	if err != nil {
		t.Fatalf("issue a fixed-lifetime key: %v", err)
	}
	command := seedKeyRegistration(ctx, t, admin, scope, issued.Key().ID(), 0xc9, "key-router.example")
	result, err := newIntegrationRegistrationService(t, runtimePool).Register(ctx, command)
	if err != nil {
		t.Fatalf("register with an issued key: %v", err)
	}
	var lifetime time.Duration
	var ownerID string
	if err := admin.QueryRow(ctx, `SELECT device.expires_at - device.created_at, owner.public_id::TEXT
FROM mesh.device AS device JOIN mesh.principal AS owner ON owner.id = device.owner_principal_id
WHERE device.public_id = $1::UUID`, result.NodeID().String()).Scan(&lifetime, &ownerID); err != nil {
		t.Fatalf("read the key-enrolled Device: %v", err)
	}
	if lifetime != 72*time.Hour || ownerID != publicid.ID(issuer.PrincipalID()).String() {
		t.Fatalf("Device lifetime %v owned by %s; want 72h owned by the key's creator", lifetime, ownerID)
	}
	assertListedKey(ctx, t, service, issuer, scope, issued.Key().ID(), enrollmentkey.StateUsed, result.NodeID())

	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `UPDATE mesh.enrollment_credential_use AS used
SET result = 'resumed' FROM mesh.enrollment_credential AS credential
WHERE credential.id = used.enrollment_credential_id AND credential.public_id = $1::UUID`,
		args: []any{issued.Key().ID().String()}}})
	assertListedKey(ctx, t, service, issuer, scope, issued.Key().ID(), enrollmentkey.StateUsed, result.NodeID())

	if revoked, err := service.Revoke(ctx, issuer, scope, issued.Key().ID(), newCorrelationID(t)); err != nil ||
		revoked.State() != enrollmentkey.StateRevoked {
		t.Fatalf("revoke the spent key = %+v, %v", revoked, err)
	}
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.device WHERE public_id = $1::UUID`,
		result.NodeID().String()).Scan(&state); err != nil || state != "active" {
		t.Fatalf("Device after its key was revoked: %q, %v", state, err)
	}

	short, err := service.Issue(ctx, issuer, enrollmentkey.IssueRequest{
		Scope: scope, DeviceLifetime: fixed, KeyLifetime: 5 * time.Minute, CorrelationID: newCorrelationID(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `UPDATE mesh.enrollment_credential
SET valid_from = now() - INTERVAL '1 hour', expires_at = now() - INTERVAL '30 minutes'
WHERE public_id = $1::UUID`, args: []any{short.Key().ID().String()}}})
	assertListedKey(ctx, t, service, issuer, scope, short.Key().ID(), enrollmentkey.StateExpired, node.ID{})

	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `INSERT INTO mesh.enrollment_credential (
    id, public_id, workspace_id, network_id, enrollment_profile_id, issuer_principal_id, digest_algorithm,
    digest_key_id, token_digest, token_fingerprint, issued_recovery_epoch, use_limit_kind, max_uses, used_count,
    valid_from, expires_at, state)
OVERRIDING SYSTEM VALUE SELECT 1995, '01890f00-0000-7000-8000-000000001995', 103, 203, profile.id, 11,
    'hmac-sha256-v1', 'other-profile', pg_catalog.sha256('other-profile'::BYTEA),
    pg_catalog.substr(pg_catalog.sha256('other-profile-fingerprint'::BYTEA), 1, 16), 1,
    'bounded', 1, 0, now() - INTERVAL '1 minute', now() + INTERVAL '1 hour', 'active'
FROM mesh.enrollment_profile AS profile
WHERE profile.workspace_id = 103 AND profile.network_id = 203 AND profile.name_key <> 'enrollment-keys'
ORDER BY profile.id LIMIT 1`}})
	other, _ := enrollment.ParseCredentialID("01890f00-0000-7000-8000-000000001995")
	if _, err := service.Revoke(ctx, issuer, scope, other, newCorrelationID(t)); !errors.Is(err,
		enrollmentkey.ErrNotFound) {
		t.Fatalf("revoked a credential of another profile as a key: %v", err)
	}
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{
		sql: `DELETE FROM mesh.enrollment_credential WHERE id = 1995`}})

	assertEnrollmentKeyCap(ctx, t, service, issuer, scope, fixed)
}

func assertListedKey(ctx context.Context, t *testing.T, service *enrollmentkey.Service,
	session accountsession.Session, scope network.Scope, id enrollment.CredentialID, state enrollmentkey.State,
	device node.ID) {
	t.Helper()
	keys, err := service.List(ctx, session, scope)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	for _, key := range keys {
		if key.ID() != id {
			continue
		}
		listedDevice, _, enrolled := key.Device()
		if key.State() != state || enrolled != device.IsValid() || listedDevice != device {
			t.Fatalf("listed key %s = %s with Device %s; want %s with %s", id, key.State(), listedDevice, state, device)
		}
		return
	}
	t.Fatalf("key %s is not listed", id)
}

// assertEnrollmentKeyCap fills the Network to 100 usable keys, checks the
// 101st is refused and that the list shows every usable key first, then
// revokes them.
func assertEnrollmentKeyCap(ctx context.Context, t *testing.T, service *enrollmentkey.Service,
	session accountsession.Session, scope network.Scope, lifetime enrollment.DeviceLifetime) {
	t.Helper()
	before, err := service.List(ctx, session, scope)
	if err != nil {
		t.Fatal(err)
	}
	usable := 0
	for _, key := range before {
		if key.State() == enrollmentkey.StateActive {
			usable++
		}
	}
	created := make([]enrollment.CredentialID, 0, enrollmentkey.MaximumActiveKeys)
	for range enrollmentkey.MaximumActiveKeys - usable {
		issued, err := service.Issue(ctx, session, enrollmentkey.IssueRequest{
			Scope: scope, DeviceLifetime: lifetime, CorrelationID: newCorrelationID(t),
		})
		if err != nil {
			t.Fatalf("issue key %d of %d: %v", len(created)+usable+1, enrollmentkey.MaximumActiveKeys, err)
		}
		created = append(created, issued.Key().ID())
	}
	if _, err := service.Issue(ctx, session, enrollmentkey.IssueRequest{
		Scope: scope, DeviceLifetime: lifetime, CorrelationID: newCorrelationID(t),
	}); !errors.Is(err, enrollmentkey.ErrLimitReached) {
		t.Fatalf("a 101st usable key: %v", err)
	}
	listed, err := service.List(ctx, session, scope)
	if err != nil || len(listed) < enrollmentkey.MaximumActiveKeys {
		t.Fatalf("list at the cap = %d keys, %v", len(listed), err)
	}
	for index, key := range listed[:enrollmentkey.MaximumActiveKeys] {
		if key.State() != enrollmentkey.StateActive {
			t.Fatalf("listed key %d is %s; usable keys must come first", index, key.State())
		}
	}
	for _, id := range created {
		if _, err := service.Revoke(ctx, session, scope, id, newCorrelationID(t)); err != nil {
			t.Fatalf("revoke key %s: %v", id, err)
		}
	}
}

// seedKeyRegistration stores a pending registration of a new machine that
// presents the key (fixture statements, triggers bypassed) and returns its
// registration command.
func seedKeyRegistration(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope,
	keyID enrollment.CredentialID, material byte, hostname string) registrationapp.Command {
	t.Helper()
	registrationID := enrollment.RegistrationID(newCorrelationID(t))
	machineKey, err := node.NewMachineKey(filledIntegrationKey(material))
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey(filledIntegrationKey(material + 0x30))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	name, err := node.ParseHostname(hostname)
	if err != nil {
		t.Fatal(err)
	}
	command := registrationapp.Command{
		RegistrationID: registrationID, Scope: scope, CredentialID: keyID, Identity: identity, Hostname: name,
		RecoveryEpoch: 1,
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	hash := requestHash.Bytes()
	fingerprint := identity.MachineKey().Fingerprint()
	requested := identity.NodeKey().Bytes()
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `INSERT INTO mesh.pending_registration (
    public_id, workspace_id, network_id, enrollment_profile_id, authorization_kind, enrollment_credential_id,
    request_hash, machine_key_fingerprint, requested_node_key, expires_at, state)
SELECT $1::UUID, credential.workspace_id, credential.network_id, credential.enrollment_profile_id, 'credential',
    credential.id, $3::BYTEA, $4::BYTEA, $5::BYTEA, now() + INTERVAL '10 minutes', 'pending'
FROM mesh.enrollment_credential AS credential WHERE credential.public_id = $2::UUID`,
		args: []any{registrationID.String(), keyID.String(), hash[:], fingerprint[:], requested[:]}}})
	return command
}
