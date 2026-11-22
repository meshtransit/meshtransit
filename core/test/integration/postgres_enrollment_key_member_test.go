//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/adapter/postgres/registrationintake"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	appintake "meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// setNetwork203Membership gives the session's principal a membership of
// Network 203 in the given state, creating it when it has none.
func setNetwork203Membership(ctx context.Context, t *testing.T, admin *pgx.Conn, session accountsession.Session,
	state string) {
	t.Helper()
	principal := publicid.ID(session.PrincipalID()).String()
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `UPDATE mesh.network_membership AS membership SET state = $2
FROM mesh.principal AS principal
WHERE principal.id = membership.principal_id AND principal.public_id = $1::UUID
  AND membership.workspace_id = 103 AND membership.network_id = 203`, args: []any{principal, state}},
		{sql: `INSERT INTO mesh.network_membership (public_id, deployment_id, workspace_id, network_id,
    principal_id, workspace_membership_id, state, valid_from)
SELECT pg_catalog.uuidv7(), workspace_membership.deployment_id, 103, 203, principal.id,
    workspace_membership.id, $2, now() - INTERVAL '1 minute'
FROM mesh.principal AS principal
JOIN mesh.workspace_membership AS workspace_membership
  ON workspace_membership.workspace_id = 103 AND workspace_membership.principal_id = principal.id
WHERE principal.public_id = $1::UUID AND NOT EXISTS (
    SELECT 1 FROM mesh.network_membership AS existing
    WHERE existing.principal_id = principal.id AND existing.workspace_id = 103 AND existing.network_id = 203)`,
			args: []any{principal, state}},
	})
}

// assertEnrollmentKeyIssuerMustBeMember qualifies schema 312 (TD-API-50): a
// Workspace administrator who is not an active member of the Network cannot
// issue a key there, and a key whose issuer is no longer an active member is
// refused at use like a revoked one.
func assertEnrollmentKeyIssuerMustBeMember(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, service *enrollmentkey.Service, issuer accountsession.Session,
	scope network.Scope) {
	t.Helper()
	fixed, err := enrollment.NewDeviceLifetime(72 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := func() enrollmentkey.IssueRequest {
		return enrollmentkey.IssueRequest{Scope: scope, DeviceLifetime: fixed, CorrelationID: newCorrelationID(t)}
	}
	setNetwork203Membership(ctx, t, admin, issuer, "suspended")
	if _, err := service.Issue(ctx, issuer, request()); !errors.Is(err, enrollmentkey.ErrNotMember) {
		t.Fatalf("an administrator outside the Network issued a key: %v", err)
	}
	setNetwork203Membership(ctx, t, admin, issuer, "active")
	issued, err := service.Issue(ctx, issuer, request())
	if err != nil {
		t.Fatalf("a member issued no key: %v", err)
	}
	// The issuer's membership is suspended before the key is used.
	setNetwork203Membership(ctx, t, admin, issuer, "suspended")
	command := seedKeyRegistration(ctx, t, admin, scope, issued.Key().ID(), 0xca, "key-nonmember.example")
	if _, err := newIntegrationRegistrationService(t, runtimePool).Register(ctx, command); !errors.Is(err,
		enrollment.ErrCredentialInactive) {
		t.Fatalf("a key of a suspended member enrolled a Device: %v", err)
	}
	setNetwork203Membership(ctx, t, admin, issuer, "active")

	// Intake refuses the key before writing any intent: while the issuer's
	// Workspace membership is suspended, and once their Network membership
	// has expired.
	intake := newKeyIntakeService(t, runtimePool)
	intakeRequest := keyIntakeRequest(t, issued.Key().ID(), issued.Presentation().Token(), 0xcb)
	principal := publicid.ID(issuer.PrincipalID()).String()
	for name, change := range map[string][2]string{
		"suspended Workspace member": {
			`UPDATE mesh.workspace_membership AS membership SET state = 'suspended' FROM mesh.principal AS principal
WHERE principal.id = membership.principal_id AND principal.public_id = $1::UUID AND membership.workspace_id = 103`,
			`UPDATE mesh.workspace_membership AS membership SET state = 'active' FROM mesh.principal AS principal
WHERE principal.id = membership.principal_id AND principal.public_id = $1::UUID AND membership.workspace_id = 103`,
		},
		"expired Network membership": {
			`UPDATE mesh.network_membership AS membership SET valid_from = now() - INTERVAL '2 hours',
    expires_at = now() - INTERVAL '1 hour' FROM mesh.principal AS principal
WHERE principal.id = membership.principal_id AND principal.public_id = $1::UUID
  AND membership.workspace_id = 103 AND membership.network_id = 203`,
			`UPDATE mesh.network_membership AS membership SET expires_at = NULL FROM mesh.principal AS principal
WHERE principal.id = membership.principal_id AND principal.public_id = $1::UUID
  AND membership.workspace_id = 103 AND membership.network_id = 203`,
		},
	} {
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: change[0], args: []any{principal}}})
		_, err := intake.Prepare(ctx, intakeRequest)
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: change[1], args: []any{principal}}})
		if !errors.Is(err, appintake.ErrAuthenticationFailed) {
			t.Fatalf("%s: intake Prepare() = %v, want an invalid key", name, err)
		}
		var pending int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.pending_registration
WHERE public_id = $1::UUID`, intakeRequest.RegistrationID.String()).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("%s: %d pending intents after a refused key, %v", name, pending, err)
		}
	}
	// A member again: intake accepts the key.
	if _, err := intake.Prepare(ctx, intakeRequest); err != nil {
		t.Fatalf("intake refused the key of an active member: %v", err)
	}
	// The issuer revokes the unused key (no extra Device for the tests that
	// count them).
	if _, err := service.Revoke(ctx, issuer, scope, issued.Key().ID(), newCorrelationID(t)); err != nil {
		t.Fatalf("revoke the member's unused key: %v", err)
	}
}

// newKeyIntakeService is registration intake with the enrollment key
// service's digest key.
func newKeyIntakeService(t *testing.T, runtimePool *postgresadapter.Pool) *appintake.Service {
	t.Helper()
	keyID, err := enrollment.NewDigestKeyID("integration-enrollment-key-v1")
	if err != nil {
		t.Fatal(err)
	}
	material := filledIntegrationKey(0x61)
	digestKey, err := enrollment.NewDigestKey(keyID, material[:])
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := enrollment.NewCredentialKeyring(digestKey)
	if err != nil {
		t.Fatal(err)
	}
	transactions, err := postgresadapter.NewRegistrationIntakeTransactions(controlPoolFor(runtimePool),
		registrationintake.Options{StatementTimeout: 5 * time.Second, LockTimeout: time.Second,
			IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := appintake.NewService(
		appintake.Options{MaxAttempts: 3, RollbackTimeout: time.Second, PendingTTL: 10 * time.Minute},
		appintake.Dependencies{Transactions: transactions, PreparedIntents: transactions,
			CredentialProofs: keyring, EvidenceIDs: freshIntakeEvidenceIDs{}, Retry: integrationIntakeRetry{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type freshIntakeEvidenceIDs struct{}

func (freshIntakeEvidenceIDs) NewEvidenceIDs() (appintake.EvidenceIDs, error) {
	var ids [3]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return appintake.EvidenceIDs{}, err
		}
		ids[index] = id
	}
	return appintake.NewEvidenceIDs(ids[0], ids[1], ids[2])
}

func keyIntakeRequest(t *testing.T, keyID enrollment.CredentialID, token enrollment.CredentialToken,
	material byte) appintake.Request {
	t.Helper()
	registrationID, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	parsedRegistration, err := enrollment.ParseRegistrationID(registrationID.String())
	if err != nil {
		t.Fatal(err)
	}
	machineKey, err := node.NewMachineKey(filledIntegrationKey(material))
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey(filledIntegrationKey(material + 1))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := node.ParseHostname("key-intake.example")
	if err != nil {
		t.Fatal(err)
	}
	return appintake.Request{RegistrationID: parsedRegistration, CredentialID: keyID, Token: token,
		Identity: identity, Hostname: hostname}
}

// keepNetwork203Membership returns a function that puts the session's
// Network 203 membership back as it was (later tests rely on the fixture).
func keepNetwork203Membership(ctx context.Context, t *testing.T, admin *pgx.Conn,
	session accountsession.Session) func() {
	t.Helper()
	principal := publicid.ID(session.PrincipalID()).String()
	var original *string
	var state string
	err := admin.QueryRow(ctx, `SELECT membership.state FROM mesh.network_membership AS membership
JOIN mesh.principal AS principal ON principal.id = membership.principal_id
WHERE principal.public_id = $1::UUID AND membership.workspace_id = 103 AND membership.network_id = 203`,
		principal).Scan(&state)
	switch {
	case err == nil:
		original = &state
	case !errors.Is(err, pgx.ErrNoRows):
		t.Fatalf("read the membership: %v", err)
	}
	return func() {
		if original != nil {
			setNetwork203Membership(ctx, t, admin, session, *original)
			return
		}
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `DELETE FROM mesh.network_membership AS membership
USING mesh.principal AS principal
WHERE principal.id = membership.principal_id AND principal.public_id = $1::UUID
  AND membership.workspace_id = 103 AND membership.network_id = 203`, args: []any{principal}}})
	}
}
