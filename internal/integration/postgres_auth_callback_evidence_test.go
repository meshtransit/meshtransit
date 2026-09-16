//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

type integrationCallbackExpected struct {
	claim            oidcauth.ClaimCommand
	issue            oidcauth.IssueCommand
	before           [5]int64
	identityBefore   [6]int64
	issued, terminal bool
}

func integrationCallbackIdentityCounts(ctx context.Context, t *testing.T, admin *pgx.Conn) [6]int64 {
	t.Helper()
	var counts [6]int64
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.principal),
    (SELECT pg_catalog.count(*) FROM mesh.account),
    (SELECT pg_catalog.count(*) FROM mesh.identity_subject),
    (SELECT pg_catalog.count(*) FROM mesh.workspace_membership),
    (SELECT pg_catalog.count(*) FROM mesh.role_binding),
    (SELECT pg_catalog.count(*) FROM mesh.account_session)
`).Scan(
		&counts[0],
		&counts[1],
		&counts[2],
		&counts[3],
		&counts[4],
		&counts[5],
	); err != nil {
		t.Fatal(err)
	}
	return counts
}

func integrationCallbackDurableState(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	expected integrationCallbackExpected,
) {
	t.Helper()
	wantIdentity := expected.identityBefore
	want := expected.before
	for index := 1; index <= 3; index++ {
		want[index]++ // one durable claim, even when its acknowledgement was hidden
		if expected.terminal {
			want[index]++
		}
		if expected.issued {
			want[index] += 2 // Session creation and AuthTransaction success together
		}
	}
	if expected.issued {
		wantIdentity[5]++
	}
	actual := authAdmissionAuthorityCounts(ctx, t, admin)
	actualIdentity := integrationCallbackIdentityCounts(ctx, t, admin)
	if actual != want || actualIdentity != wantIdentity {
		t.Fatal("callback duplicated lifecycle/evidence or provisioned identity/membership/roles/Network revision")
	}
	var state string
	var version int64
	var erased, anonymousLogin bool
	var resultKind, resultID *string
	if err := admin.QueryRow(ctx, `SELECT state,version,
    pkce_verifier_encryption_algorithm IS NULL
      AND pkce_verifier_encryption_key_id IS NULL AND pkce_verifier_ciphertext IS NULL,
    operation_kind='login' AND principal_id IS NULL,
    consumed_result_kind,consumed_result_public_id::TEXT
 FROM mesh.auth_transaction WHERE public_id=$1::UUID`, expected.claim.Snapshot().TransactionID().String()).Scan(
		&state,
		&version,
		&erased,
		&anonymousLogin,
		&resultKind,
		&resultID,
	); err != nil {
		t.Fatal(err)
	}
	// Migration 19 forbids assigning a Principal to any login auth-row. Issuance
	// binds identity on the result Session, not on the original anonymous command.
	if !anonymousLogin {
		t.Fatal("callback changed original anonymous login operation")
	}
	switch {
	case expected.issued:
		validSuccess := state == "succeeded" && version == 3 && erased
		validResult := resultKind != nil && *resultKind == "account_session" && resultID != nil &&
			*resultID == expected.issue.IDs().SessionID().String()
		if !validSuccess || !validResult {
			t.Fatal("callback Session/result/erasure was not atomic")
		}
		assertCallbackSessionIdentity(
			ctx,
			t,
			admin,
			expected.issue,
		)
	case expected.terminal:
		validFailure := state == "failed" && version == 3 && erased
		resultAbsent := resultKind == nil && resultID == nil
		if !validFailure || !resultAbsent {
			t.Fatal("callback failure granted access or retained proof")
		}
	default:
		validUnfinished := state == "consuming" && version == 2 && !erased
		resultAbsent := resultKind == nil && resultID == nil
		if !validUnfinished || !resultAbsent {
			t.Fatal("uncertain/rejected issuance was retried or terminalized without disposition")
		}
	}
}

func assertCallbackSessionIdentity(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	command oidcauth.IssueCommand,
) {
	t.Helper()
	var activeInitial, principalMatches, subjectMatches bool
	if err := admin.QueryRow(
		ctx,
		`SELECT
    session.state='active' AND session.version=1,
    principal.public_id=$2::UUID,subject.public_id=$3::UUID
 FROM mesh.account_session AS session
 JOIN mesh.principal AS principal ON principal.deployment_id=session.deployment_id
    AND principal.id=session.principal_id
 JOIN mesh.identity_subject AS subject ON subject.deployment_id=session.deployment_id
    AND subject.id=session.identity_subject_id
    AND subject.principal_id=session.principal_id
    AND subject.identity_provider_id=session.identity_provider_id
 WHERE session.public_id=$1::UUID`,
		command.IDs().SessionID().String(),
		command.Subject().PrincipalID().String(),
		command.Subject().IdentitySubjectID().String(),
	).Scan(&activeInitial, &principalMatches, &subjectMatches); err != nil {
		t.Fatal(err)
	}
	validIdentity := activeInitial && principalMatches && subjectMatches
	if !validIdentity {
		t.Fatal("callback Session did not bind the exact resolved Principal/subject")
	}
}
