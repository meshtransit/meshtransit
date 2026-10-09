//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	adapteroidc "meshtransit.net/core/internal/adapter/oidc"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/publicid"
)

func assertPostgreSQLSessionIssuance(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, pool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewAuthTransactionStore(pool, postgresadapter.AuthTransactionOptions{StatementTimeout: 10 * time.Second, LockTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	subjects, err := oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "integration-subject-active-v1", 0x51), integrationSubjectKey(t, "integration-subject-previous-v1", 0x52))
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := func(name string, fill byte) accountsession.DigestKey {
		id, keyErr := accountsession.NewDigestKeyID(name)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		key, keyErr := accountsession.NewDigestKey(id, integrationFilledBytes(fill, 32))
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		return key
	}
	sessions, err := accountsession.NewKeyring(sessionKey("integration-session-active-v1", 0x61), sessionKey("integration-session-previous-v1", 0x60))
	if err != nil {
		t.Fatal(err)
	}
	sidID, err := oidcauth.NewDigestKeyID("integration-provider-session-v1")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := oidcauth.NewProviderSessionKey(sidID, integrationFilledBytes(0x62, 32))
	if err != nil {
		t.Fatal(err)
	}
	for index, scenario := range []string{
		"missing auth time", "wrong assurance", "confirmed", "lost commit ACK", "rollback after evidence",
		"absent SID", "second outbox failure", "bounded membership",
	} {
		t.Run("issuance "+scenario, func(t *testing.T) {
			profile := integrationSubjectProfile{authTime: true, sid: " Synthetic-é-SID ", acr: "urn:meshtransit:assurance:mfa", amr: []string{"synthetic"}}
			if scenario == "missing auth time" {
				profile.authTime = false
			}
			if scenario == "wrong assurance" {
				profile.acr = "unconfigured-assurance"
			}
			if scenario == "absent SID" {
				profile.sid = ""
			}
			if scenario == "bounded membership" {
				setIssueMembershipExpiry(ctx, t, admin, "fc1", time.Now().UTC().Add(30*time.Second).Truncate(time.Microsecond))
				t.Cleanup(func() { setIssueMembershipExpiry(ctx, t, admin, "fc2", time.Time{}) })
			}
			exchange, _ := integrationSubjectExchangeWithProfile(ctx, t, store,
				[]string{"fb0", "fb1", "fb2", "fb3", "fb4", "fb5", "fb6", "fb7"}[index], profile)
			resolution, err := oidcauth.NewSubjectResolutionService(oidcauth.SubjectResolutionOptions{RequestTimeout: 10 * time.Second, MaxConcurrent: 1}, oidcauth.SubjectResolutionDependencies{Subjects: store, Keys: subjects, Clock: oidcauth.SystemStartClock{}, Observer: adapteroidc.NewSubjectTelemetry()})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := resolution.ResolveBrowser(ctx, exchange)
			if err != nil {
				t.Fatal(err)
			}
			// The login Workspace holds the Account's most recent Session (seeded by
			// subject resolution, then renewed by every committed issuance here).
			if snapshot.WorkspaceID().String() != integrationLoginWorkspacePublicID ||
				snapshot.MembershipID().String() != integrationLoginMembershipPublicID {
				t.Fatalf("issuance subject chose Workspace %s, want the most recent Session's", snapshot.WorkspaceID())
			}
			transactions := &integrationIssueTransactions{store: store, hideACK: scenario == "lost commit ACK", rejectAfterIssue: scenario == "rollback after evidence"}
			var material oidcauth.IssueMaterialGenerator = oidcauth.SystemIssueMaterial{}
			if scenario == "second outbox failure" {
				// Bootstrap outbox already exists. Prepare the fault before Begin;
				// production material generation always creates six fresh IDs.
				duplicate, parseErr := publicid.Parse("01890f03-0000-7000-8000-000000000001")
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				material = integrationIssueCollisionMaterial{duplicate: duplicate}
			}
			service, err := oidcauth.NewIssueService(oidcauth.IssueOptions{RequestTimeout: 10 * time.Second, RollbackTimeout: 2 * time.Second, IdleLifetime: time.Minute, AbsoluteLifetime: time.Hour, MaxConcurrent: 1}, oidcauth.IssueDependencies{Transactions: transactions, Material: material, Subjects: subjects, Sessions: sessions, ProviderSessions: sid, Clock: oidcauth.SystemStartClock{}, Observer: adapteroidc.NewIssueTelemetry()})
			if err != nil {
				t.Fatal(err)
			}
			before := authAdmissionAuthorityCounts(ctx, t, admin)
			result, issueErr := service.IssueBrowser(ctx, exchange, snapshot)
			committed := scenario == "confirmed" || scenario == "lost commit ACK" ||
				scenario == "absent SID" || scenario == "bounded membership"
			if committed && scenario != "lost commit ACK" {
				if issueErr != nil || !result.IsValid() {
					t.Fatalf("confirmed issuance failed: %v", issueErr)
				}
				assertIssuedSessionAuthenticates(ctx, t, pool, sessions, result)
				assertIssuedSessionLoginWorkspace(ctx, t, admin, snapshot, result)
				if scenario == "bounded membership" &&
					(!result.Session().IdleExpiresAt().Equal(snapshot.MembershipExpiresAt()) ||
						!result.Session().AbsoluteExpiresAt().Equal(snapshot.MembershipExpiresAt())) {
					t.Fatal("finite membership did not cap both Session deadlines")
				}
			} else if issueErr == nil || result.IsValid() || result.Token().Encoded() != "" {
				t.Fatal("failure/unknown Commit released bearer")
			}
			if scenario == "lost commit ACK" && !errors.Is(issueErr, oidcauth.ErrCommitOutcomeUnknown) {
				t.Fatal("unknown Commit classification lost")
			}
			if scenario == "missing auth time" && transactions.begins != 0 {
				t.Fatal("missing auth_time entered write unit")
			}
			assertIssueDurableResult(ctx, t, admin, exchange, transactions.command, before, committed)
			if scenario != "missing auth time" {
				replay, replayErr := service.IssueBrowser(ctx, exchange, snapshot)
				if replayErr == nil || replay.IsValid() || transactions.begins != 1 {
					t.Fatal("issuance attempt replayed")
				}
			}
			if scenario == "rollback after evidence" {
				assertIssueSQLRechecks(ctx, t, admin, runtime, transactions.command)
				assertIssueSubjectWriteBarrier(ctx, t, admin, runtime, transactions.command)
				assertIssueIndependentUnits(ctx, t, admin, store, transactions.command)
			}
		})
	}
}

type integrationIssueTransactions struct {
	store                     *postgresadapter.AuthTransactionStore
	hideACK, rejectAfterIssue bool
	begins                    int
	command                   oidcauth.IssueCommand
}

func (transactions *integrationIssueTransactions) BeginIssue(ctx context.Context, route oidcauth.Route) (oidcauth.IssueTransaction, error) {
	transactions.begins++
	unit, err := transactions.store.BeginIssue(ctx, route)
	if unit == nil {
		return nil, err
	}
	return &integrationIssueUnit{IssueTransaction: unit, owner: transactions}, err
}

type integrationIssueUnit struct {
	oidcauth.IssueTransaction
	owner *integrationIssueTransactions
}

func (unit *integrationIssueUnit) Issue(ctx context.Context, command oidcauth.IssueCommand) (oidcauth.Issued, error) {
	unit.owner.command = command
	issued, err := unit.IssueTransaction.Issue(ctx, command)
	if err == nil && unit.owner.rejectAfterIssue {
		return oidcauth.Issued{}, errors.New("synthetic failure after atomic evidence")
	}
	return issued, err
}
func (unit *integrationIssueUnit) Commit(ctx context.Context) error {
	if err := unit.IssueTransaction.Commit(ctx); err != nil {
		return err
	}
	if unit.owner.hideACK {
		return oidcauth.ErrCommitOutcomeUnknown
	}
	return nil
}

func assertIssuedSessionAuthenticates(ctx context.Context, t *testing.T, pool *postgresadapter.Pool, keys *accountsession.Keyring, result oidcauth.IssueResult) {
	t.Helper()
	store, err := postgresadapter.NewAccountSessionStore(pool, postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := accountsession.NewService(keys, store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := accountsession.ParseToken(result.Token().Encoded())
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := authenticator.Authenticate(ctx, parsed)
	if err != nil || authenticated.ID() != result.Session().ID() || authenticated.PrincipalID() != result.Session().PrincipalID() {
		t.Fatal("new bearer incompatible with current authenticator")
	}
}

func assertIssueDurableResult(ctx context.Context, t *testing.T, admin *pgx.Conn, exchange oidcauth.ExchangeResult, command oidcauth.IssueCommand, before [5]int64, committed bool) {
	t.Helper()
	after := authAdmissionAuthorityCounts(ctx, t, admin)
	var state string
	var proofErased bool
	var resultID *string
	if err := admin.QueryRow(ctx, `SELECT state,pkce_verifier_encryption_algorithm IS NULL AND pkce_verifier_encryption_key_id IS NULL AND pkce_verifier_ciphertext IS NULL,consumed_result_public_id::TEXT FROM mesh.auth_transaction WHERE public_id=$1::UUID`, exchange.Claimed().TransactionID().String()).Scan(&state, &proofErased, &resultID); err != nil {
		t.Fatal(err)
	}
	if !committed {
		if before != after || state != "consuming" || proofErased || resultID != nil {
			t.Fatal("rejection did not roll back authority/proof/evidence")
		}
		return
	}
	if state != "succeeded" || !proofErased || resultID == nil || *resultID != command.IDs().SessionID().String() {
		t.Fatal("success reference/proof not atomic")
	}
	var sessionCount, mutations, audits, outboxes, grants int64
	var sidAlgorithm, sidKey *string
	var tokenKey string
	var sidDigest []byte
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM mesh.account_session WHERE public_id=$1::UUID),
    (SELECT count(*) FROM mesh_audit.authority_mutation WHERE change_public_id=$2::UUID),
    (SELECT count(*) FROM mesh_audit.audit_event_identity WHERE change_public_id=$2::UUID),
    (SELECT count(*) FROM mesh_ops.outbox_event WHERE change_public_id=$2::UUID AND network_revision IS NULL),
    (SELECT count(*) FROM mesh.role_binding WHERE workspace_id=101 AND principal_id=11),
    provider_sid_digest_algorithm,provider_sid_digest_key_id,provider_sid_digest,token_digest_key_id
FROM mesh.account_session WHERE public_id=$1::UUID`, command.IDs().SessionID().String(), command.IDs().ChangeID().String()).Scan(&sessionCount, &mutations, &audits, &outboxes, &grants, &sidAlgorithm, &sidKey, &sidDigest, &tokenKey); err != nil {
		t.Fatal(err)
	}
	expectedSID := command.ProviderSessionDigest().Bytes()
	if sessionCount != 1 || mutations != 2 || audits != 2 || outboxes != 2 || grants != 0 ||
		tokenKey != "integration-session-active-v1" {
		t.Fatal("atomic Session/evidence/SID/active-key contract failed")
	}
	if command.ProviderSessionDigest().IsValid() {
		if sidAlgorithm == nil || *sidAlgorithm != "hmac-sha256-v1" || sidKey == nil ||
			*sidKey != command.ProviderSessionDigest().KeyID().String() || len(sidDigest) != 32 ||
			string(sidDigest) != string(expectedSID[:]) {
			t.Fatal("present SID evidence changed")
		}
	} else if sidAlgorithm != nil || sidKey != nil || sidDigest != nil {
		t.Fatal("absent SID did not persist an all-NULL triple")
	}
	assertIssueEvidenceChain(ctx, t, admin, command)
}

// assertIssuedSessionLoginWorkspace proves the durable Session is bound to the
// Workspace Core chose for the Account, not to any configured route Workspace.
func assertIssuedSessionLoginWorkspace(ctx context.Context, t *testing.T, admin *pgx.Conn, snapshot oidcauth.LoginSubjectSnapshot, result oidcauth.IssueResult) {
	t.Helper()
	var loginWorkspace string
	if err := admin.QueryRow(ctx, `SELECT workspace.public_id::TEXT FROM mesh.account_session AS session
JOIN mesh.workspace AS workspace ON workspace.deployment_id = session.deployment_id AND workspace.id = session.login_workspace_id
WHERE session.public_id = $1::UUID`, result.Session().ID().String()).Scan(&loginWorkspace); err != nil {
		t.Fatal(err)
	}
	sessionWorkspace, hasWorkspace := result.Session().LoginWorkspaceID()
	if loginWorkspace != snapshot.WorkspaceID().String() || !hasWorkspace || sessionWorkspace != snapshot.WorkspaceID() {
		t.Fatalf("issued Session login Workspace = %s, want chosen %s", loginWorkspace, snapshot.WorkspaceID())
	}
}

const integrationIssueCountSQL = `SELECT count(*) FROM mesh_ops.issue_oidc_existing_subject_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,
    $7::TEXT,$8::TEXT,$9::TEXT,$10::TEXT,$11::TEXT,$12::TEXT,$13::TEXT,$14::TEXT[],$15::TEXT[],$16::TEXT,
    $17::UUID,$18::BIGINT,$19::BYTEA,$20::TIMESTAMPTZ,$21::TEXT,$22::TEXT,
    $23::TEXT,$24::TEXT,$25::BYTEA,$26::TEXT,$27::BYTEA,
    $28::UUID,$29::UUID,$30::UUID,$31::BIGINT,$32::BIGINT,$33::BIGINT,$34::BIGINT,$35::BIGINT,$36::BIGINT,
    $37::TIMESTAMPTZ,$38::TIMESTAMPTZ,$39::UUID,$40::TEXT,$41::TEXT,$42::BYTEA,
    $43::TEXT,$44::TEXT,$45::BYTEA,$46::TIMESTAMPTZ,$47::TEXT,$48::TEXT[],$49::TIMESTAMPTZ,$50::BIGINT,$51::BIGINT
)`

func integrationIssueArguments(command oidcauth.IssueCommand) []any {
	subject, token, sid := command.Subject(), command.TokenDigest().Bytes(), command.ProviderSessionDigest().Bytes()
	var expiry any
	if !subject.MembershipExpiresAt().IsZero() {
		expiry = subject.MembershipExpiresAt()
	}
	// issue_oidc_existing_subject_v1 keeps its released shape: the Workspace is
	// the one resolve_oidc_login_subject_v2 chose, never a configured route value.
	lookup := integrationSubjectArguments(command.Lookup())
	args := append(append([]any{lookup[0], subject.WorkspaceID().String()}, lookup[1:]...), subject.PrincipalID().String(), subject.IdentitySubjectID().String(), subject.MembershipID().String(),
		subject.SubjectVersion(), subject.AccountVersion(), subject.MembershipVersion(), subject.PrincipalAuthorityGeneration(), subject.AccountSessionGeneration(), subject.MembershipAuthorityGeneration(), expiry, subject.EvaluatedAt(),
		command.IDs().SessionID().String(), command.TokenDigest().Algorithm(), command.TokenDigest().KeyID().String(), token[:],
		command.ProviderSessionDigest().Algorithm(), command.ProviderSessionDigest().KeyID().String(), sid[:], command.AuthenticationTime(), command.ACR(), command.AMR(), command.ProviderExpiresAt(), int64(command.IdleLifetime()/time.Second), int64(command.AbsoluteLifetime()/time.Second))
	return args
}

func assertIssueSQLRechecks(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, command oidcauth.IssueCommand) {
	t.Helper()
	for _, scenario := range []string{"valid rollback", "stale subject version", "stale account generation", "stale member generation", "missing auth time", "wrong ACR", "expired provider evidence", "duplicate SID half", "terminal claim", "account quarantine", "revoked membership"} {
		t.Run("issuance SQL "+scenario, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, tx)
			setIntegrationChange(ctx, t, tx, command.IDs().ChangeID().String())
			args := integrationIssueArguments(command)
			switch scenario {
			case "stale subject version":
				args[30] = command.Subject().SubjectVersion() + 1
			case "stale account generation":
				args[34] = command.Subject().AccountSessionGeneration() + 1
			case "stale member generation":
				args[35] = command.Subject().MembershipAuthorityGeneration() + 1
			case "missing auth time":
				args[45] = nil
			case "wrong ACR":
				args[46] = "unconfigured-assurance"
			case "expired provider evidence":
				args[48] = time.Now().UTC().Add(-time.Second)
			case "duplicate SID half":
				args[43] = nil
			case "terminal claim":
				if _, err := tx.Exec(ctx, `SELECT count(*) FROM mesh_ops.fail_oidc_browser_v2($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::UUID,2,$7::BYTEA,$8::TIMESTAMPTZ)`, args[0], args[2], args[3], args[4], args[5], args[16], args[18], args[19]); err != nil {
					t.Fatal(err)
				}
			case "account quarantine":
				if _, err := tx.Exec(ctx, `UPDATE mesh.account SET recovery_state='quarantined',session_generation=session_generation+1,version=version+1,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE id=701`); err != nil {
					t.Fatal(err)
				}
			case "revoked membership":
				if _, err := tx.Exec(ctx, `UPDATE mesh.workspace_membership SET state='revoked',authority_generation=authority_generation+1,version=version+1,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE public_id='01890f00-0000-7000-8000-000000000fa1'`); err != nil {
					t.Fatal(err)
				}
			}
			var count int64
			if err := tx.QueryRow(ctx, integrationIssueCountSQL, args...).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if scenario == "valid rollback" {
				want = 1
			}
			if count != want {
				t.Fatalf("issuance SQL count=%d, want=%d", count, want)
			}
			assertAdmissionScopeCleared(ctx, t, tx)
		})
	}
	var secure, runtimeExecute, workerExecute, observerExecute bool
	if err := admin.QueryRow(ctx, `SELECT p.prosecdef AND p.proowner='mesh_migrator'::regrole,
    has_function_privilege('mesh_runtime',p.oid,'EXECUTE'),has_function_privilege('mesh_worker',p.oid,'EXECUTE'),has_function_privilege('mesh_observer',p.oid,'EXECUTE')
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='mesh_ops' AND p.proname='issue_oidc_existing_subject_v1'`).Scan(&secure, &runtimeExecute, &workerExecute, &observerExecute); err != nil {
		t.Fatal(err)
	}
	if !secure || !runtimeExecute || workerExecute || observerExecute {
		t.Fatal("issuance privilege contract widened")
	}
	// Serving role can exercise the exact authority function without table grants.
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, tx)
	setIntegrationChange(ctx, t, tx, command.IDs().ChangeID().String())
	var count int64
	if err := tx.QueryRow(ctx, integrationIssueCountSQL, integrationIssueArguments(command)...).Scan(&count); err != nil || count != 1 {
		t.Fatalf("runtime issuance function failed: %v", err)
	}
	assertAdmissionScopeCleared(ctx, t, tx)
}
