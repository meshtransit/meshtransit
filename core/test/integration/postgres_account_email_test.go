//go:build integration

package integration

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

// assertPostgreSQLAccountEmail qualifies schema 288 through the production
// store and real claimed, exchanged sign-ins (S4c §3.1): an identity without
// an Account records nothing; a signed-up Account's verified email is
// recorded once, with evidence that never carries it; the same email again
// writes nothing; a new one updates it; the runtime role cannot read the
// table; and the database refuses an email Devices may not show.
func assertPostgreSQLAccountEmail(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimeConnection *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	authStore, err := postgresadapter.NewAuthTransactionStore(runtimePool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: 10 * time.Second, LockTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	options := postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	emails, err := postgresadapter.NewAccountEmailStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	signups, err := postgresadapter.NewAccountSignupStore(runtimePool, options,
		postgresadapter.SignupLimits{SourcePerDay: 10, DeploymentPerHour: 100})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "email-subject-v1", 0x91))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(suffix, email string) oidcauth.SubjectLookup {
		exchange, route := integrationSubjectExchangeWithProfile(ctx, t, authStore, suffix,
			integrationSubjectProfile{email: email})
		digests, err := keys.Digests(route, exchange.Identity())
		if err != nil {
			t.Fatal(err)
		}
		found, err := oidcauth.NewSubjectLookup(exchange.Claimed(), digests)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	record := func(suffix, email string) oidcauth.AccountEmailResult {
		result, err := emails.RecordEmail(ctx, oidcauth.AccountEmail{Lookup: lookup(suffix, email), Email: email})
		if err != nil {
			t.Fatalf("RecordEmail(%s) error = %v", suffix, err)
		}
		return result
	}

	if result := record("e91", "person@example.test"); result != oidcauth.AccountEmailNoAccount {
		t.Fatalf("an identity without an Account = %v, want no account", result)
	}
	if err := signups.SignUp(ctx, oidcauth.AccountSignup{
		Lookup: lookup("e92", ""), Source: oidcauth.NewSignupSource([32]byte{0x91}), DisplayName: "Email Person",
	}); err != nil {
		t.Fatalf("sign up: %v", err)
	}
	if result := record("e93", "person@example.test"); result != oidcauth.AccountEmailRecorded {
		t.Fatalf("first email = %v, want recorded", result)
	}
	if result := record("e94", "person@example.test"); result != oidcauth.AccountEmailUnchanged {
		t.Fatalf("same email = %v, want unchanged", result)
	}
	if result := record("e95", "renamed@example.test"); result != oidcauth.AccountEmailRecorded {
		t.Fatalf("new email = %v, want recorded", result)
	}
	assertConcurrentFirstEmail(ctx, t, authStore, emails, signups)
	var stored string
	var version int64
	if err := admin.QueryRow(ctx, `SELECT stored.email, stored.version
FROM mesh.account_email AS stored
JOIN mesh.account AS account ON account.id = stored.account_id
WHERE account.display_name = 'Email Person'`).Scan(&stored, &version); err != nil {
		t.Fatal(err)
	}
	if stored != "renamed@example.test" || version != 2 {
		t.Fatalf("stored email = %q v%d, want the new email at version 2", stored, version)
	}
	rows, err := admin.Query(ctx, `SELECT target_kind, (payload ->> 'email_version')::BIGINT, payload::TEXT
FROM mesh_audit.audit_event WHERE action = 'account.email_verified' ORDER BY occurred_at, event_identity_id`)
	if err != nil {
		t.Fatal(err)
	}
	var events int
	for rows.Next() {
		var kind, payload string
		var aggregateVersion int64
		if err := rows.Scan(&kind, &aggregateVersion, &payload); err != nil {
			t.Fatal(err)
		}
		events++
		if kind != "account_email" || aggregateVersion < 1 || aggregateVersion > 2 || strings.Contains(payload, "@") {
			t.Fatalf("evidence %d = %s v%d %s; want account_email, its version, no email", events, kind,
				aggregateVersion, payload)
		}
	}
	if err := rows.Err(); err != nil || events != 3 {
		t.Fatalf("email evidence = %d, %v; want 3", events, err)
	}
	_, err = runtimeConnection.Exec(ctx, `SELECT email FROM mesh.account_email`)
	assertPostgreSQLCode(t, err, "42501")
	// The function refuses what Go refuses before the CHECK ever sees it.
	for _, email := range []string{"al<ice@example.test", "üser@example.test", "two@@example.test"} {
		_, err := runtimeConnection.Exec(ctx, `SELECT * FROM mesh_ops.record_account_verified_email_v1(
 pg_catalog.uuidv7(), pg_catalog.uuidv7(), pg_catalog.uuidv7(), 1, 1, pg_catalog.uuidv7(), 1,
 pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.clock_timestamp(), 'hmac-sha256-v1', 'k',
 pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), NULL, NULL, $1, pg_catalog.uuidv7(), pg_catalog.uuidv7())`,
			email)
		assertPostgreSQLCode(t, err, "22023")
	}
	// A sign-in that is not this one's never writes.
	_, err = runtimeConnection.Exec(ctx, `SELECT * FROM mesh_ops.record_account_verified_email_v1(
 pg_catalog.uuidv7(), pg_catalog.uuidv7(), pg_catalog.uuidv7(), 1, 1, pg_catalog.uuidv7(), 1,
 pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.clock_timestamp(), 'hmac-sha256-v1', 'k',
 pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), NULL, NULL, 'x@example.test', pg_catalog.uuidv7(),
 pg_catalog.uuidv7())`)
	assertPostgreSQLCode(t, err, "42501")
}

// assertConcurrentFirstEmail: two first sign-ins of one Account at once
// write one row; the other finds it and writes nothing, without an error.
func assertConcurrentFirstEmail(ctx context.Context, t *testing.T, authStore *postgresadapter.AuthTransactionStore,
	emails *postgresadapter.AccountEmailStore, signups *postgresadapter.AccountSignupStore) {
	t.Helper()
	keys, err := oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "email-subject-v2", 0x92))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(suffix string) oidcauth.SubjectLookup {
		exchange, route := integrationSubjectExchangeWithProfile(ctx, t, authStore, suffix, integrationSubjectProfile{})
		digests, err := keys.Digests(route, exchange.Identity())
		if err != nil {
			t.Fatal(err)
		}
		found, err := oidcauth.NewSubjectLookup(exchange.Claimed(), digests)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	if err := signups.SignUp(ctx, oidcauth.AccountSignup{
		Lookup: lookup("e96"), Source: oidcauth.NewSignupSource([32]byte{0x92}), DisplayName: "Racing Person",
	}); err != nil {
		t.Fatalf("sign up: %v", err)
	}
	first, second := lookup("e97"), lookup("e98")
	var group sync.WaitGroup
	results := make([]oidcauth.AccountEmailResult, 2)
	errs := make([]error, 2)
	for index, found := range []oidcauth.SubjectLookup{first, second} {
		group.Go(func() {
			results[index], errs[index] = emails.RecordEmail(ctx,
				oidcauth.AccountEmail{Lookup: found, Email: "racing@example.test"})
		})
	}
	group.Wait()
	recorded, unchanged := 0, 0
	for index := range results {
		if errs[index] != nil {
			t.Fatalf("concurrent RecordEmail error = %v", errs[index])
		}
		switch results[index] {
		case oidcauth.AccountEmailRecorded:
			recorded++
		case oidcauth.AccountEmailUnchanged:
			unchanged++
		}
	}
	if recorded != 1 || unchanged != 1 {
		t.Fatalf("concurrent first emails = %v, want one recorded and one unchanged", results)
	}
}
