//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

func assertIssueSubjectWriteBarrier(
	ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, command oidcauth.IssueCommand,
) {
	t.Helper()
	active := command.Lookup().Digests()[0]
	value := active.Bytes()
	// This subject does not match either observed HMAC candidate. Digest-only
	// updates therefore would not be protected by the issuance row locks.
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000000fc0",
		eventPublicID:  "01890f02-0000-7000-8000-000000000fc0",
		outboxPublicID: "01890f03-0000-7000-8000-000000000fc0",
		streamID:       1, aggregateKind: "identity_subject",
		aggregatePublicID: "01890f00-0000-7000-8000-000000000fc0", aggregateVersion: 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "identity_subject.created", permission: "system.bootstrap",
		outboxEventClass: "identity_subject.created",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `INSERT INTO mesh.identity_subject (
public_id,deployment_id,identity_provider_id,principal_id,subject_digest_algorithm,
subject_digest_key_id,subject_digest,claims_revision,last_seen_at,state
) VALUES ('01890f00-0000-7000-8000-000000000fc0',1,601,11,$1,$2,$3,1,clock_timestamp(),'active')`,
			active.Algorithm(), active.KeyID().String(), integrationFilledBytes(0x7b, 32)); err != nil {
			t.Fatal(err)
		}
	})
	reader, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, reader)
	setIntegrationChange(ctx, t, reader, command.IDs().ChangeID().String())
	var count int64
	if err := reader.QueryRow(ctx, integrationIssueCountSQL, integrationIssueArguments(command)...).Scan(&count); err != nil || count != 1 {
		t.Fatalf("acquire issuance barrier: %v", err)
	}
	var held bool
	if err := reader.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks
WHERE pid=pg_backend_pid() AND relation='mesh.identity_subject'::regclass AND mode='ShareLock' AND granted)`).Scan(
		&held,
	); err != nil || !held {
		t.Fatal("authority function did not retain subject relation barrier")
	}
	for _, statement := range []string{
		`UPDATE mesh.identity_subject SET subject_digest_key_id=$1,subject_digest=$2,
version=version+1,claims_revision=claims_revision+1,updated_at=GREATEST(updated_at,clock_timestamp())
WHERE public_id='01890f00-0000-7000-8000-000000000fc0'`,
		`INSERT INTO mesh.identity_subject (public_id,deployment_id,identity_provider_id,principal_id,
subject_digest_algorithm,subject_digest_key_id,subject_digest,claims_revision,last_seen_at,state)
VALUES ('01890f00-0000-7000-8000-000000000fc3',1,601,11,'hmac-sha256-v1',$1,$2,1,clock_timestamp(),'active')`,
	} {
		writer, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		setIntegrationChange(ctx, t, writer, "01890f01-0000-7000-8000-000000000fc3")
		if _, err := writer.Exec(ctx, `SELECT set_config('lock_timeout','50ms',TRUE)`); err != nil {
			t.Fatal(err)
		}
		_, writeErr := writer.Exec(ctx, statement, active.KeyID().String(), value[:])
		var postgresErr *pgconn.PgError
		if !errors.As(writeErr, &postgresErr) || postgresErr.Code != "55P03" {
			t.Fatalf("subject write crossed barrier: %v", writeErr)
		}
		rollbackIntegrationTransaction(ctx, t, writer)
	}
	rollbackIntegrationTransaction(ctx, t, reader)
	// Releasing the owned unit releases the barrier; this write is deliberately
	// rolled back with all its authority mutations, not committed unaudited.
	writer, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, writer)
	setIntegrationChange(ctx, t, writer, "01890f01-0000-7000-8000-000000000fc3")
	if _, err := writer.Exec(ctx, `SELECT set_config('lock_timeout','1s',TRUE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(ctx, `UPDATE mesh.identity_subject SET subject_digest_key_id=$1,subject_digest=$2,
version=version+1,claims_revision=claims_revision+1,updated_at=GREATEST(updated_at,clock_timestamp())
WHERE public_id='01890f00-0000-7000-8000-000000000fc0'`, active.KeyID().String(), value[:]); err != nil {
		t.Fatalf("released barrier still blocks writer: %v", err)
	}
}

func assertIssueIndependentUnits(
	ctx context.Context, t *testing.T, admin *pgx.Conn, store *postgresadapter.AuthTransactionStore,
	command oidcauth.IssueCommand,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	route := command.Lookup().Snapshot().Route()
	first, err := store.BeginIssue(ctx, route)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationIssueUnit(ctx, t, first)
	second, err := store.BeginIssue(ctx, route)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationIssueUnit(ctx, t, second)
	issued, err := first.Issue(ctx, command)
	if err != nil || !issued.Matches(command) {
		t.Fatalf("first independent issuer rejected: %v", err)
	}
	started, finished := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		_, err := second.Issue(ctx, command)
		finished <- err
	}()
	<-started
	commitErr := first.Commit(ctx)
	var secondErr error
	select {
	case secondErr = <-finished:
	case <-ctx.Done():
		secondErr = ctx.Err()
		// Join in-flight work before the deferred cleanup touches its unit.
		<-finished
	}
	if commitErr != nil || secondErr == nil || errors.Is(secondErr, context.DeadlineExceeded) {
		t.Fatalf("independent units did not enforce one durable winner: first=%v second=%v", commitErr, secondErr)
	}
	var sessions, audits, outboxes int64
	if err := admin.QueryRow(ctx, `SELECT
(SELECT count(*) FROM mesh.account_session WHERE public_id=$1::UUID),
(SELECT count(*) FROM mesh_audit.audit_event_identity WHERE change_public_id=$2::UUID),
(SELECT count(*) FROM mesh_ops.outbox_event WHERE change_public_id=$2::UUID)`,
		command.IDs().SessionID().String(), command.IDs().ChangeID().String(),
	).Scan(&sessions, &audits, &outboxes); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || audits != 2 || outboxes != 2 {
		t.Fatal("independent issuer race duplicated or lost atomic authority evidence")
	}
	assertIssueEvidenceChain(ctx, t, admin, command)
}

func rollbackIntegrationIssueUnit(ctx context.Context, t *testing.T, unit oidcauth.IssueTransaction) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := unit.Rollback(cleanup); err != nil {
		t.Errorf("join independent issuance cleanup: %v", err)
	}
}
