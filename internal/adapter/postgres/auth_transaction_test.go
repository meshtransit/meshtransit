package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuthTransactionCreateAppendsAtomicEvidenceAndCommits(t *testing.T) {
	t.Parallel()

	pending := authTransactionPendingFixture(t)
	databaseTransaction := newFakeAuthTransactionDatabaseTransaction()
	enqueueAuthTransactionCreation(databaseTransaction, pending)
	database := &fakeAuthTransactionDatabase{
		transactions: []*fakeAuthTransactionDatabaseTransaction{databaseTransaction},
	}
	store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
	if err != nil {
		t.Fatalf("newAuthTransactionStore() error = %v", err)
	}
	transaction, err := store.Begin(t.Context(), pending.Route())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	created, err := transaction.Create(t.Context(), pending)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !created.IsValid() || created.TransactionID() != pending.TransactionID() {
		t.Fatalf("Create() = %#v, want exact durable creation", created)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	wantQueries := []string{
		configureAuthTransactionSQL,
		setAuthTransactionChangeSQL,
		createAuthTransactionSQL,
		lockAuthTransactionAuditStreamSQL,
		appendAuthTransactionEvidenceSQL,
	}
	if len(databaseTransaction.calls) != len(wantQueries) {
		t.Fatalf("database call count = %d, want %d", len(databaseTransaction.calls), len(wantQueries))
	}
	for index, want := range wantQueries {
		if databaseTransaction.calls[index].query != want {
			t.Fatalf("database call %d query mismatch", index)
		}
	}
	if len(databaseTransaction.calls[2].arguments) != 30 {
		t.Fatalf("create argument count = %d, want 30", len(databaseTransaction.calls[2].arguments))
	}
	evidence := databaseTransaction.calls[4]
	if len(evidence.arguments) != 12 {
		t.Fatalf("evidence argument count = %d, want 12", len(evidence.arguments))
	}
	evidenceText := string(evidence.arguments[10].([]byte)) + string(evidence.arguments[11].([]byte))
	for _, secret := range secretEncodings(pending) {
		if strings.Contains(evidenceText, secret) {
			t.Fatal("audit/outbox payload exposed secret-bearing material")
		}
	}
	if databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf(
			"database completion = (commit %d, rollback %d), want (1, 0)",
			databaseTransaction.commitCalls,
			databaseTransaction.rollbackCalls,
		)
	}
	if len(database.readOnly) != 1 || database.readOnly[0] {
		t.Fatalf("Begin() readOnly = %v, want read-write", database.readOnly)
	}
}

func TestAuthTransactionCreateFailureRequiresRollback(t *testing.T) {
	t.Parallel()

	pending := authTransactionPendingFixture(t)
	databaseTransaction := newFakeAuthTransactionDatabaseTransaction()
	databaseTransaction.enqueueRow(createAuthTransactionSQL, authTransactionCreatedRow(pending))
	databaseTransaction.enqueueRow(lockAuthTransactionAuditStreamSQL, authTransactionTestRow{
		err: errors.New("audit stream unavailable"),
	})
	store, err := newAuthTransactionStore(
		&fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{
			databaseTransaction,
		}},
		testAuthTransactionOptions(),
		nil,
	)
	if err != nil {
		t.Fatalf("newAuthTransactionStore() error = %v", err)
	}
	transaction, err := store.Begin(t.Context(), pending.Route())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := transaction.Create(t.Context(), pending); !errors.Is(err, ErrCreateAuthTransaction) {
		t.Fatalf("Create() error = %v, want ErrCreateAuthTransaction", err)
	}
	if err := transaction.Commit(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Fatalf("Commit() error = %v, want ErrAuthTransactionState", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if databaseTransaction.commitCalls != 0 || databaseTransaction.rollbackCalls != 1 {
		t.Fatalf(
			"database completion = (commit %d, rollback %d), want (0, 1)",
			databaseTransaction.commitCalls,
			databaseTransaction.rollbackCalls,
		)
	}
}

func TestAuthTransactionResolveCommittedUsesExactBinding(t *testing.T) {
	t.Parallel()

	pending := authTransactionPendingFixture(t)
	databaseTransaction := newFakeAuthTransactionDatabaseTransaction()
	databaseTransaction.enqueueRow(loadCommittedAuthTransactionSQL, authTransactionCreatedRow(pending))
	database := &fakeAuthTransactionDatabase{
		transactions: []*fakeAuthTransactionDatabaseTransaction{databaseTransaction},
	}
	store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
	if err != nil {
		t.Fatalf("newAuthTransactionStore() error = %v", err)
	}
	created, found, err := store.ResolveCommitted(t.Context(), pending)
	if err != nil || !found || created.TransactionID() != pending.TransactionID() {
		t.Fatalf("ResolveCommitted() = (%#v, %t, %v), want exact result", created, found, err)
	}
	if len(database.readOnly) != 1 || !database.readOnly[0] {
		t.Fatalf("ResolveCommitted() readOnly = %v, want read-only", database.readOnly)
	}
	if len(databaseTransaction.calls) != 2 ||
		databaseTransaction.calls[1].query != loadCommittedAuthTransactionSQL {
		t.Fatalf("ResolveCommitted() calls = %#v, want configure then exact load", databaseTransaction.calls)
	}
	if databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf("ResolveCommitted() completion = (%d, %d)", databaseTransaction.commitCalls, databaseTransaction.rollbackCalls)
	}
}

func TestAuthTransactionResolveCommittedReturnsNotFound(t *testing.T) {
	t.Parallel()

	pending := authTransactionPendingFixture(t)
	databaseTransaction := newFakeAuthTransactionDatabaseTransaction()
	databaseTransaction.enqueueRow(loadCommittedAuthTransactionSQL, authTransactionTestRow{err: pgx.ErrNoRows})
	store, err := newAuthTransactionStore(
		&fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{
			databaseTransaction,
		}},
		testAuthTransactionOptions(),
		nil,
	)
	if err != nil {
		t.Fatalf("newAuthTransactionStore() error = %v", err)
	}
	if created, found, err := store.ResolveCommitted(t.Context(), pending); err != nil || found || created.IsValid() {
		t.Fatalf("ResolveCommitted() = (%#v, %t, %v), want not found", created, found, err)
	}
	if databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf("ResolveCommitted() completion = (%d, %d)", databaseTransaction.commitCalls, databaseTransaction.rollbackCalls)
	}
}

func TestAuthTransactionCommitReportsUnknownOutcome(t *testing.T) {
	t.Parallel()

	pending := authTransactionPendingFixture(t)
	databaseTransaction := newFakeAuthTransactionDatabaseTransaction()
	enqueueAuthTransactionCreation(databaseTransaction, pending)
	databaseTransaction.commitErr = errors.New("connection lost while committing")
	store, err := newAuthTransactionStore(
		&fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{
			databaseTransaction,
		}},
		testAuthTransactionOptions(),
		nil,
	)
	if err != nil {
		t.Fatalf("newAuthTransactionStore() error = %v", err)
	}
	transaction, err := store.Begin(t.Context(), pending.Route())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := transaction.Create(t.Context(), pending); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := transaction.Commit(t.Context()); !errors.Is(err, ErrCommitAuthTransaction) ||
		!errors.Is(err, ErrAuthTransactionCommitOutcomeUnknown) {
		t.Fatalf("Commit() error = %v, want classified unknown outcome", err)
	}
}

func TestAuthTransactionDatabaseErrorsRetainClassWithoutSensitiveDetail(t *testing.T) {
	t.Parallel()

	err := classifyAuthTransactionDatabaseError(t.Context(), &pgconn.PgError{
		Code:    "23505",
		Message: "duplicate state digest",
		Detail:  "secret-derived-digest-value",
	})
	if !errors.Is(err, ErrAuthTransactionConflict) {
		t.Fatalf("classified error = %v, want conflict", err)
	}
	if strings.Contains(err.Error(), "secret-derived-digest-value") ||
		strings.Contains(err.Error(), "duplicate state digest") {
		t.Fatal("classified database error exposed sensitive PostgreSQL detail")
	}
}
