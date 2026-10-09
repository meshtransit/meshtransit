package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestAuthTransactionAdmitUsesExactReadOnlyRoute(t *testing.T) {
	t.Parallel()
	route := authTransactionPendingFixture(t).Route()
	transaction := newFakeAuthTransactionDatabaseTransaction()
	transaction.enqueueRow(admitAuthTransactionRouteSQL, admissionTestRow(true))
	database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
	store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Admit(t.Context(), route); err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if len(database.readOnly) != 1 || !database.readOnly[0] {
		t.Fatalf("readOnly = %v, want one read-only unit", database.readOnly)
	}
	if len(transaction.calls) != 2 || transaction.calls[0].query != configureAuthTransactionSQL ||
		transaction.calls[1].query != admitAuthTransactionRouteSQL {
		t.Fatal("admission must only configure timeouts and read exact route")
	}
	want := []any{
		route.DeploymentID().String(),
		route.ProviderID().String(), route.ClientID().String(),
		route.ProviderGeneration(), route.RecoveryEpoch(),
		route.Issuer(), route.DiscoveryURI(), route.AuthorizationEndpoint(),
		route.TokenEndpoint(), route.JWKSURI(), route.OIDCClientID(),
		route.ClientAuthMethod(), route.Scopes(), route.AllowedAlgorithms(), route.RedirectURI(),
	}
	if !reflect.DeepEqual(transaction.calls[1].arguments, want) {
		t.Fatal("admission arguments must match the complete durable route, with no secrets")
	}
	if transaction.commitCalls != 1 || transaction.rollbackCalls != 0 {
		t.Fatal("successful read must close once before returning")
	}
}

func TestAuthTransactionAdmitRejectsDependencyAndCompletionFailures(t *testing.T) {
	t.Parallel()
	for _, candidate := range []struct {
		name  string
		setup func(*fakeAuthTransactionDatabase, *fakeAuthTransactionDatabaseTransaction)
		want  error
	}{
		{name: "begin", setup: func(database *fakeAuthTransactionDatabase, _ *fakeAuthTransactionDatabaseTransaction) {
			database.beginErr = errors.New("connection unavailable")
		}},
		{name: "configure", setup: func(_ *fakeAuthTransactionDatabase, transaction *fakeAuthTransactionDatabaseTransaction) {
			transaction.execErrors[configureAuthTransactionSQL] = []error{errors.New("setup rejected")}
		}},
		{name: "false", setup: func(_ *fakeAuthTransactionDatabase, transaction *fakeAuthTransactionDatabaseTransaction) {
			transaction.rows[admitAuthTransactionRouteSQL] = []authTransactionRow{admissionTestRow(false)}
		}, want: ErrAuthTransactionRouteUnavailable},
		{name: "missing", setup: func(_ *fakeAuthTransactionDatabase, transaction *fakeAuthTransactionDatabaseTransaction) {
			transaction.rows[admitAuthTransactionRouteSQL] = []authTransactionRow{authTransactionTestRow{err: pgx.ErrNoRows}}
		}, want: ErrAuthTransactionRouteUnavailable},
		{name: "null or malformed result", setup: func(_ *fakeAuthTransactionDatabase, transaction *fakeAuthTransactionDatabaseTransaction) {
			transaction.rows[admitAuthTransactionRouteSQL] = []authTransactionRow{authTransactionTestRow{err: errors.New("invalid boolean")}}
		}},
		{name: "query", setup: func(_ *fakeAuthTransactionDatabase, transaction *fakeAuthTransactionDatabaseTransaction) {
			transaction.rows[admitAuthTransactionRouteSQL] = []authTransactionRow{authTransactionTestRow{err: &pgconn.PgError{
				Code: "23503", Message: "private provider topology", Detail: "private metadata",
			}}}
		}, want: ErrAuthTransactionRouteUnavailable},
		{name: "read commit unknown", setup: func(_ *fakeAuthTransactionDatabase, transaction *fakeAuthTransactionDatabaseTransaction) {
			transaction.commitErr = errors.New("connection lost during read completion")
		}},
		{name: "cleanup", setup: func(_ *fakeAuthTransactionDatabase, transaction *fakeAuthTransactionDatabaseTransaction) {
			transaction.rows[admitAuthTransactionRouteSQL] = []authTransactionRow{admissionTestRow(false)}
			transaction.rollbackErr = &pgconn.PgError{Code: "XX000", Detail: "private cleanup metadata"}
		}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			t.Parallel()
			route := authTransactionPendingFixture(t).Route()
			transaction := newFakeAuthTransactionDatabaseTransaction()
			transaction.enqueueRow(admitAuthTransactionRouteSQL, admissionTestRow(true))
			database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
			candidate.setup(database, transaction)
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			err = store.Admit(t.Context(), route)
			if !errors.Is(err, ErrAdmitAuthTransactionRoute) || (candidate.want != nil && !errors.Is(err, candidate.want)) {
				t.Fatalf("Admit() error = %v, want classified rejection", err)
			}
			if errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) {
				t.Fatal("read-only completion must never imply uncertain authority writes")
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("PostgreSQL query or cleanup detail escaped")
			}
			if database.beginErr == nil && transaction.rollbackCalls != 1 {
				t.Fatal("rejected read must attempt bounded cleanup once")
			}
		})
	}
}

func TestAuthTransactionAdmitRejectsInvalidStateBeforeDatabase(t *testing.T) {
	t.Parallel()
	var nilStore *AuthTransactionStore
	if err := nilStore.Admit(t.Context(), oidcauth.Route{}); !errors.Is(err, ErrInvalidAuthTransactionStore) {
		t.Fatalf("nil store error = %v", err)
	}
	database := &fakeAuthTransactionDatabase{}
	store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var missingContext context.Context
	if err := store.Admit(missingContext, authTransactionPendingFixture(t).Route()); !errors.Is(err, ErrInvalidAuthTransactionStore) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := store.Admit(t.Context(), oidcauth.Route{}); !errors.Is(err, ErrInvalidAuthTransactionStore) {
		t.Fatalf("invalid route error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.Admit(ctx, authTransactionPendingFixture(t).Route()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled admission error = %v", err)
	}
	if len(database.readOnly) != 0 {
		t.Fatal("invalid or canceled admission touched database")
	}
}

func TestAuthTransactionAdmitPropagatesDeadlineAndCancellation(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"configure", "query", "commit"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			transaction := newFakeAuthTransactionDatabaseTransaction()
			transaction.enqueueRow(admitAuthTransactionRouteSQL, admissionTestRow(true))
			wrapped := &admissionContextTransaction{
				fakeAuthTransactionDatabaseTransaction: transaction,
				t:                                      t, stage: stage, cancel: cancel,
			}
			database := &admissionContextDatabase{transaction: wrapped, t: t}
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Admit(ctx, authTransactionPendingFixture(t).Route()); !errors.Is(err, context.Canceled) {
				t.Fatalf("Admit() error = %v, want cancellation at %s", err, stage)
			}
			if stage == "configure" && len(transaction.calls) != 1 {
				t.Fatal("canceled setup continued to route query")
			}
			if stage != "commit" && transaction.commitCalls != 0 {
				t.Fatal("canceled route check continued to completion")
			}
		})
	}
}

func admissionTestRow(admitted bool) authTransactionRow {
	return authTransactionTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*bool) = admitted
		return nil
	}}
}

type admissionContextDatabase struct {
	transaction *admissionContextTransaction
	t           *testing.T
}

func (database *admissionContextDatabase) Begin(ctx context.Context, readOnly bool) (authTransactionDatabaseTransaction, error) {
	if !readOnly {
		database.t.Fatal("admission opened a read-write transaction")
	}
	assertAdmissionContext(ctx, database.t, 30*time.Second)
	return database.transaction, nil
}

type admissionContextTransaction struct {
	*fakeAuthTransactionDatabaseTransaction
	t      *testing.T
	stage  string
	cancel context.CancelFunc
}

func (transaction *admissionContextTransaction) Exec(ctx context.Context, query string, arguments ...any) error {
	assertAdmissionContext(ctx, transaction.t, 30*time.Second)
	if transaction.stage == "configure" {
		transaction.cancel()
	}
	return transaction.fakeAuthTransactionDatabaseTransaction.Exec(ctx, query, arguments...)
}

func (transaction *admissionContextTransaction) QueryRow(ctx context.Context, query string, arguments ...any) authTransactionRow {
	assertAdmissionContext(ctx, transaction.t, 30*time.Second)
	if transaction.stage == "query" {
		transaction.cancel()
	}
	return transaction.fakeAuthTransactionDatabaseTransaction.QueryRow(ctx, query, arguments...)
}

func (transaction *admissionContextTransaction) Commit(ctx context.Context) error {
	assertAdmissionContext(ctx, transaction.t, 30*time.Second)
	if transaction.stage == "commit" {
		transaction.cancel()
	}
	return transaction.fakeAuthTransactionDatabaseTransaction.Commit(ctx)
}

func (transaction *admissionContextTransaction) Rollback(ctx context.Context) error {
	assertAdmissionContext(ctx, transaction.t, authTransactionSetupRollbackWindow)
	return transaction.fakeAuthTransactionDatabaseTransaction.Rollback(ctx)
}

func assertAdmissionContext(ctx context.Context, t *testing.T, maximum time.Duration) {
	t.Helper()
	deadline, found := ctx.Deadline()
	if !found || ctx.Err() != nil || time.Until(deadline) <= 0 || time.Until(deadline) > maximum {
		t.Fatal("database operation requires a live finite context")
	}
}
