package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestLoadPendingClosesReadOnlyUnitBeforeReturningEvidence(t *testing.T) {
	t.Parallel()
	pending := authTransactionPendingFixture(t)
	transaction := newFakeAuthTransactionDatabaseTransaction()
	transaction.enqueueRow(loadPendingAuthTransactionSQL, pendingAuthTransactionRow(pending))
	database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
	store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, found, err := store.LoadPending(context.Background(), pending.Route(), pending.StateDigest())
	if err != nil || !found || !snapshot.IsValid() || snapshot.SemanticHash() != pending.SemanticHash() {
		t.Fatalf("LoadPending() found=%v error=%v", found, err)
	}
	if len(database.readOnly) != 1 || !database.readOnly[0] || transaction.commitCalls != 1 || transaction.rollbackCalls != 0 {
		t.Fatal("positive snapshot escaped an incomplete read-only unit")
	}
	query := transaction.calls[len(transaction.calls)-1]
	if query.query != loadPendingAuthTransactionSQL || len(query.arguments) != 20 ||
		query.arguments[18] != pending.Route().RedirectID() ||
		query.arguments[19] != pending.Route().ReturnRouteID() {
		t.Fatal("pending lookup omitted exact route labels")
	}
}

func TestLoadPendingRejectsReadCompletionCleanupAndMalformedEvidence(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing", "missing canceled", "malformed", "configure", "commit", "cleanup", "canceled during scan", "algorithm", "short digest", "null hash", "changed hash", "nonpending"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pending := authTransactionPendingFixture(t)
			transaction := newFakeAuthTransactionDatabaseTransaction()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			row := pendingAuthTransactionRow(pending)
			original := row.scan
			row.scan = func(destinations ...any) error {
				if err := original(destinations...); err != nil {
					return err
				}
				switch name {
				case "canceled during scan":
					cancel()
				case "algorithm":
					*destinations[5].(*string) = "unsupported"
				case "short digest":
					*destinations[7].(*[]byte) = []byte{1}
				case "null hash":
					*destinations[14].(*[]byte) = nil
				case "changed hash":
					(*destinations[14].(*[]byte))[0] ^= 1
				case "nonpending":
					*destinations[2].(*string) = "consuming"
				}
				return nil
			}
			switch name {
			case "missing":
				row = authTransactionTestRow{err: pgx.ErrNoRows}
			case "missing canceled":
				row = authTransactionTestRow{scan: func(...any) error { cancel(); return pgx.ErrNoRows }}
			case "malformed":
				row = authTransactionTestRow{}
			case "configure":
				transaction.execErrors[configureAuthTransactionSQL] = []error{errors.New("synthetic setup failure")}
			case "commit":
				transaction.commitErr = errors.New("synthetic completion failure")
			case "cleanup":
				row = authTransactionTestRow{err: pgx.ErrNoRows}
				transaction.rollbackErr = errors.New("synthetic cleanup failure")
			}
			transaction.enqueueRow(loadPendingAuthTransactionSQL, row)
			database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, found, err := store.LoadPending(ctx, pending.Route(), pending.StateDigest())
			if found || snapshot.IsValid() {
				t.Fatal("bad read released positive evidence")
			}
			if name == "missing" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("failed read returned no failure")
			}
			if name == "missing canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("absent read lost cancellation classification")
			}
			if transaction.rollbackCalls != 1 {
				t.Fatal("failed or absent read did not join cleanup")
			}
		})
	}
}

func TestLoadPendingRejectsInvalidRequestBeforeBegin(t *testing.T) {
	t.Parallel()
	database := &fakeAuthTransactionDatabase{}
	store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The absent context interface deliberately exercises invalid caller input,
	// matching existing admission tests. No context operation or I/O is allowed.
	var absentContext context.Context
	pending := authTransactionPendingFixture(t)
	if _, _, err := store.LoadPending(absentContext, pending.Route(), pending.StateDigest()); err == nil || len(database.readOnly) != 0 {
		t.Fatal("invalid request reached database")
	}
	if _, _, err := store.LoadPending(t.Context(), oidcauth.Route{}, pending.StateDigest()); err == nil || len(database.readOnly) != 0 {
		t.Fatal("invalid route reached database")
	}
}

func pendingAuthTransactionRow(pending oidcauth.Pending) authTransactionTestRow {
	return authTransactionTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = pending.TransactionID().String()
		*destinations[1].(*int64) = 1
		*destinations[2].(*string) = "pending"
		*destinations[3].(*string) = "browser_authorization_code"
		*destinations[4].(*string) = "login"
		*destinations[5].(*string) = pending.StateDigest().Algorithm()
		*destinations[6].(*string) = pending.StateDigest().KeyID().String()
		state := pending.StateDigest().Bytes()
		*destinations[7].(*[]byte) = append([]byte(nil), state[:]...)
		*destinations[8].(*string) = pending.NonceDigest().Algorithm()
		*destinations[9].(*string) = pending.NonceDigest().KeyID().String()
		nonce := pending.NonceDigest().Bytes()
		*destinations[10].(*[]byte) = append([]byte(nil), nonce[:]...)
		*destinations[11].(*string) = pending.VerifierCiphertext().Algorithm()
		*destinations[12].(*string) = pending.VerifierCiphertext().KeyID().String()
		*destinations[13].(*[]byte) = pending.VerifierCiphertext().Bytes()
		hash := pending.SemanticHash()
		*destinations[14].(*[]byte) = append([]byte(nil), hash[:]...)
		*destinations[15].(*time.Time) = pending.CreatedAt()
		*destinations[16].(*time.Time) = pending.ExpiresAt()
		return nil
	}}
}
