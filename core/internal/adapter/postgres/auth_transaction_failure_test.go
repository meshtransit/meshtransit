package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

func TestFailureUnitExactEvidenceAndSingleCommit(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"confirmed", "expired", "unknown commit", "bad ID", "bad hash", "bad consumed time", "bad version", "bad head", "bad class", "future deadline class", "append failure", "bad sequence"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := authFailureCommandFixture(t)
			snapshot := command.Snapshot()
			database := newFakeAuthTransactionDatabaseTransaction()
			database.enqueueRow(failAuthTransactionSQL, authTransactionTestRow{scan: func(dest ...any) error {
				hash := snapshot.SemanticHash()
				*dest[0].(*string), *dest[1].(*int64) = snapshot.TransactionID().String(), 3
				*dest[2].(*time.Time), *dest[3].(*time.Time), *dest[4].(*time.Time) = snapshot.CreatedAt(), snapshot.ExpiresAt(), command.Claimed().ConsumedAt()
				*dest[5].(*[]byte), *dest[6].(*string), *dest[7].(*string) = hash[:], "failed", "authentication_failed"
				*dest[8].(*time.Time) = command.Claimed().ConsumedAt().Add(time.Second)
				*dest[9].(*int64), *dest[10].(*int64), *dest[11].(*[]byte) = 51, 7, make([]byte, 32)
				switch name {
				case "expired":
					*dest[6].(*string), *dest[7].(*string), *dest[8].(*time.Time) = "expired", "deadline_expired", snapshot.ExpiresAt()
				case "bad ID":
					*dest[0].(*string) = "01890f00-0000-7000-8000-000000000051"
				case "bad hash":
					*dest[5].(*[]byte) = make([]byte, 32)
				case "bad consumed time":
					*dest[4].(*time.Time) = command.Claimed().ConsumedAt().Add(time.Microsecond)
				case "bad version":
					*dest[1].(*int64) = 2
				case "bad head":
					*dest[11].(*[]byte) = make([]byte, 31)
				case "bad class":
					*dest[7].(*string) = "raw_error"
				case "future deadline class":
					*dest[8].(*time.Time) = snapshot.ExpiresAt()
				}
				return nil
			}})
			database.enqueueRow(appendAuthFailureEvidenceSQL, authTransactionTestRow{scan: func(dest ...any) error {
				*dest[0].(*int64) = 7
				if name == "append failure" {
					return errors.New("private-secret")
				}
				if name == "bad sequence" {
					*dest[0].(*int64) = 8
				}
				return nil
			}})
			if name == "unknown commit" {
				database.commitErr = errors.New("lost ACK")
			}
			unit := newAuthFailureTransaction(database, snapshot.Route(), nil)
			result, err := unit.Fail(t.Context(), command)
			if name != "confirmed" && name != "expired" && name != "unknown commit" {
				if err == nil || result.IsValid() || unit.Commit(t.Context()) == nil || database.commitCalls != 0 {
					t.Fatal("invalid terminal released/committed")
				}
			} else {
				if err != nil || !result.IsValid() {
					t.Fatal(err)
				}
				if len(database.calls) != 3 {
					t.Fatal("unexpected terminal IO")
				}
				args := database.calls[2].arguments
				before, after := result.BeforeSemanticHash(), result.AfterSemanticHash()
				if args[7] != int64(3) || string(args[9].([]byte)) != string(before[:]) || string(args[10].([]byte)) != string(after[:]) {
					t.Fatal("terminal evidence hash/version")
				}
				err = unit.Commit(t.Context())
				if name == "unknown commit" && !errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) {
					t.Fatal("unknown outcome lost")
				}
				if name != "unknown commit" && err != nil {
					t.Fatal(err)
				}
				if unit.Commit(t.Context()) == nil || database.commitCalls != 1 {
					t.Fatal("Commit retried")
				}
			}
			if err := unit.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailureUnitRejectsOverlappingMethods(t *testing.T) {
	t.Parallel()
	command := authFailureCommandFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	database := newFakeAuthTransactionDatabaseTransaction()
	database.enqueueRow(failAuthTransactionSQL, authTransactionTestRow{scan: func(...any) error { close(entered); <-release; return errors.New("rejected") }})
	unit := newAuthFailureTransaction(database, command.Snapshot().Route(), nil)
	finished := make(chan error, 1)
	go func() { _, err := unit.Fail(t.Context(), command); finished <- err }()
	<-entered
	if _, err := unit.Fail(t.Context(), command); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("queued Fail")
	}
	if err := unit.Commit(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("queued Commit")
	}
	if err := unit.Rollback(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("queued Rollback")
	}
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("failure disappeared")
	}
	if err := unit.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(database.calls) != 2 || database.commitCalls != 0 || database.rollbackCalls != 1 {
		t.Fatal("overlapping database IO")
	}
}

func TestFailureBeginOwnsSetupCleanupAndNeverUsesAdmission(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"confirmed", "setup error", "setup cleanup error", "begin error", "canceled"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := authFailureCommandFixture(t)
			transaction := newFakeAuthTransactionDatabaseTransaction()
			database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
			store := &AuthTransactionStore{database: database, options: testAuthTransactionOptions()}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch name {
			case "setup error", "setup cleanup error":
				transaction.execErrors[configureAuthTransactionSQL] = []error{errors.New("private-secret")}
			case "begin error":
				database.beginErr = errors.New("private-secret")
			case "canceled":
				cancel()
			}
			if name == "setup cleanup error" {
				transaction.rollbackErr = errors.New("private-secret")
			}
			unit, err := store.BeginFailure(ctx, command.Snapshot().Route())
			if name == "confirmed" {
				if err != nil || unit == nil || len(database.readOnly) != 1 || database.readOnly[0] || len(transaction.calls) != 1 || transaction.calls[0].query != configureAuthTransactionSQL {
					t.Fatal("begin did more than owned write setup", err)
				}
				if err := unit.Rollback(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || unit != nil {
				t.Fatal("failed setup returned unit")
			}
			if (name == "setup error" || name == "setup cleanup error") && transaction.rollbackCalls != 1 {
				t.Fatal("owned setup leaked")
			}
			if name == "canceled" && len(database.readOnly) != 0 {
				t.Fatal("canceled begin performed IO")
			}
		})
	}
}

func authFailureCommandFixture(t *testing.T) oidcauth.FailureCommand {
	t.Helper()
	verified := authClaimVerifiedFixture(t)
	claim, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}, oidcauth.ClaimDependencies{Transactions: failureFixtureClaims{}, IDs: oidcauth.SystemClaimIDs{}, Clock: authClaimClock{verified.Snapshot().CreatedAt().Add(time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := claim.ClaimBrowser(t.Context(), verified)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	command, err := oidcauth.NewFailureCommand(receipt, ids)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

type failureFixtureClaims struct{}

func (failureFixtureClaims) BeginClaim(context.Context, oidcauth.Route) (oidcauth.ClaimTransaction, error) {
	return failureFixtureClaim{}, nil
}

type failureFixtureClaim struct{}

func (failureFixtureClaim) Claim(_ context.Context, command oidcauth.ClaimCommand) (oidcauth.Claimed, error) {
	return oidcauth.NewClaimed(command.Snapshot(), 2, command.Snapshot().CreatedAt().Add(time.Second))
}
func (failureFixtureClaim) Commit(context.Context) error   { return nil }
func (failureFixtureClaim) Rollback(context.Context) error { return nil }
