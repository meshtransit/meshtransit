package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestBrowserClaimUnitRejectsOverlappingCallsWithoutDatabaseIO(t *testing.T) {
	t.Parallel()
	command := authClaimCommandFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	database := newFakeAuthTransactionDatabaseTransaction()
	database.enqueueRow(claimAuthTransactionSQL, authTransactionTestRow{scan: func(...any) error { close(entered); <-release; return errors.New("synthetic claim rejection") }})
	unit := newAuthClaimTransaction(database, command.Snapshot().Route(), nil)
	finished := make(chan error, 1)
	go func() { _, err := unit.Claim(t.Context(), command); finished <- err }()
	<-entered
	if _, err := unit.Claim(t.Context(), command); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("overlapping Claim did not reject")
	}
	if err := unit.Commit(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("overlapping Commit did not reject")
	}
	if err := unit.Rollback(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Error("overlapping Rollback did not reject")
	}
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("synthetic claim failure disappeared")
	}
	if err := unit.Commit(t.Context()); !errors.Is(err, ErrAuthTransactionState) {
		t.Fatal("failed Claim permitted Commit")
	}
	if err := unit.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := unit.Rollback(t.Context()); err != nil || database.rollbackCalls != 1 || database.commitCalls != 0 || len(database.calls) != 2 {
		t.Fatal("ownership caused overlapping or repeated database I/O")
	}
}

func TestBrowserClaimUnitAppendsExactLifecycleEvidenceAndNeverRetriesCommit(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"confirmed", "unknown commit", "bad ID", "bad version", "bad hash", "expired after audit lock", "append failed", "bad appended sequence"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			command := authClaimCommandFixture(t)
			database := newFakeAuthTransactionDatabaseTransaction()
			snapshot := command.Snapshot()
			at := snapshot.CreatedAt().Add(time.Second)
			database.enqueueRow(claimAuthTransactionSQL, authTransactionTestRow{scan: func(destinations ...any) error {
				*destinations[0].(*string) = snapshot.TransactionID().String()
				*destinations[1].(*int64) = 2
				*destinations[2].(*time.Time), *destinations[3].(*time.Time), *destinations[4].(*time.Time) = snapshot.CreatedAt(), snapshot.ExpiresAt(), at
				hash := snapshot.SemanticHash()
				*destinations[5].(*[]byte) = hash[:]
				switch name {
				case "bad ID":
					*destinations[0].(*string) = "01890f00-0000-7000-8000-000000000051"
				case "bad version":
					*destinations[1].(*int64) = 1
				case "bad hash":
					*destinations[5].(*[]byte) = make([]byte, 31)
				}
				return nil
			}})
			database.enqueueRow(lockAuthTransactionAuditStreamSQL, authTransactionTestRow{scan: func(destinations ...any) error {
				*destinations[0].(*int64), *destinations[1].(*int64), *destinations[2].(*[]byte) = 51, 7, make([]byte, 32)
				return nil
			}})
			database.enqueueRow(authClaimClockSQL, authTransactionTestRow{scan: func(destinations ...any) error {
				if name == "expired after audit lock" {
					*destinations[0].(*time.Time) = snapshot.ExpiresAt()
				} else {
					*destinations[0].(*time.Time) = at
				}
				return nil
			}})
			database.enqueueRow(appendAuthClaimEvidenceSQL, authTransactionTestRow{scan: func(destinations ...any) error {
				*destinations[0].(*int64) = 7
				if name == "bad appended sequence" {
					*destinations[0].(*int64) = 8
				}
				return nil
			}})
			if name == "append failed" {
				database.rows[appendAuthClaimEvidenceSQL] = []authTransactionRow{authTransactionTestRow{err: errors.New("synthetic append failure")}}
			}
			if name == "unknown commit" {
				database.commitErr = errors.New("synthetic lost commit ACK")
			}
			unit := newAuthClaimTransaction(database, snapshot.Route(), nil)
			claimed, err := unit.Claim(t.Context(), command)
			if name != "confirmed" && name != "unknown commit" {
				if err == nil || claimed.IsValid() {
					t.Fatal("invalid claim returned evidence")
				}
				if unit.Commit(t.Context()) == nil || database.commitCalls != 0 {
					t.Fatal("failed claim committed")
				}
				if err := unit.Rollback(t.Context()); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil || !claimed.IsValid() {
				t.Fatal(err)
			}
			calls := database.calls
			if len(calls) != 5 || calls[2].query != lockAuthTransactionAuditStreamSQL || calls[3].query != authClaimClockSQL || calls[4].query != appendAuthClaimEvidenceSQL {
				t.Fatal("audit lock/expiry/evidence order changed")
			}
			args := calls[4].arguments
			before, after := claimed.BeforeSemanticHash(), claimed.AfterSemanticHash()
			if args[1] != command.MutationIDs().AuditEventID().String() || args[2] != command.MutationIDs().OutboxEventID().String() || args[7] != int64(2) || string(args[9].([]byte)) != string(before[:]) || string(args[10].([]byte)) != string(after[:]) {
				t.Fatal("claim evidence mismatched IDs/version/hashes")
			}
			err = unit.Commit(t.Context())
			if name == "unknown commit" && !errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) {
				t.Fatal("uncertain Commit lost classification")
			}
			if name == "confirmed" && err != nil {
				t.Fatal(err)
			}
			if unit.Commit(t.Context()) == nil || database.commitCalls != 1 {
				t.Fatal("Commit was retried")
			}
			if err := unit.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if name == "unknown commit" && database.rollbackCalls != 1 {
				t.Fatal("uncertain owned resource not cleaned up")
			}
		})
	}
}

func authClaimCommandFixture(t *testing.T) oidcauth.ClaimCommand {
	t.Helper()
	verified := authClaimVerifiedFixture(t)
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	command, err := oidcauth.NewClaimCommand(verified, ids)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func authClaimVerifiedFixture(t *testing.T) oidcauth.VerifiedBrowser {
	t.Helper()
	pending, secrets := authTransactionBrowserFixture(t)
	snapshot, err := oidcauth.NewPendingSnapshot(oidcauth.PendingSnapshotParams{
		TransactionID: pending.TransactionID(), Route: pending.Route(), Version: 1, State: "pending", FlowKind: "browser_authorization_code", OperationKind: "login",
		StateDigest: pending.StateDigest(), NonceDigest: pending.NonceDigest(), VerifierCiphertext: pending.VerifierCiphertext(), SemanticHash: pending.SemanticHash(), CreatedAt: pending.CreatedAt(), ExpiresAt: pending.ExpiresAt(),
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := oidcauth.NewDigestKeyID("oidc-digest-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := oidcauth.NewDigestKey(keyID, bytesOf(0x41, 32))
	if err != nil {
		t.Fatal(err)
	}
	cipherID, err := oidcauth.NewVerifierEncryptionKeyID("oidc-verifier-v1")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherID, bytesOf(0x52, 32))
	if err != nil {
		t.Fatal(err)
	}
	state, cookie := secrets.State(), secrets.PreAuthCookie()
	service, err := oidcauth.NewBrowserVerificationService(oidcauth.BrowserVerificationOptions{RequestTimeout: time.Second}, oidcauth.BrowserVerificationDependencies{Pending: authClaimLoader{snapshot}, DigestKey: key, VerifierCipher: cipher, Clock: authClaimClock{snapshot.CreatedAt().Add(time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyBrowser(t.Context(), pending.Route(), state, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

type authClaimLoader struct{ snapshot oidcauth.PendingSnapshot }

func (loader authClaimLoader) LoadPending(context.Context, oidcauth.Route, oidcauth.Digest) (oidcauth.PendingSnapshot, bool, error) {
	return loader.snapshot, true, nil
}

type authClaimClock struct{ at time.Time }

func (clock authClaimClock) Now() time.Time { return clock.at }
