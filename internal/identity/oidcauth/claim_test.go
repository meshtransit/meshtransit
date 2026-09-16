package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestClaimBrowserReleasesOnlyConfirmedReceipt(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"confirmed", "unknown commit", "claim failure", "malformed evidence", "future claim timestamp", "canceled before claim", "expired before claim", "canceled after commit", "expired after commit", "clock backwards after commit", "cleanup failure", "begin error with owned unit", "zero proof"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			verified := claimVerifiedFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			unit := &claimTestUnit{snapshot: verified.Snapshot(), now: verified.Snapshot().CreatedAt().Add(time.Second)}
			beginErr := error(nil)
			switch name {
			case "unknown commit":
				unit.commitErr = ErrCommitOutcomeUnknown
			case "claim failure":
				unit.claimErr = errors.New("synthetic private failure")
			case "malformed evidence":
				unit.malformed = true
			case "future claim timestamp":
				unit.claimAt = unit.now.Add(time.Second)
			case "canceled before claim":
				cancel()
			case "expired before claim":
				unit.now = verified.Snapshot().ExpiresAt()
			case "canceled after commit":
				unit.afterCommit = cancel
			case "expired after commit":
				unit.afterCommit = func() { unit.now = verified.Snapshot().ExpiresAt() }
			case "clock backwards after commit":
				unit.afterCommit = func() { unit.now = unit.now.Add(-time.Microsecond) }
			case "cleanup failure":
				unit.claimErr = errors.New("synthetic private failure")
				unit.rollbackErr = errors.New("synthetic cleanup failure")
			case "begin error with owned unit":
				beginErr = errors.New("synthetic begin failure")
			case "zero proof":
				verified = VerifiedBrowser{}
			}
			store := &claimTestTransactions{unit: unit, beginErr: beginErr}
			service, err := NewClaimService(ClaimOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}, ClaimDependencies{
				Transactions: store, IDs: SystemClaimIDs{}, Clock: browserVerificationClock{now: func() time.Time { return unit.now }},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.ClaimBrowser(ctx, verified)
			if name == "confirmed" {
				if err != nil || !result.IsValid() || result.Claimed().Version() != 2 || unit.commits != 1 || unit.rollbacks != 0 {
					t.Fatalf("confirmed claim: %v", err)
				}
				if fmt.Sprintf("%v %#+v", result, result) != "[REDACTED] oidcauth.ClaimResult([REDACTED])" {
					t.Fatal("receipt disclosed evidence")
				}
			} else {
				if err == nil || result.IsValid() {
					t.Fatal("unconfirmed claim released receipt")
				}
				if name == "unknown commit" && (!errors.Is(err, ErrCommitOutcomeUnknown) || unit.commits != 1 || unit.rollbacks != 1 || store.begins != 1) {
					t.Fatal("unknown claim retried or lost classification")
				}
				if name == "zero proof" && store.begins != 0 {
					t.Fatal("invalid proof reached database")
				}
				if name == "cleanup failure" && !errors.Is(err, ErrClaimCleanupFailed) {
					t.Fatal("cleanup classification lost")
				}
				if (name == "canceled before claim" || name == "expired before claim") && store.begins != 0 {
					t.Fatal("nonlive proof reached database")
				}
				if name == "future claim timestamp" && unit.commits != 0 {
					t.Fatal("future claim evidence committed")
				}
				if name == "begin error with owned unit" && unit.rollbacks != 1 {
					t.Fatal("owned begin resource leaked")
				}
				if name == "malformed evidence" && unit.commits != 0 {
					t.Fatal("malformed evidence committed")
				}
			}
		})
	}
}

func TestClaimCommandAndLifecycleEvidenceRejectInvalidBindings(t *testing.T) {
	t.Parallel()
	if (Claimed{}).BeforeSemanticHash() != ([32]byte{}) || (Claimed{}).AfterSemanticHash() != ([32]byte{}) || (Claimed{}).Version() != 0 {
		t.Fatal("zero claim manufactured evidence")
	}
	verified := claimVerifiedFixture(t)
	ids, err := (SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewClaimCommand(verified, ids)
	if err != nil || !command.IsValid() {
		t.Fatal("valid command rejected")
	}
	claimed, err := NewClaimed(command.Snapshot(), 2, command.Snapshot().CreatedAt().Add(time.Second))
	if err != nil || !claimed.IsValid() || claimed.BeforeSemanticHash() == claimed.AfterSemanticHash() || claimed.AfterSemanticHash() == command.Snapshot().SemanticHash() {
		t.Fatal("lifecycle hashes not separated")
	}
	for _, at := range []time.Time{command.Snapshot().CreatedAt().Add(-time.Second), command.Snapshot().ExpiresAt(), command.Snapshot().CreatedAt().Add(time.Nanosecond)} {
		if _, err := NewClaimed(command.Snapshot(), 2, at); err == nil {
			t.Fatal("invalid claim time accepted")
		}
	}
	if _, err := NewClaimed(command.Snapshot(), 1, claimed.ConsumedAt()); err == nil {
		t.Fatal("pending version accepted as claim")
	}
	if _, err := NewClaimCommand(VerifiedBrowser{}, ids); err == nil {
		t.Fatal("unverified claim accepted")
	}
	if _, err := NewClaimCommand(verified, MutationIDs{}); err == nil {
		t.Fatal("missing evidence IDs accepted")
	}
}

func claimVerifiedFixture(t *testing.T) VerifiedBrowser {
	t.Helper()
	params := pendingParamsFixture(t)
	snapshot, err := NewPendingSnapshot(snapshotParamsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewBrowserVerificationService(BrowserVerificationOptions{RequestTimeout: time.Second}, BrowserVerificationDependencies{
		Pending:   browserVerificationLoader{load: func(context.Context, Route, Digest) (PendingSnapshot, bool, error) { return snapshot, true, nil }},
		DigestKey: params.DigestKey, VerifierCipher: params.VerifierCipher,
		Clock: browserVerificationClock{now: func() time.Time { return snapshot.CreatedAt().Add(time.Second) }},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyBrowser(t.Context(), params.Route, params.Secrets.State(), params.Secrets.PreAuthCookie())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

type claimTestTransactions struct {
	unit     *claimTestUnit
	beginErr error
	begins   int
}

func (store *claimTestTransactions) BeginClaim(context.Context, Route) (ClaimTransaction, error) {
	store.begins++
	return store.unit, store.beginErr
}

type claimTestUnit struct {
	snapshot                         PendingSnapshot
	now, claimAt                     time.Time
	claimErr, commitErr, rollbackErr error
	malformed                        bool
	afterCommit                      func()
	commits, rollbacks               int
}

func (unit *claimTestUnit) Claim(_ context.Context, command ClaimCommand) (Claimed, error) {
	if unit.claimErr != nil {
		return Claimed{}, unit.claimErr
	}
	if unit.malformed {
		return Claimed{}, nil
	}
	at := unit.now
	if !unit.claimAt.IsZero() {
		at = unit.claimAt
	}
	return NewClaimed(command.Snapshot(), 2, at)
}
func (unit *claimTestUnit) Commit(context.Context) error {
	unit.commits++
	if unit.afterCommit != nil {
		unit.afterCommit()
	}
	return unit.commitErr
}
func (unit *claimTestUnit) Rollback(ctx context.Context) error {
	unit.rollbacks++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("unbounded cleanup")
	}
	return unit.rollbackErr
}
