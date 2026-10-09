package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFailureBrowserConfirmedOnlyAndOneAttempt(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"confirmed", "expired", "bounded clock skew", "unknown commit", "apply failure", "malformed", "canceled", "canceled after commit", "cleanup failure", "owned begin error", "zero receipt"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			receipt := failureReceiptFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			unit := &failureTestUnit{at: receipt.Claimed().ConsumedAt().Add(time.Second)}
			store := &failureTestTransactions{unit: unit}
			now := unit.at
			switch name {
			case "expired":
				unit.at = receipt.claimed.snapshot.ExpiresAt()
				now = unit.at
			case "bounded clock skew":
				now = receipt.Claimed().ConsumedAt()
			case "unknown commit":
				unit.commitErr = ErrCommitOutcomeUnknown
			case "apply failure":
				unit.applyErr = errors.New("private-secret")
			case "malformed":
				unit.malformed = true
			case "canceled":
				cancel()
			case "canceled after commit":
				unit.afterCommit = cancel
			case "cleanup failure":
				unit.applyErr, unit.rollbackErr = errors.New("private-secret"), errors.New("private-secret")
			case "owned begin error":
				store.err = errors.New("private-secret")
			case "zero receipt":
				receipt = ClaimResult{}
			}
			service, err := NewFailureService(FailureOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}, FailureDependencies{Transactions: store, IDs: SystemClaimIDs{}, Clock: browserVerificationClock{now: func() time.Time { return now }}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.FailBrowser(ctx, receipt)
			if name == "confirmed" || name == "expired" || name == "bounded clock skew" {
				if err != nil || !result.IsValid() || unit.commits != 1 || unit.rollbacks != 0 {
					t.Fatal("confirmed terminal missing", err)
				}
				if (name == "expired") != (result.Terminated().State() == "expired") {
					t.Fatal("terminal deadline classification")
				}
				if fmt.Sprintf("%v %#+v", result, result) != "[REDACTED] oidcauth.FailureResult([REDACTED])" {
					t.Fatal("disclosed receipt")
				}
			} else if err == nil || result.IsValid() || strings.Contains(err.Error(), "private-secret") {
				t.Fatal("unconfirmed terminal or private error released")
			}
			if name == "unknown commit" && (!errors.Is(err, ErrCommitOutcomeUnknown) || unit.commits != 1 || unit.rollbacks != 1) {
				t.Fatal("unknown commit retried or lost")
			}
			if name == "cleanup failure" && !errors.Is(err, ErrFailureCleanupFailed) {
				t.Fatal("cleanup classification")
			}
			if name == "owned begin error" && unit.rollbacks != 1 {
				t.Fatal("owned begin leaked")
			}
			if name == "malformed" && unit.commits != 0 {
				t.Fatal("malformed terminal committed")
			}
			if name == "canceled" || name == "zero receipt" {
				if store.begins != 0 {
					t.Fatal("invalid reached DB")
				}
				return
			}
			if !receipt.exchangeAttempt.Load() {
				t.Fatal("unused exchange not burned")
			}
			if next, err := service.FailBrowser(t.Context(), receipt); err == nil || next.IsValid() || store.begins != 1 {
				t.Fatal("copy retried failure attempt")
			}
		})
	}
}

func TestFailureEvidenceRejectsInvalidBindings(t *testing.T) {
	t.Parallel()
	receipt := failureReceiptFixture(t)
	ids, err := (SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewFailureCommand(receipt, ids)
	if err != nil || !command.IsValid() {
		t.Fatal("valid command rejected")
	}
	for _, at := range []time.Time{{}, receipt.Claimed().ConsumedAt().Add(-time.Microsecond), receipt.Claimed().ConsumedAt().Add(time.Nanosecond)} {
		if _, err := NewTerminated(command.Claimed(), 3, "failed", "authentication_failed", at); err == nil {
			t.Fatal("bad terminal timestamp accepted")
		}
	}
	for _, bad := range []struct {
		version      int64
		state, class string
	}{{2, "failed", "authentication_failed"}, {3, "succeeded", "authentication_failed"}, {3, "failed", "raw_error"}, {3, "expired", "deadline_expired"}} {
		if _, err := NewTerminated(command.Claimed(), bad.version, bad.state, bad.class, receipt.Claimed().ConsumedAt()); err == nil {
			t.Fatal("bad terminal binding accepted")
		}
	}
	if _, err := NewFailureCommand(ClaimResult{}, ids); err == nil {
		t.Fatal("unconfirmed command accepted")
	}
	if (Terminated{}).AfterSemanticHash() != ([32]byte{}) {
		t.Fatal("zero terminal hash")
	}
	first, err := NewTerminated(command.Claimed(), 3, "failed", "authentication_failed", receipt.Claimed().ConsumedAt())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTerminated(command.Claimed(), 3, "failed", "authentication_failed", first.TerminatedAt().Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if first.BeforeSemanticHash() != command.Claimed().AfterSemanticHash() || first.AfterSemanticHash() == first.BeforeSemanticHash() || first.AfterSemanticHash() == second.AfterSemanticHash() {
		t.Fatal("terminal lifecycle hash separation")
	}
	if fmt.Sprintf("%v %#+v", command, command) != "[REDACTED] oidcauth.FailureCommand([REDACTED])" || fmt.Sprintf("%v %#+v", first, first) != "[REDACTED] oidcauth.Terminated([REDACTED])" {
		t.Fatal("terminal evidence formatting disclosed")
	}
}

func TestFailureConstructionAndConcurrentReceiptCopies(t *testing.T) {
	t.Parallel()
	receipt := failureReceiptFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	unit := &failureTestUnit{at: receipt.Claimed().ConsumedAt().Add(time.Second)}
	store := &failureBlockingTransactions{unit: unit, entered: entered, release: release}
	dependencies := FailureDependencies{Transactions: store, IDs: SystemClaimIDs{}, Clock: browserVerificationClock{now: func() time.Time { return unit.at }}}
	for _, options := range []FailureOptions{{}, {RequestTimeout: 31 * time.Second, RollbackTimeout: time.Second}, {RequestTimeout: time.Second, RollbackTimeout: 6 * time.Second}} {
		if _, err := NewFailureService(options, dependencies); err == nil {
			t.Fatal("unsafe budget accepted")
		}
	}
	options := FailureOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}
	service, err := NewFailureService(options, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := service.FailBrowser(t.Context(), receipt); finished <- err }()
	<-entered
	if result, err := service.FailBrowser(t.Context(), receipt); err == nil || result.IsValid() {
		t.Error("concurrent receipt queued a second DB unit")
	}
	close(release)
	if err := <-finished; err != nil || unit.commits != 1 {
		t.Fatal("original terminal failed", err)
	}
}

type failureBlockingTransactions struct {
	unit             *failureTestUnit
	entered, release chan struct{}
}

func (store *failureBlockingTransactions) BeginFailure(ctx context.Context, _ Route) (FailureTransaction, error) {
	close(store.entered)
	select {
	case <-store.release:
		return store.unit, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func failureReceiptFixture(t *testing.T) ClaimResult {
	t.Helper()
	verified := claimVerifiedFixture(t)
	unit := &claimTestUnit{snapshot: verified.Snapshot(), now: verified.Snapshot().CreatedAt().Add(time.Second)}
	service, err := NewClaimService(ClaimOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}, ClaimDependencies{Transactions: &claimTestTransactions{unit: unit}, IDs: SystemClaimIDs{}, Clock: browserVerificationClock{now: func() time.Time { return unit.now }}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ClaimBrowser(t.Context(), verified)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type failureTestTransactions struct {
	unit   *failureTestUnit
	err    error
	begins int
}

func (store *failureTestTransactions) BeginFailure(context.Context, Route) (FailureTransaction, error) {
	store.begins++
	return store.unit, store.err
}

type failureTestUnit struct {
	at                               time.Time
	applyErr, commitErr, rollbackErr error
	malformed                        bool
	afterCommit                      func()
	commits, rollbacks               int
}

func (unit *failureTestUnit) Fail(_ context.Context, command FailureCommand) (Terminated, error) {
	if unit.applyErr != nil {
		return Terminated{}, unit.applyErr
	}
	if unit.malformed {
		return Terminated{}, nil
	}
	state, class := "failed", "authentication_failed"
	if !unit.at.Before(command.Claimed().snapshot.ExpiresAt()) {
		state, class = "expired", "deadline_expired"
	}
	return NewTerminated(command.Claimed(), 3, state, class, unit.at)
}
func (unit *failureTestUnit) Commit(context.Context) error {
	unit.commits++
	if unit.afterCommit != nil {
		unit.afterCommit()
	}
	return unit.commitErr
}
func (unit *failureTestUnit) Rollback(ctx context.Context) error {
	unit.rollbacks++
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return errors.New("unbounded/canceled cleanup")
	}
	return unit.rollbackErr
}
