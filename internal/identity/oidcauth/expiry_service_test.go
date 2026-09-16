package oidcauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
)

func TestExpiryServiceOwnsOnlyOneAttemptAndJoinedCleanup(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"confirmed", "unknown", "apply error", "substitution", "owned begin error", "cleanup error",
		"canceled", "cancel after commit", "entropy error", "future DB time",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := expirySnapshotFixture(t, false)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			unit := &expiryTestUnit{at: snapshot.ExpiresAt(), onRollback: func(cleanup context.Context) {
				if cleanup.Err() != nil {
					t.Error("rollback inherited cancellation")
				}
				if _, ok := cleanup.Deadline(); !ok {
					t.Error("rollback unbounded")
				}
			}}
			owner := &expiryTestStore{unit: unit}
			var ids ClaimIDGenerator = SystemClaimIDs{}
			switch name {
			case "unknown":
				unit.commitErr = ErrCommitOutcomeUnknown
			case "apply error":
				unit.applyErr = errors.New("private-detail")
			case "substitution":
				unit.substitute = true
			case "owned begin error":
				owner.beginErr = errors.New("private-detail")
			case "cleanup error":
				unit.applyErr, unit.rollbackErr = errors.New("private-detail"), errors.New("private-detail")
			case "canceled":
				cancel()
			case "cancel after commit":
				unit.onCommit = cancel
			case "entropy error":
				ids = expiryBrokenIDs{}
			case "future DB time":
				unit.at = unit.at.Add(time.Microsecond)
			}
			service := expiryServiceFixture(t, owner, ids, snapshot.ExpiresAt())
			result, err := service.Expire(ctx, snapshot)
			if name == "confirmed" {
				if err != nil || !result.IsValid() || unit.commits != 1 || unit.rollbacks != 0 {
					t.Fatal("confirmed expiry missing", err)
				}
				return
			}
			if err == nil || result.IsValid() || strings.Contains(err.Error(), "private-detail") {
				t.Fatal("failure released receipt/details")
			}
			if name == "canceled" || name == "entropy error" {
				if owner.begins != 0 {
					t.Fatal("invalid preparation reached Begin")
				}
				return
			}
			if name == "cancel after commit" {
				if unit.commits != 1 || unit.rollbacks != 0 {
					t.Fatal("confirmed canceled Commit retried")
				}
				return
			}
			if unit.rollbacks != 1 {
				t.Fatal("owned unit not joined exactly once")
			}
			if name == "unknown" && (!errors.Is(err, ErrCommitOutcomeUnknown) || unit.commits != 1) {
				t.Fatal("unknown classified/retried incorrectly")
			}
			if name == "cleanup error" && !errors.Is(err, ErrExpiryCleanupFailed) {
				t.Fatal("cleanup failure lost")
			}
			if name == "substitution" || name == "future DB time" {
				if unit.commits != 0 {
					t.Fatal("malformed DB evidence committed")
				}
			}
		})
	}
}

func TestExpiryPassValidatesWholeBatchAndStopsOnUnknown(t *testing.T) {
	t.Parallel()
	snapshot := expirySnapshotFixture(t, false)
	for _, name := range []string{"empty", "duplicate", "invalid", "overflow", "wrong deployment", "unknown"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			owner := &expiryTestStore{unit: &expiryTestUnit{at: snapshot.ExpiresAt()}, batch: []ExpirySnapshot{snapshot}}
			dep := snapshot.DeploymentID()
			switch name {
			case "empty":
				owner.batch = nil
			case "duplicate":
				owner.batch = append(owner.batch, snapshot)
			case "invalid":
				owner.batch = append(owner.batch, ExpirySnapshot{})
			case "overflow":
				owner.batch = make([]ExpirySnapshot, 3)
			case "wrong deployment":
				dep = deployment.ID{}
			case "unknown":
				params := snapshot.Params()
				params.TransactionID[15]--
				other, err := NewExpirySnapshot(params)
				if err != nil {
					t.Fatal(err)
				}
				owner.batch = append(owner.batch, other)
				owner.unit.commitErr = ErrCommitOutcomeUnknown
			}
			service := expiryServiceFixture(t, owner, SystemClaimIDs{}, snapshot.ExpiresAt())
			pass, err := service.Sweep(t.Context(), dep)
			if name == "empty" {
				if err != nil || pass != (ExpiryPass{}) || owner.begins != 0 {
					t.Fatal("empty pass mutated")
				}
				return
			}
			if err == nil || pass.Confirmed != 0 {
				t.Fatal("invalid batch confirmed work")
			}
			if name == "unknown" {
				if !errors.Is(err, ErrCommitOutcomeUnknown) || owner.begins != 1 || pass.Attempted != 1 {
					t.Fatal("unknown did not end pass")
				}
			} else if owner.begins != 0 {
				t.Fatal("whole batch was not checked before writes")
			}
		})
	}
}

func TestExpiryPassPreservesClosedCleanupFailureFromListAndSetup(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"list", "begin"} {
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			snapshot := expirySnapshotFixture(t, false)
			owner := &expiryTestStore{batch: []ExpirySnapshot{snapshot}}
			failure := errors.Join(ErrExpiryCleanupFailed, errors.New("private-detail"))
			if phase == "list" {
				owner.listErr = failure
			} else {
				owner.beginErr = failure
			}
			service := expiryServiceFixture(t, owner, SystemClaimIDs{}, snapshot.ExpiresAt())
			pass, err := service.Sweep(t.Context(), snapshot.DeploymentID())
			if !errors.Is(err, ErrExpiryCleanupFailed) || pass.Confirmed != 0 ||
				strings.Contains(err.Error(), "private-detail") {
				t.Fatal("cleanup ownership class lost or dependency text exposed")
			}
		})
	}
}

func TestExpiryPassTimeoutIsFinite(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		snapshot := expirySnapshotFixture(t, false)
		owner := &expiryTestStore{onList: func(ctx context.Context) { <-ctx.Done() }}
		service := expiryServiceFixture(t, owner, SystemClaimIDs{}, snapshot.ExpiresAt())
		if _, err := service.Sweep(t.Context(), snapshot.DeploymentID()); !errors.Is(err, context.DeadlineExceeded) || owner.begins != 0 {
			t.Fatal("pass lost bounded cancellation")
		}
	})
}

func TestExpiryRejectsZeroServicesAndTypedNilPorts(t *testing.T) {
	t.Parallel()
	snapshot := expirySnapshotFixture(t, false)
	var service ExpiryService
	if _, err := service.Expire(t.Context(), snapshot); !errors.Is(err, ErrInvalidExpiry) {
		t.Fatal("zero service admitted effects")
	}
	if _, err := service.Sweep(t.Context(), snapshot.DeploymentID()); !errors.Is(err, ErrInvalidExpiry) {
		t.Fatal("zero sweep admitted effects")
	}
	var missing *expiryTestStore
	deps := ExpiryDependencies{Candidates: missing, Transactions: missing, IDs: SystemClaimIDs{}, Clock: SystemStartClock{}}
	options := ExpiryOptions{BatchSize: 1, PassTimeout: time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second}
	if service, err := NewExpiryService(options, deps); err == nil || service != nil {
		t.Fatal("typed-nil ports accepted")
	}
	owner := &expiryTestStore{}
	servicePointer := expiryServiceFixture(t, owner, SystemClaimIDs{}, snapshot.ExpiresAt())
	if result, err := servicePointer.Expire(t.Context(), snapshot); err == nil || result.IsValid() || owner.begins != 1 {
		t.Fatal("typed-nil owned unit released evidence")
	}
}

func TestExpiryOptionsAndIDsRejectUnsafeSetup(t *testing.T) {
	t.Parallel()
	owner := &expiryTestStore{}
	deps := ExpiryDependencies{Candidates: owner, Transactions: owner, IDs: SystemClaimIDs{}, Clock: SystemStartClock{}}
	for _, options := range []ExpiryOptions{
		{}, {BatchSize: 129, PassTimeout: time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second},
		{BatchSize: 1, PassTimeout: 31 * time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second},
		{BatchSize: 1, PassTimeout: time.Second, UnitTimeout: 31 * time.Second, RollbackTimeout: time.Second},
		{BatchSize: 1, PassTimeout: time.Second, UnitTimeout: time.Second, RollbackTimeout: 6 * time.Second},
	} {
		if service, err := NewExpiryService(options, deps); err == nil || service != nil {
			t.Fatal("unsafe setup accepted")
		}
	}
	snapshot := expirySnapshotFixture(t, false)
	ids, err := (SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewExpiryCommand(ExpirySnapshot{}, ids); err == nil {
		t.Fatal("zero snapshot accepted")
	}
	if _, err := NewExpiryCommand(snapshot, MutationIDs{}); err == nil {
		t.Fatal("zero evidence IDs accepted")
	}
	if (Expired{}).AfterSemanticHash() != ([32]byte{}) {
		t.Fatal("invalid terminal produced hash")
	}
}

func expiryServiceFixture(t *testing.T, owner *expiryTestStore, ids ClaimIDGenerator, now time.Time) *ExpiryService {
	t.Helper()
	service, err := NewExpiryService(ExpiryOptions{BatchSize: 2, PassTimeout: time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second},
		ExpiryDependencies{Candidates: owner, Transactions: owner, IDs: ids, Clock: browserVerificationClock{now: func() time.Time { return now }}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type expiryBrokenIDs struct{}

func (expiryBrokenIDs) NewClaimIDs() (MutationIDs, error) {
	return MutationIDs{}, errors.New("private-detail")
}

type expiryTestStore struct {
	unit     *expiryTestUnit
	batch    []ExpirySnapshot
	beginErr error
	listErr  error
	begins   int
	onList   func(context.Context)
}

func (store *expiryTestStore) ListDue(ctx context.Context, _ deployment.ID, _ int) ([]ExpirySnapshot, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded list")
	}
	if store.onList != nil {
		store.onList(ctx)
	}
	return store.batch, errors.Join(store.listErr, ctx.Err())
}
func (store *expiryTestStore) BeginExpiry(ctx context.Context, _ deployment.ID) (ExpiryTransaction, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded unit")
	}
	store.begins++
	return store.unit, store.beginErr
}

type expiryTestUnit struct {
	at                               time.Time
	applyErr, commitErr, rollbackErr error
	substitute                       bool
	commits, rollbacks               int
	onRollback                       func(context.Context)
	onCommit                         func()
}

func (unit *expiryTestUnit) Expire(_ context.Context, command ExpiryCommand) (Expired, error) {
	if unit.applyErr != nil {
		return Expired{}, unit.applyErr
	}
	snapshot := command.Snapshot()
	if unit.substitute {
		params := snapshot.Params()
		params.TransactionID[15]--
		snapshot = ExpirySnapshot{params: params}
	}
	return NewExpired(snapshot, unit.at)
}
func (unit *expiryTestUnit) Commit(context.Context) error {
	unit.commits++
	if unit.onCommit != nil {
		unit.onCommit()
	}
	return unit.commitErr
}
func (unit *expiryTestUnit) Rollback(ctx context.Context) error {
	unit.rollbacks++
	if unit.onRollback != nil {
		unit.onRollback(ctx)
	}
	return unit.rollbackErr
}
