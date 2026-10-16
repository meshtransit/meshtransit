package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/node/revocation"
)

func TestDeviceRevocationTransactionPersistsAtomicTerminalEvidence(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	attempt := deviceRevocationAttemptFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueNewDeviceRevocationResolution(t, databaseTransaction, command, attempt)
	enqueueDeviceRevocationApply(
		databaseTransaction,
		attempt.MutationIDs().IdempotencyRecordID(),
	)
	store := beginTestDeviceRevocationStore(t, databaseTransaction)

	transaction, err := store.Begin(context.Background(), command.Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	resolution, err := transaction.Resolve(context.Background(), command, attempt)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change, err := revocation.NewChange(command, resolution, attempt)
	if err != nil {
		t.Fatalf("revocation.NewChange() error = %v", err)
	}
	result, err := transaction.Apply(context.Background(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if result.IdempotencyRecordID() != attempt.MutationIDs().IdempotencyRecordID() ||
		result.NodeID() != command.NodeID() || result.DeviceVersion() != 2 ||
		result.SessionGeneration() != 2 || result.NetworkRevision() != 6 ||
		result.InventoryRevision() != 8 {
		t.Fatalf("Apply() result = %#v, want exact terminal revisions", result)
	}
	if databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf(
			"database close calls = commit %d rollback %d, want 1/0",
			databaseTransaction.commitCalls,
			databaseTransaction.rollbackCalls,
		)
	}
	wantQueries := []string{
		configureDeviceRevocationTransactionSQL,
		setDeviceRevocationScopeSQL,
		authorizeDeviceRevocationSQL,
		claimDeviceRevocationIdempotencySQL,
		lockDeviceRevocationRevisionSQL,
		lockDeviceRevocationTargetSQL,
		lockDeviceRevocationAuditStreamSQL,
		setDeviceRevocationChangeSQL,
		revokeDeviceSQL,
		revokeMachineKeyEpochSQL,
		revokeNodeKeyEpochSQL,
		quarantineRevokedDeviceLeasesSQL,
		advanceDeviceRevocationRevisionSQL,
		appendDeviceRevocationEvidenceSQL,
		completeDeviceRevocationIdempotencySQL,
	}
	if got := deviceRevocationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("query order = %#v, want %#v", got, wantQueries)
	}

	completeCall := databaseTransaction.calls[len(databaseTransaction.calls)-1]
	if got := completeCall.arguments[1]; got != command.ActorPrincipalID().String() {
		t.Fatalf("complete actor = %v, want %s", got, command.ActorPrincipalID())
	}
	if got := completeCall.arguments[6]; got != deviceRevocationResultKind {
		t.Fatalf("complete result kind = %v, want %q", got, deviceRevocationResultKind)
	}
}

func TestDeviceRevocationResolveReturnsCompletedReplayWithoutAuthorityLocks(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	attempt := deviceRevocationAttemptFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueDeviceRevocationSetup(databaseTransaction)
	enqueueDeviceRevocationAuthorization(databaseTransaction, attempt.OccurredAt())
	enqueueCompletedDeviceRevocationRecord(
		t,
		databaseTransaction,
		claimDeviceRevocationIdempotencySQL,
		command,
		attempt.MutationIDs().IdempotencyRecordID(),
		attempt.ExpiresAt(),
		true,
	)
	store := beginTestDeviceRevocationStore(t, databaseTransaction)

	transaction, err := store.Begin(context.Background(), command.Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	resolution, err := transaction.Resolve(context.Background(), command, attempt)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	result, found := resolution.CompletedResult()
	if !found || result.NetworkRevision() != 6 || result.InventoryRevision() != 8 {
		t.Fatalf("CompletedResult() = %#v, %t, want revisions 6/8", result, found)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	wantQueries := []string{
		configureDeviceRevocationTransactionSQL,
		setDeviceRevocationScopeSQL,
		authorizeDeviceRevocationSQL,
		claimDeviceRevocationIdempotencySQL,
	}
	if got := deviceRevocationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("replay query order = %#v, want %#v", got, wantQueries)
	}
}

func TestDeviceRevocationResolveRejectsIdempotencyIntentConflict(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	attempt := deviceRevocationAttemptFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueDeviceRevocationSetup(databaseTransaction)
	enqueueDeviceRevocationAuthorization(databaseTransaction, attempt.OccurredAt())
	databaseTransaction.enqueueRow(claimDeviceRevocationIdempotencySQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = attempt.MutationIDs().IdempotencyRecordID().String()
			*destinations[1].(*[]byte) = make([]byte, 32)
			(*destinations[1].(*[]byte))[31] = 9
			*destinations[2].(*string) = "completed"
			*destinations[3].(*string) = deviceRevocationResultKind
			*destinations[4].(*string) = command.NodeID().String()
			*destinations[5].(*int64) = 2
			*destinations[6].(*int64) = 6
			*destinations[7].(*string) = "{}"
			*destinations[8].(*time.Time) = attempt.ExpiresAt()
			*destinations[9].(*bool) = false
			return nil
		},
	})
	store := beginTestDeviceRevocationStore(t, databaseTransaction)

	transaction, err := store.Begin(context.Background(), command.Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := transaction.Resolve(context.Background(), command, attempt); !errors.Is(err, revocation.ErrIntentConflict) {
		t.Fatalf("Resolve() error = %v, want ErrIntentConflict", err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestDeviceRevocationResolveHidesMissingTarget(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	attempt := deviceRevocationAttemptFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueDeviceRevocationSetup(databaseTransaction)
	enqueueDeviceRevocationAuthorization(databaseTransaction, attempt.OccurredAt())
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	databaseTransaction.enqueueRow(claimDeviceRevocationIdempotencySQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = attempt.MutationIDs().IdempotencyRecordID().String()
			hash := requestHash.Bytes()
			*destinations[1].(*[]byte) = append([]byte(nil), hash[:]...)
			*destinations[2].(*string) = "pending"
			*destinations[3].(*string) = ""
			*destinations[4].(*string) = ""
			*destinations[5].(*int64) = 0
			*destinations[6].(*int64) = 0
			*destinations[7].(*string) = "{}"
			*destinations[8].(*time.Time) = attempt.ExpiresAt()
			*destinations[9].(*bool) = true
			return nil
		},
	})
	databaseTransaction.enqueueRow(lockDeviceRevocationRevisionSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			for index := range destinations {
				*destinations[index].(*int64) = 1
			}
			return nil
		},
	})
	databaseTransaction.enqueueRow(
		lockDeviceRevocationTargetSQL,
		deviceRevocationTestRow{err: pgx.ErrNoRows},
	)
	store := beginTestDeviceRevocationStore(t, databaseTransaction)

	transaction, err := store.Begin(context.Background(), command.Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := transaction.Resolve(context.Background(), command, attempt); !errors.Is(err, revocation.ErrNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrNotFound", err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestDeviceRevocationStoreResolveCommittedReauthorizesInScopedTransaction(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	attempt := deviceRevocationAttemptFixture(t)
	recordID := deviceRevocationPublicIDFixture(t, "000000000901")
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueDeviceRevocationSetup(databaseTransaction)
	enqueueDeviceRevocationAuthorization(databaseTransaction, attempt.OccurredAt())
	enqueueCompletedDeviceRevocationRecord(
		t,
		databaseTransaction,
		loadDeviceRevocationIdempotencySQL,
		command,
		recordID,
		attempt.ExpiresAt(),
		false,
	)
	database := &fakeDeviceRevocationDatabase{
		transactions: []*fakeDeviceRevocationTransaction{databaseTransaction},
	}
	store, err := newDeviceRevocationStore(database, testDeviceRevocationOptions(), nil)
	if err != nil {
		t.Fatalf("newDeviceRevocationStore() error = %v", err)
	}

	result, found, err := store.ResolveCommitted(context.Background(), command, attempt.MutationIDs())
	if err != nil {
		t.Fatalf("ResolveCommitted() error = %v", err)
	}
	if !found || result.IdempotencyRecordID() != recordID {
		t.Fatalf("ResolveCommitted() = %#v, %t, want record %s", result, found, recordID)
	}
	if !reflect.DeepEqual(database.readOnly, []bool{false}) || databaseTransaction.commitCalls != 1 {
		t.Fatalf(
			"readOnly/commit = %#v/%d, want [false]/1",
			database.readOnly,
			databaseTransaction.commitCalls,
		)
	}
}

func TestDeviceRevocationResolveDeniesBeforeIdempotencyClaim(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	attempt := deviceRevocationAttemptFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueDeviceRevocationSetup(databaseTransaction)
	databaseTransaction.enqueueRow(
		authorizeDeviceRevocationSQL,
		deviceRevocationTestRow{err: pgx.ErrNoRows},
	)
	store := beginTestDeviceRevocationStore(t, databaseTransaction)

	transaction, err := store.Begin(context.Background(), command.Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := transaction.Resolve(context.Background(), command, attempt); !errors.Is(
		err,
		revocation.ErrForbidden,
	) {
		t.Fatalf("Resolve() error = %v, want ErrForbidden", err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	wantQueries := []string{
		configureDeviceRevocationTransactionSQL,
		setDeviceRevocationScopeSQL,
		authorizeDeviceRevocationSQL,
	}
	if got := deviceRevocationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("denied query order = %#v, want %#v", got, wantQueries)
	}
}

func TestNewDeviceRevocationStoreRejectsWorkerPool(t *testing.T) {
	t.Parallel()

	pool := &Pool{
		role:                     PoolRoleWorker,
		deviceRevocationDatabase: &fakeDeviceRevocationDatabase{},
	}
	if _, err := NewDeviceRevocationStore(pool, testDeviceRevocationOptions()); !errors.Is(err, ErrInvalidDeviceRevocationStore) {
		t.Fatalf("NewDeviceRevocationStore() error = %v, want ErrInvalidDeviceRevocationStore", err)
	}
}

func TestDeviceRevocationTransactionDecidesOnlyOnItsDatabaseTime(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	fixture := deviceRevocationAttemptFixture(t)
	hostAttempt, err := revocation.NewAttempt(
		fixture.MutationIDs(), fixture.OccurredAt().Add(200*time.Millisecond), fixture.ExpiresAt(),
	)
	if err != nil {
		t.Fatal(err)
	}
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueDeviceRevocationSetup(databaseTransaction)
	store := beginTestDeviceRevocationStore(t, databaseTransaction)
	transaction, err := store.Begin(context.Background(), command.Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if !transaction.DecisionTime().Equal(deviceRevocationFixtureTime) {
		t.Fatalf("DecisionTime() = %s, want the database time %s", transaction.DecisionTime(), deviceRevocationFixtureTime)
	}
	if _, err := transaction.Resolve(context.Background(), command, hostAttempt); !errors.Is(err, ErrDeviceRevocationState) {
		t.Fatalf("Resolve(attempt at another clock's time) error = %v, want ErrDeviceRevocationState", err)
	}
}

func TestDeviceRevocationStateMapsEveryStoredState(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]revocation.DeviceState{
		"active": revocation.DeviceStateActive, "suspended": revocation.DeviceStateSuspended,
		"expired": revocation.DeviceStateExpired, "revoked": revocation.DeviceStateRevoked,
		"deleted": revocation.DeviceStateDeleted,
	} {
		if got, err := deviceRevocationState(value); err != nil || got != want {
			t.Errorf("deviceRevocationState(%q) = %v, %v; want %v", value, got, err, want)
		}
	}
	if _, err := deviceRevocationState("paused"); !errors.Is(err, ErrDeviceRevocationEvidence) {
		t.Fatalf("unknown state: %v", err)
	}
}
