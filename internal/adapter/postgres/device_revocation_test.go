package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
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
		claimDeviceRevocationIdempotencySQL,
		lockDeviceRevocationRevisionSQL,
		lockDeviceRevocationTargetSQL,
		lockDeviceRevocationAuditStreamSQL,
		setDeviceRevocationChangeSQL,
		revokeDeviceSQL,
		revokeMachineKeyEpochSQL,
		revokeNodeKeyEpochSQL,
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

func TestDeviceRevocationStoreResolveCommittedUsesReadOnlyScopedTransaction(t *testing.T) {
	t.Parallel()

	command := deviceRevocationCommandFixture(t)
	recordID := deviceRevocationPublicIDFixture(t, "000000000901")
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueDeviceRevocationSetup(databaseTransaction)
	enqueueCompletedDeviceRevocationRecord(
		t,
		databaseTransaction,
		loadDeviceRevocationIdempotencySQL,
		command,
		recordID,
		time.Now().UTC().Add(time.Hour),
		false,
	)
	database := &fakeDeviceRevocationDatabase{
		transactions: []*fakeDeviceRevocationTransaction{databaseTransaction},
	}
	store, err := newDeviceRevocationStore(database, testDeviceRevocationOptions(), nil)
	if err != nil {
		t.Fatalf("newDeviceRevocationStore() error = %v", err)
	}

	result, found, err := store.ResolveCommitted(context.Background(), command)
	if err != nil {
		t.Fatalf("ResolveCommitted() error = %v", err)
	}
	if !found || result.IdempotencyRecordID() != recordID {
		t.Fatalf("ResolveCommitted() = %#v, %t, want record %s", result, found, recordID)
	}
	if !reflect.DeepEqual(database.readOnly, []bool{true}) || databaseTransaction.commitCalls != 1 {
		t.Fatalf(
			"readOnly/commit = %#v/%d, want [true]/1",
			database.readOnly,
			databaseTransaction.commitCalls,
		)
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
