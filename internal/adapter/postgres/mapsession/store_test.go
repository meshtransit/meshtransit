package mapsession

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	appmapsession "github.com/meshtransit/meshtransit/internal/control/mapsession"
)

func TestStoreLoadsConsistentScopedSnapshot(t *testing.T) {
	store, database, transaction, observer, identity := validStoreFixture(t)

	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !snapshot.IsValid() || snapshot.Scope().WorkspaceID().String() != testWorkspaceID ||
		snapshot.Scope().NetworkID().String() != testNetworkID || snapshot.RecoveryEpoch() != 2 ||
		snapshot.NetworkRevision() != 7 || len(snapshot.Addresses()) != 2 {
		t.Fatalf("Load() snapshot = %+v, want complete authority evidence", snapshot)
	}
	if database.beginCalls != 1 || !transaction.committed || transaction.rollbackCalls != 0 {
		t.Fatalf(
			"transaction state = (begin=%d committed=%t rollbacks=%d), want (1 true 0)",
			database.beginCalls,
			transaction.committed,
			transaction.rollbackCalls,
		)
	}
	wantQueries := []string{
		configureTransactionSQL,
		resolveScopeSQL,
		setScopeSQL,
		loadSnapshotSQL,
		loadPeerCandidatesSQL,
	}
	if !reflect.DeepEqual(transaction.queries, wantQueries) {
		t.Fatalf("queries = %v, want %v", transaction.queries, wantQueries)
	}
	fingerprint := identity.MachineFingerprint()
	nodeKey := identity.NodeKey().Bytes()
	if !reflect.DeepEqual(transaction.arguments[1], []any{fingerprint[:], nodeKey[:]}) ||
		!reflect.DeepEqual(transaction.arguments[3], []any{fingerprint[:], nodeKey[:]}) {
		t.Fatalf("identity arguments were not pinned to the authenticated Node")
	}
	if !reflect.DeepEqual(transaction.arguments[4], []any{fingerprint[:], nodeKey[:], 101}) {
		t.Fatalf("candidate arguments did not bind authenticated keys and limit+1")
	}
	candidates := snapshot.PeerCandidates()
	if len(candidates) != 1 || candidates[0].NodeID().String() != testPeerNodeID {
		t.Fatalf("PeerCandidates() = %+v, want one decoded candidate", candidates)
	}
	if observer.calls != 1 || observer.operation != OperationLoad || observer.err != nil {
		t.Fatalf("observer = %+v, want one successful load", observer)
	}
}

func TestStoreMapsUnknownIdentityToUnauthorized(t *testing.T) {
	store, _, transaction, observer, identity := validStoreFixture(t)
	transaction.rows = []databaseRow{errorRow{err: pgx.ErrNoRows}}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, appmapsession.ErrUnauthorized) {
		t.Fatalf("Load() error = %v, want mapsession.ErrUnauthorized", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
	if observer.calls != 1 || !errors.Is(observer.err, appmapsession.ErrUnauthorized) {
		t.Fatalf("observer = %+v, want unauthorized outcome", observer)
	}
}

func TestStoreRejectsMalformedSnapshotEvidence(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	record := validSnapshotRecord(t, identity)
	record.machineKey = []byte{1}
	transaction.rows[2] = snapshotRow{record: record}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
		t.Fatalf("Load() error = %v, want ErrSnapshotEvidence", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
}

func TestStoreReturnsCanceledContextBeforeBeginning(t *testing.T) {
	store, database, _, observer, identity := validStoreFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := store.Load(ctx, identity); !errors.Is(err, context.Canceled) {
		t.Fatalf("Load() error = %v, want context canceled", err)
	}
	if database.beginCalls != 0 {
		t.Fatalf("begin calls = %d, want zero", database.beginCalls)
	}
	if observer.calls != 1 || !errors.Is(observer.err, context.Canceled) {
		t.Fatalf("observer = %+v, want canceled outcome", observer)
	}
}

func TestStoreRejectsMissingTransaction(t *testing.T) {
	observer := &recordingObserver{}
	store, err := newStore(
		&fakeDatabase{},
		Options{
			StatementTimeout:   time.Second,
			IdleTimeout:        2 * time.Second,
			PeerCandidateLimit: 100,
		},
		observer,
	)
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}

	if _, err := store.Load(t.Context(), validIdentity(t)); !errors.Is(err, ErrLoadSnapshot) {
		t.Fatalf("Load() error = %v, want ErrLoadSnapshot", err)
	}
}

func TestStoreRejectsUnsafeConstruction(t *testing.T) {
	observer := &recordingObserver{}
	validOptions := Options{
		StatementTimeout:   time.Second,
		IdleTimeout:        2 * time.Second,
		PeerCandidateLimit: 100,
	}
	for _, test := range []struct {
		name     string
		database database
		options  Options
		observer Observer
	}{
		{name: "missing database", options: validOptions, observer: observer},
		{name: "missing observer", database: &fakeDatabase{}, options: validOptions},
		{name: "zero statement timeout", database: &fakeDatabase{}, options: Options{IdleTimeout: time.Second}, observer: observer},
		{name: "excess idle timeout", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: maximumIdleTimeout + 1}, observer: observer},
		{name: "zero candidate limit", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: time.Second}, observer: observer},
		{name: "excess candidate limit", database: &fakeDatabase{}, options: Options{StatementTimeout: time.Second, IdleTimeout: time.Second, PeerCandidateLimit: appmapsession.MaximumPeerCandidates + 1}, observer: observer},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newStore(test.database, test.options, test.observer); !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("newStore() error = %v, want ErrInvalidStore", err)
			}
		})
	}
}

func TestStoreFailsClosedWhenPeerCandidateBoundIsExceeded(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	store.options.PeerCandidateLimit = 1
	transaction.candidateRows = &peerCandidateRows{records: []peerCandidateRecord{
		validPeerCandidateRecord(2),
		validPeerCandidateRecord(3),
	}}

	if _, err := store.Load(t.Context(), identity); !errors.Is(err, appmapsession.ErrPeerCandidateLimit) {
		t.Fatalf("Load() error = %v, want ErrPeerCandidateLimit", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("transaction committed=%t rollbacks=%d, want false/1", transaction.committed, transaction.rollbackCalls)
	}
}
