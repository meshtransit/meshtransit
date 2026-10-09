package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

const (
	testClaimID         = "550e8400-e29b-41d4-a716-446655440000"
	testNetworkPublicID = "01890f00-0000-7000-8000-000000000201"
)

func TestOutboxStoreReadsReadyNetworkRevisionBacklog(t *testing.T) {
	t.Parallel()

	database := &fakeOutboxDatabase{queryRow: fakeOutboxRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 7
		*destinations[1].(*int64) = 12_345
		return nil
	}}}
	store := mustTestOutboxStore(t, database)

	backlog, err := store.ReadNetworkRevisionBacklog(t.Context())
	if err != nil {
		t.Fatalf("ReadNetworkRevisionBacklog() error = %v", err)
	}
	if backlog.Events() != 7 || backlog.OldestAge() != 12_345*time.Millisecond {
		t.Fatalf(
			"ReadNetworkRevisionBacklog() = (%d, %s), want (7, 12.345s)",
			backlog.Events(),
			backlog.OldestAge(),
		)
	}
	for _, fragment := range []string{
		"event.available_at <= pg_catalog.clock_timestamp()",
		"event.state = 'pending'",
		"event.claim_expires_at <= pg_catalog.clock_timestamp()",
	} {
		if !strings.Contains(database.query, fragment) {
			t.Fatalf("backlog query missing ready-work predicate %q: %s", fragment, database.query)
		}
	}
	if len(database.arguments) != 0 {
		t.Fatalf("backlog query arguments = %#v, want none", database.arguments)
	}
}

func TestOutboxStoreClassifiesBacklogReadFailure(t *testing.T) {
	t.Parallel()

	readErr := errors.New("backlog unavailable")
	database := &fakeOutboxDatabase{queryRow: fakeOutboxRow{scan: func(...any) error {
		return readErr
	}}}
	store := mustTestOutboxStore(t, database)

	_, err := store.ReadNetworkRevisionBacklog(t.Context())
	if !errors.Is(err, ErrReadOutboxBacklog) || !errors.Is(err, readErr) {
		t.Fatalf("ReadNetworkRevisionBacklog() error = %v, want classified read failure", err)
	}
}

func TestOutboxStoreClaimsBoundedNetworkRevisionWork(t *testing.T) {
	t.Parallel()

	claimedAt := time.Date(2026, 9, 13, 3, 0, 0, 0, time.UTC)
	rows := &fakeOutboxRows{scans: []func(...any) error{
		func(destinations ...any) error {
			*destinations[0].(*int64) = 91
			*destinations[1].(*int64) = 101
			*destinations[2].(*int64) = 201
			*destinations[3].(*int64) = 42
			*destinations[4].(*int) = 3
			*destinations[5].(*time.Time) = claimedAt
			return nil
		},
	}}
	database := &fakeOutboxDatabase{queryRows: rows}
	store := mustTestOutboxStore(t, database)

	claims, err := store.ClaimNetworkRevisions(t.Context(), "worker-1", 32, 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimNetworkRevisions() error = %v", err)
	}
	if len(claims) != 1 {
		t.Fatalf("len(claims) = %d, want 1", len(claims))
	}
	claim := claims[0]
	if claim.EventID() != 91 || claim.WorkspaceID() != 101 || claim.NetworkID() != 201 ||
		claim.RecordedRevision() != 42 || claim.Token() != testClaimID ||
		claim.WorkerID() != "worker-1" || claim.Attempt() != 3 || !claim.ClaimedAt().Equal(claimedAt) {
		t.Fatalf("claim = %+v, want complete fencing metadata", claim)
	}
	if !strings.Contains(database.query, "FOR UPDATE SKIP LOCKED") ||
		!strings.Contains(database.query, "network_revision IS NOT NULL") {
		t.Fatalf("claim query does not preserve bounded network outbox semantics: %s", database.query)
	}
	if len(database.arguments) != 4 || database.arguments[0] != 32 ||
		database.arguments[1] != testClaimID || database.arguments[2] != "worker-1" ||
		database.arguments[3] != int64(30_000) {
		t.Fatalf("claim arguments = %#v, want bounded parameterized values", database.arguments)
	}
	if !rows.closed {
		t.Fatal("ClaimNetworkRevisions() did not close rows")
	}
}

func TestOutboxStoreLoadsCurrentRevisionUnderExactScope(t *testing.T) {
	t.Parallel()

	claim := validTestRevisionClaim(t)
	transaction := &fakeOutboxTransaction{
		queryRow: fakeOutboxRow{scan: func(destinations ...any) error {
			*destinations[0].(*string) = testNetworkPublicID
			*destinations[1].(*int64) = 45
			return nil
		}},
	}
	database := &fakeOutboxDatabase{transaction: transaction}
	store := mustTestOutboxStore(t, database)

	revision, err := store.LoadNetworkRevision(t.Context(), claim)
	if err != nil {
		t.Fatalf("LoadNetworkRevision() error = %v", err)
	}
	if revision.NetworkPublicID() != testNetworkPublicID || revision.Number() != 45 {
		t.Fatalf("LoadNetworkRevision() = (%q, %d), want (%q, 45)", revision.NetworkPublicID(), revision.Number(), testNetworkPublicID)
	}
	if !database.readOnly || !transaction.committed || transaction.rollbackCalls != 0 {
		t.Fatalf("transaction state: readOnly=%t committed=%t rollbacks=%d", database.readOnly, transaction.committed, transaction.rollbackCalls)
	}
	if len(transaction.actions) != 2 || !strings.Contains(transaction.actions[0], "set_config") ||
		!strings.Contains(transaction.actions[1], "mesh_ops.network_revision") {
		t.Fatalf("transaction actions = %#v, want scope then revision query", transaction.actions)
	}
}

func TestOutboxStoreRejectsRevisionRegression(t *testing.T) {
	t.Parallel()

	transaction := &fakeOutboxTransaction{
		queryRow: fakeOutboxRow{scan: func(destinations ...any) error {
			*destinations[0].(*string) = testNetworkPublicID
			*destinations[1].(*int64) = 41
			return nil
		}},
	}
	store := mustTestOutboxStore(t, &fakeOutboxDatabase{transaction: transaction})

	if _, err := store.LoadNetworkRevision(t.Context(), validTestRevisionClaim(t)); !errors.Is(err, ErrOutboxRevisionRegressed) {
		t.Fatalf("LoadNetworkRevision() error = %v, want ErrOutboxRevisionRegressed", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 {
		t.Fatalf("regressed revision transaction: committed=%t rollbacks=%d", transaction.committed, transaction.rollbackCalls)
	}
}

func TestOutboxStoreRecordsDeliveredAndRetryAtomically(t *testing.T) {
	t.Parallel()

	claim := validTestRevisionClaim(t)
	database := &fakeOutboxDatabase{rowsAffected: 1}
	store := mustTestOutboxStore(t, database)

	if err := store.MarkRevisionDelivered(t.Context(), claim); err != nil {
		t.Fatalf("MarkRevisionDelivered() error = %v", err)
	}
	if !strings.Contains(database.query, "INSERT INTO mesh_ops.outbox_attempt") ||
		!strings.Contains(database.query, "'delivered'") {
		t.Fatalf("delivered query does not atomically append attempt: %s", database.query)
	}

	if err := store.RetryNetworkRevision(t.Context(), claim, "publish_failed", 5*time.Second); err != nil {
		t.Fatalf("RetryNetworkRevision() error = %v", err)
	}
	if !strings.Contains(database.query, "state = 'pending'") ||
		!strings.Contains(database.query, "'retry'") {
		t.Fatalf("retry query does not atomically release and append attempt: %s", database.query)
	}
}

func TestOutboxStoreClassifiesLostClaim(t *testing.T) {
	t.Parallel()

	database := &fakeOutboxDatabase{}
	store := mustTestOutboxStore(t, database)
	if err := store.MarkRevisionDelivered(t.Context(), validTestRevisionClaim(t)); !errors.Is(err, ErrOutboxClaimLost) {
		t.Fatalf("MarkRevisionDelivered() error = %v, want ErrOutboxClaimLost", err)
	}
}

func TestOutboxStoreRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	store := mustTestOutboxStore(t, &fakeOutboxDatabase{})
	var nilContext context.Context
	tests := []struct {
		name string
		call func() error
	}{
		{name: "nil claim context", call: func() error {
			_, err := store.ClaimNetworkRevisions(nilContext, "worker-1", 1, time.Second)
			return err
		}},
		{name: "nil backlog context", call: func() error {
			_, err := store.ReadNetworkRevisionBacklog(nilContext)
			return err
		}},
		{name: "oversized batch", call: func() error {
			_, err := store.ClaimNetworkRevisions(t.Context(), "worker-1", 257, time.Second)
			return err
		}},
		{name: "invalid worker", call: func() error {
			_, err := store.ClaimNetworkRevisions(t.Context(), "worker id", 1, time.Second)
			return err
		}},
		{name: "invalid lease", call: func() error {
			_, err := store.ClaimNetworkRevisions(t.Context(), "worker-1", 1, 0)
			return err
		}},
		{name: "zero claim", call: func() error {
			return store.MarkRevisionDelivered(t.Context(), network.RevisionClaim{})
		}},
		{name: "invalid retry class", call: func() error {
			return store.RetryNetworkRevision(t.Context(), validTestRevisionClaim(t), "Publish Failed", time.Second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.call(); !errors.Is(err, ErrInvalidOutboxStore) {
				t.Fatalf("call error = %v, want ErrInvalidOutboxStore", err)
			}
		})
	}
}

func TestNewOutboxStoreRequiresWorkerPool(t *testing.T) {
	t.Parallel()

	database := &fakeOutboxDatabase{}
	if _, err := NewOutboxStore(&Pool{
		role:           PoolRoleRuntime,
		outboxDatabase: database,
	}); !errors.Is(err, ErrInvalidOutboxStore) {
		t.Fatalf("NewOutboxStore(runtime) error = %v, want ErrInvalidOutboxStore", err)
	}
	if _, err := NewOutboxStore(&Pool{
		role:           PoolRoleWorker,
		outboxDatabase: database,
	}); err != nil {
		t.Fatalf("NewOutboxStore(worker) error = %v", err)
	}
}

func TestRandomClaimTokenProducesValidDistinctUUIDs(t *testing.T) {
	t.Parallel()

	first, err := randomClaimToken()
	if err != nil {
		t.Fatalf("randomClaimToken() first error = %v", err)
	}
	second, err := randomClaimToken()
	if err != nil {
		t.Fatalf("randomClaimToken() second error = %v", err)
	}
	if first == second {
		t.Fatal("randomClaimToken() returned a duplicate")
	}
	if _, err := network.NewRevisionClaim(1, 1, 1, 1, first, "worker-1", 1, time.Now()); err != nil {
		t.Fatalf("randomClaimToken() returned invalid UUID %q: %v", first, err)
	}
}

func validTestRevisionClaim(t *testing.T) network.RevisionClaim {
	t.Helper()
	claim, err := network.NewRevisionClaim(
		91,
		101,
		201,
		42,
		testClaimID,
		"worker-1",
		3,
		time.Date(2026, 9, 13, 3, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("network.NewRevisionClaim() error = %v", err)
	}
	return claim
}

func mustTestOutboxStore(t *testing.T, database outboxDatabase) *OutboxStore {
	t.Helper()
	store, err := newOutboxStore(database, func() (string, error) { return testClaimID, nil }, nil)
	if err != nil {
		t.Fatalf("newOutboxStore() error = %v", err)
	}
	return store
}
