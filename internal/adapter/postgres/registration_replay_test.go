package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
)

func TestRegistrationReplayStoreResolvesCommittedResultUnderExactScope(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	transaction := &fakeRegistrationReplayTransaction{
		row: fakeRegistrationReplayRow{record: validRegistrationReplayRecord(t, command)},
	}
	database := &fakeRegistrationReplayDatabase{transaction: transaction}
	store := mustRegistrationReplayStore(t, database)

	result, found, err := store.ResolveCommitted(t.Context(), command)
	if err != nil {
		t.Fatalf("ResolveCommitted() error = %v", err)
	}
	if !found || !result.IsValid() || result.RegistrationID() != command.RegistrationID ||
		result.Scope() != command.Scope || result.Hostname().String() != "node-one.example" ||
		result.Disposition() != registration.DispositionCreated || result.NetworkRevision() != 42 {
		t.Fatalf("ResolveCommitted() = (%+v, %t), want exact committed result", result, found)
	}
	if !database.readOnly || !transaction.committed || transaction.rollbackCalls != 0 {
		t.Fatalf(
			"transaction state: readOnly=%t committed=%t rollbacks=%d",
			database.readOnly,
			transaction.committed,
			transaction.rollbackCalls,
		)
	}
	if len(transaction.queries) != 2 ||
		!strings.Contains(transaction.queries[0], "mesh_ops.set_network_scope") ||
		!strings.Contains(transaction.queries[1], "mesh.pending_registration") {
		t.Fatalf("transaction queries = %#v, want exact scope then replay evidence", transaction.queries)
	}
	if len(transaction.arguments[0]) != 2 ||
		transaction.arguments[0][0] != command.Scope.WorkspaceID().String() ||
		transaction.arguments[0][1] != command.Scope.NetworkID().String() ||
		len(transaction.arguments[1]) != 1 ||
		transaction.arguments[1][0] != command.RegistrationID.String() {
		t.Fatalf("transaction arguments = %#v, want public exact-scope IDs", transaction.arguments)
	}
}

func TestRegistrationReplayStoreReturnsNotFoundForOpenOrMissingIntent(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	tests := []struct {
		name string
		row  registrationReplayRow
	}{
		{
			name: "open intent",
			row: fakeRegistrationReplayRow{record: registrationReplayRecord{
				intentFormatVersion: 2,
				state:               "authorized",
			}},
		},
		{name: "missing intent", row: fakeRegistrationReplayRow{err: pgx.ErrNoRows}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			transaction := &fakeRegistrationReplayTransaction{row: test.row}
			store := mustRegistrationReplayStore(
				t,
				&fakeRegistrationReplayDatabase{transaction: transaction},
			)
			result, found, err := store.ResolveCommitted(t.Context(), command)
			if err != nil || found || result.IsValid() {
				t.Fatalf("ResolveCommitted() = (%+v, %t, %v), want empty not found", result, found, err)
			}
			if !transaction.committed || transaction.rollbackCalls != 0 {
				t.Fatalf(
					"transaction state: committed=%t rollbacks=%d, want committed read",
					transaction.committed,
					transaction.rollbackCalls,
				)
			}
		})
	}
}

func TestRegistrationReplayStoreRejectsConflictingIntentEvidence(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	base := validRegistrationReplayRecord(t, command)
	tests := []struct {
		name   string
		mutate func(*registrationReplayRecord)
	}{
		{name: "request hash", mutate: func(record *registrationReplayRecord) { record.requestHash[0] ^= 0xff }},
		{name: "machine fingerprint", mutate: func(record *registrationReplayRecord) { record.machineFingerprint[0] ^= 0xff }},
		{name: "requested Node key", mutate: func(record *registrationReplayRecord) { record.requestedNodeKey[0] ^= 0xff }},
		{name: "credential", mutate: func(record *registrationReplayRecord) {
			record.credentialPublicID = "01890f40-0000-7000-8000-000000000402"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			record := cloneRegistrationReplayRecord(base)
			test.mutate(&record)
			transaction := &fakeRegistrationReplayTransaction{
				row: fakeRegistrationReplayRow{record: record},
			}
			store := mustRegistrationReplayStore(
				t,
				&fakeRegistrationReplayDatabase{transaction: transaction},
			)
			_, _, err := store.ResolveCommitted(t.Context(), command)
			if !errors.Is(err, registration.ErrIntentConflict) ||
				!errors.Is(err, ErrResolveRegistrationReplay) {
				t.Fatalf("ResolveCommitted() error = %v, want intent conflict", err)
			}
			if transaction.committed || transaction.rollbackCalls != 1 {
				t.Fatalf(
					"transaction state: committed=%t rollbacks=%d, want rollback",
					transaction.committed,
					transaction.rollbackCalls,
				)
			}
		})
	}
}

func TestRegistrationReplayStoreRejectsMalformedCompletionEvidence(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	base := validRegistrationReplayRecord(t, command)
	tests := []struct {
		name   string
		mutate func(*registrationReplayRecord)
	}{
		{name: "legacy format", mutate: func(record *registrationReplayRecord) { record.intentFormatVersion = 1 }},
		{name: "short request hash", mutate: func(record *registrationReplayRecord) { record.requestHash = record.requestHash[:31] }},
		{name: "zero request hash", mutate: func(record *registrationReplayRecord) { record.requestHash = make([]byte, 32) }},
		{name: "missing Node", mutate: func(record *registrationReplayRecord) { record.nodePublicID = sql.NullString{} }},
		{name: "invalid hostname", mutate: func(record *registrationReplayRecord) {
			record.completedHostname.String = "Invalid Hostname"
		}},
		{name: "invalid disposition", mutate: func(record *registrationReplayRecord) {
			record.completedDisposition.String = "unknown"
		}},
		{name: "zero revision", mutate: func(record *registrationReplayRecord) {
			record.completedNetworkRevision.Int64 = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			record := cloneRegistrationReplayRecord(base)
			test.mutate(&record)
			transaction := &fakeRegistrationReplayTransaction{
				row: fakeRegistrationReplayRow{record: record},
			}
			store := mustRegistrationReplayStore(
				t,
				&fakeRegistrationReplayDatabase{transaction: transaction},
			)
			_, _, err := store.ResolveCommitted(t.Context(), command)
			if !errors.Is(err, ErrRegistrationReplayEvidence) ||
				!errors.Is(err, ErrResolveRegistrationReplay) {
				t.Fatalf("ResolveCommitted() error = %v, want invalid replay evidence", err)
			}
		})
	}
}

func TestRegistrationReplayStoreClassifiesTransactionFailures(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	beginErr := errors.New("begin failed")
	if _, _, err := mustRegistrationReplayStore(t, &fakeRegistrationReplayDatabase{
		beginErr: beginErr,
	}).ResolveCommitted(t.Context(), command); !errors.Is(err, beginErr) ||
		!errors.Is(err, ErrResolveRegistrationReplay) {
		t.Fatalf("ResolveCommitted(begin) error = %v, want classified begin failure", err)
	}

	scopeErr := errors.New("scope failed")
	queryErr := errors.New("query failed")
	commitErr := errors.New("commit failed")
	tests := []struct {
		name      string
		configure func(*fakeRegistrationReplayTransaction)
		want      error
	}{
		{name: "scope", configure: func(transaction *fakeRegistrationReplayTransaction) {
			transaction.execErr = scopeErr
		}, want: scopeErr},
		{name: "query", configure: func(transaction *fakeRegistrationReplayTransaction) {
			transaction.row = fakeRegistrationReplayRow{err: queryErr}
		}, want: queryErr},
		{name: "commit", configure: func(transaction *fakeRegistrationReplayTransaction) {
			transaction.commitErr = commitErr
		}, want: commitErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			transaction := &fakeRegistrationReplayTransaction{
				row: fakeRegistrationReplayRow{err: pgx.ErrNoRows},
			}
			test.configure(transaction)
			_, _, err := mustRegistrationReplayStore(
				t,
				&fakeRegistrationReplayDatabase{transaction: transaction},
			).ResolveCommitted(t.Context(), command)
			if !errors.Is(err, ErrResolveRegistrationReplay) || !errors.Is(err, test.want) {
				t.Fatalf("ResolveCommitted() error = %v, want classified %v", err, test.want)
			}
			if transaction.committed || transaction.rollbackCalls != 1 {
				t.Fatalf(
					"transaction state: committed=%t rollbacks=%d, want rollback",
					transaction.committed,
					transaction.rollbackCalls,
				)
			}
		})
	}
}

func TestRegistrationReplayStoreJoinsRollbackFailure(t *testing.T) {
	t.Parallel()

	queryErr := errors.New("query failed")
	rollbackErr := errors.New("rollback failed")
	transaction := &fakeRegistrationReplayTransaction{
		row:         fakeRegistrationReplayRow{err: queryErr},
		rollbackErr: rollbackErr,
	}
	_, _, err := mustRegistrationReplayStore(
		t,
		&fakeRegistrationReplayDatabase{transaction: transaction},
	).ResolveCommitted(t.Context(), validRegistrationReplayCommand(t))
	if !errors.Is(err, queryErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("ResolveCommitted() error = %v, want query and rollback failures", err)
	}
}

func TestRegistrationReplayStoreRejectsInvalidInputsAndPoolRole(t *testing.T) {
	t.Parallel()

	database := &fakeRegistrationReplayDatabase{}
	if _, err := NewRegistrationReplayStore(&Pool{
		role:                       PoolRoleWorker,
		registrationReplayDatabase: database,
	}); !errors.Is(err, ErrInvalidRegistrationReplayStore) {
		t.Fatalf("NewRegistrationReplayStore(worker) error = %v, want invalid store", err)
	}
	if _, err := NewRegistrationReplayStore(&Pool{
		role:                       PoolRoleRuntime,
		registrationReplayDatabase: database,
	}); err != nil {
		t.Fatalf("NewRegistrationReplayStore(runtime) error = %v", err)
	}

	store := mustRegistrationReplayStore(t, database)
	var nilContext context.Context
	if _, _, err := store.ResolveCommitted(nilContext, validRegistrationReplayCommand(t)); !errors.Is(err, ErrInvalidRegistrationReplayStore) {
		t.Fatalf("ResolveCommitted(nil context) error = %v, want invalid store", err)
	}
	if _, _, err := store.ResolveCommitted(t.Context(), registration.Command{}); !errors.Is(err, ErrInvalidRegistrationReplayStore) {
		t.Fatalf("ResolveCommitted(invalid command) error = %v, want invalid store", err)
	}
}

func mustRegistrationReplayStore(
	t *testing.T,
	database registrationReplayDatabase,
) *RegistrationReplayStore {
	t.Helper()

	store, err := newRegistrationReplayStore(database, nil)
	if err != nil {
		t.Fatalf("newRegistrationReplayStore() error = %v", err)
	}
	return store
}
