package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const (
	testRegistrationProfilePublicID = "01890f40-0000-7000-8000-000000000601"
	testRegistrationIssuerPublicID  = "01890f40-0000-7000-8000-000000000011"
	testRegistrationNodePublicID    = "01890f40-0000-7000-8000-000000000501"
)

type fakeRegistrationTransactionDatabase struct {
	transaction *fakeRegistrationDatabaseTransaction
	beginErr    error
	beginCalls  int
}

func (database *fakeRegistrationTransactionDatabase) Begin(
	context.Context,
) (registrationDatabaseTransaction, error) {
	database.beginCalls++
	return database.transaction, database.beginErr
}

type registrationTestCall struct {
	query     string
	arguments []any
}

type fakeRegistrationDatabaseTransaction struct {
	mu sync.Mutex

	rows          map[string][]registrationRow
	rowSets       map[string][]registrationRows
	execResults   map[string][]registrationCommandResult
	execErrors    map[string][]error
	calls         []registrationTestCall
	commitErr     error
	rollbackErr   error
	commitCalls   int
	rollbackCalls int
}

func newFakeRegistrationDatabaseTransaction() *fakeRegistrationDatabaseTransaction {
	return &fakeRegistrationDatabaseTransaction{
		rows:        make(map[string][]registrationRow),
		rowSets:     make(map[string][]registrationRows),
		execResults: make(map[string][]registrationCommandResult),
		execErrors:  make(map[string][]error),
	}
}

func (transaction *fakeRegistrationDatabaseTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) (registrationCommandResult, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.record(query, arguments)
	if queued := transaction.execErrors[query]; len(queued) > 0 {
		transaction.execErrors[query] = queued[1:]
		if queued[0] != nil {
			return nil, queued[0]
		}
	}
	if queued := transaction.execResults[query]; len(queued) > 0 {
		transaction.execResults[query] = queued[1:]
		return queued[0], nil
	}
	return fakeRegistrationCommandResult(1), nil
}

func (transaction *fakeRegistrationDatabaseTransaction) Query(
	_ context.Context,
	query string,
	arguments ...any,
) (registrationRows, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.record(query, arguments)
	queued := transaction.rowSets[query]
	if len(queued) == 0 {
		return nil, fmt.Errorf("unexpected registration query: %s", query)
	}
	transaction.rowSets[query] = queued[1:]
	return queued[0], nil
}

func (transaction *fakeRegistrationDatabaseTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) registrationRow {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.record(query, arguments)
	queued := transaction.rows[query]
	if len(queued) == 0 {
		return registrationTestRow{err: fmt.Errorf("unexpected registration row query: %s", query)}
	}
	transaction.rows[query] = queued[1:]
	return queued[0]
}

func (transaction *fakeRegistrationDatabaseTransaction) Commit(context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakeRegistrationDatabaseTransaction) Rollback(context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakeRegistrationDatabaseTransaction) record(query string, arguments []any) {
	transaction.calls = append(transaction.calls, registrationTestCall{
		query:     query,
		arguments: append([]any(nil), arguments...),
	})
}

func (transaction *fakeRegistrationDatabaseTransaction) enqueueRow(
	query string,
	row registrationRow,
) {
	transaction.rows[query] = append(transaction.rows[query], row)
}

func (transaction *fakeRegistrationDatabaseTransaction) enqueueRows(
	query string,
	rows registrationRows,
) {
	transaction.rowSets[query] = append(transaction.rowSets[query], rows)
}

type fakeRegistrationCommandResult int64

func (result fakeRegistrationCommandResult) RowsAffected() int64 { return int64(result) }

type registrationTestRow struct {
	scan func(...any) error
	err  error
}

func (row registrationTestRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if row.scan == nil {
		return nil
	}
	return row.scan(destinations...)
}

type registrationTestRows struct {
	scans  []func(...any) error
	next   int
	err    error
	closed bool
}

func (rows *registrationTestRows) Next() bool {
	return !rows.closed && rows.next < len(rows.scans)
}

func (rows *registrationTestRows) Scan(destinations ...any) error {
	if rows.next >= len(rows.scans) {
		return errors.New("registration test rows exhausted")
	}
	scan := rows.scans[rows.next]
	rows.next++
	return scan(destinations...)
}

func (rows *registrationTestRows) Err() error { return rows.err }

func (rows *registrationTestRows) Close() { rows.closed = true }

func testRegistrationTransactionOptions() RegistrationTransactionOptions {
	return RegistrationTransactionOptions{
		StatementTimeout:      5 * time.Second,
		LockTimeout:           time.Second,
		IdleTimeout:           10 * time.Second,
		AddressCandidateLimit: 256,
	}
}

func beginTestRegistrationTransaction(
	t *testing.T,
	databaseTransaction *fakeRegistrationDatabaseTransaction,
	command registration.Command,
) *registrationTransaction {
	t.Helper()
	databaseTransaction.enqueueRow(
		setRegistrationTransactionScopeSQL,
		registrationTestRow{scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 101
			*destinations[1].(*int64) = 201
			return nil
		}},
	)
	transactions, err := newRegistrationTransactions(
		&fakeRegistrationTransactionDatabase{transaction: databaseTransaction},
		testRegistrationTransactionOptions(),
		nil,
	)
	if err != nil {
		t.Fatalf("newRegistrationTransactions() error = %v", err)
	}
	value, err := transactions.Begin(t.Context(), command.Scope)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction, ok := value.(*registrationTransaction)
	if !ok {
		t.Fatalf("Begin() type = %T, want *registrationTransaction", value)
	}
	return transaction
}

func enqueueOpenRegistrationResolution(
	t *testing.T,
	database *fakeRegistrationDatabaseTransaction,
	command registration.Command,
) {
	t.Helper()
	createdAt := time.Date(2026, 9, 13, 1, 0, 0, 0, time.UTC)
	expiresAt := createdAt.Add(24 * time.Hour)
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	machineFingerprint := command.Identity.MachineKey().Fingerprint()
	nodeKey := command.Identity.NodeKey().Bytes()
	database.enqueueRow(lockPendingRegistrationSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 801
		*destinations[1].(*int64) = 601
		*destinations[2].(*sql.NullInt64) = sql.NullInt64{Int64: 701, Valid: true}
		*destinations[3].(*int16) = 2
		*destinations[4].(*[]byte) = append([]byte(nil), requestHash[:]...)
		*destinations[5].(*[]byte) = append([]byte(nil), machineFingerprint[:]...)
		*destinations[6].(*[]byte) = append([]byte(nil), nodeKey[:]...)
		*destinations[7].(*sql.NullInt64) = sql.NullInt64{}
		*destinations[8].(*sql.NullString) = sql.NullString{}
		*destinations[9].(*sql.NullString) = sql.NullString{}
		*destinations[10].(*sql.NullInt64) = sql.NullInt64{}
		*destinations[11].(*string) = "pending"
		*destinations[12].(*int64) = 4
		*destinations[13].(*time.Time) = createdAt
		*destinations[14].(*time.Time) = expiresAt
		return nil
	}})
	database.enqueueRow(lockRegistrationNetworkRevisionSQL, registrationTestRow{scan: func(destinations ...any) error {
		for index, value := range [...]int64{7, 5, 2, 3, 4, 5, 6, 1} {
			*destinations[index].(*int64) = value
		}
		return nil
	}})
	database.enqueueRow(lockRegistrationEnrollmentAuthoritySQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 701
		*destinations[1].(*int64) = 601
		*destinations[2].(*int64) = 11
		*destinations[3].(*string) = testRegistrationIssuerPublicID
		*destinations[4].(*string) = "active"
		*destinations[5].(*string) = "bounded"
		*destinations[6].(*sql.NullInt64) = sql.NullInt64{Int64: 10, Valid: true}
		*destinations[7].(*int64) = 0
		*destinations[8].(*int64) = 7
		*destinations[9].(*time.Time) = createdAt.Add(-time.Hour)
		*destinations[10].(*time.Time) = expiresAt
		*destinations[11].(*int64) = 3
		return nil
	}})
	database.enqueueRow(lockRegistrationProfileSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 601
		*destinations[1].(*string) = testRegistrationProfilePublicID
		*destinations[2].(*int64) = 3600
		*destinations[3].(*string) = "persistent"
		*destinations[4].(*string) = "bounded"
		*destinations[5].(*sql.NullInt64) = sql.NullInt64{Int64: 10, Valid: true}
		*destinations[6].(*string) = "active"
		*destinations[7].(*int64) = 2
		return nil
	}})
	database.enqueueRow(lockRegistrationDeviceSQL, registrationTestRow{err: pgx.ErrNoRows})
	database.enqueueRow(lockRegistrationAuditStreamSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 201
		*destinations[1].(*int64) = 3
		*destinations[2].(*[]byte) = make([]byte, 32)
		return nil
	}})
	database.enqueueRows(loadRegistrationHostnamesSQL, &registrationTestRows{scans: []func(...any) error{
		func(destinations ...any) error {
			*destinations[0].(*string) = command.Hostname.String()
			return nil
		},
	}})
	database.enqueueRows(lockRegistrationPrefixesSQL, &registrationTestRows{scans: []func(...any) error{
		func(destinations ...any) error {
			*destinations[0].(*int64) = 501
			*destinations[1].(*int64) = 301
			*destinations[2].(*int64) = 401
			*destinations[3].(*string) = "100.64.1.0/24"
			*destinations[4].(*int) = 4
			return nil
		},
	}})
	database.enqueueRows(loadRegistrationLeasesSQL, &registrationTestRows{})
}

func enqueueRegistrationWrites(database *fakeRegistrationDatabaseTransaction) {
	database.enqueueRow(insertRegistrationDeviceSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 901
		*destinations[1].(*int64) = 1
		return nil
	}})
	database.enqueueRow(advanceRegistrationRevisionSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 8
		*destinations[1].(*int64) = 6
		return nil
	}})
	database.enqueueRow(appendRegistrationEvidenceSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 3
		return nil
	}})
}

func testRegistrationChange(
	t *testing.T,
	command registration.Command,
	resolution registration.Resolution,
) registration.Change {
	return testRegistrationChangeWithDisposition(
		t,
		command,
		resolution,
		registration.DispositionCreated,
	)
}

func testRegistrationChangeWithDisposition(
	t *testing.T,
	command registration.Command,
	resolution registration.Resolution,
	disposition registration.Disposition,
) registration.Change {
	t.Helper()
	occurredAt := time.Date(2026, 9, 13, 2, 0, 0, 0, time.UTC)
	credential, err := resolution.Credential().Consume(occurredAt, command.RecoveryEpoch)
	if err != nil {
		t.Fatalf("Credential.Consume() error = %v", err)
	}
	registrationValue, err := resolution.Registration().Authorize(occurredAt)
	if err != nil {
		t.Fatalf("Registration.Authorize() error = %v", err)
	}
	nodeID, exists := resolution.ExistingNodeID()
	if !exists {
		nodeID, err = node.ParseID(testRegistrationNodePublicID)
		if err != nil {
			t.Fatalf("node.ParseID() error = %v", err)
		}
	}
	registrationValue, err = registrationValue.Complete(nodeID, occurredAt)
	if err != nil {
		t.Fatalf("Registration.Complete() error = %v", err)
	}
	mutationIDs := testRegistrationMutationIDs(t)
	change, err := registration.NewChange(registration.ChangeParams{
		Registration: registrationValue,
		Profile:      resolution.Profile(),
		Credential:   credential,
		Identity:     command.Identity,
		OwnerID:      credential.IssuerID(),
		CustodianID:  credential.IssuerID(),
		NodeID:       nodeID,
		Hostname:     command.Hostname,
		Disposition:  disposition,
		MutationIDs:  mutationIDs,
		OccurredAt:   occurredAt,
	})
	if err != nil {
		t.Fatalf("registration.NewChange() error = %v", err)
	}
	return change
}

func testRegistrationMutationIDs(t *testing.T) registration.MutationIDs {
	t.Helper()
	values := [...]string{
		"01890f41-0000-7000-8000-000000000001",
		"01890f41-0000-7000-8000-000000000002",
		"01890f41-0000-7000-8000-000000000003",
		"01890f41-0000-7000-8000-000000000004",
		"01890f41-0000-7000-8000-000000000005",
		"01890f41-0000-7000-8000-000000000006",
		"01890f41-0000-7000-8000-000000000007",
		"01890f41-0000-7000-8000-000000000008",
	}
	ids := make([]publicid.ID, len(values))
	for index, value := range values {
		id, err := publicid.Parse(value)
		if err != nil {
			t.Fatalf("publicid.Parse(%q) error = %v", value, err)
		}
		ids[index] = id
	}
	mutationIDs, err := registration.NewMutationIDs(registration.MutationIDParams{
		ChangeID:          ids[0],
		AuditEventID:      ids[1],
		OutboxEventID:     ids[2],
		CredentialUseID:   ids[3],
		MachineKeyEpochID: ids[4],
		NodeKeyEpochID:    ids[5],
		IPv4LeaseID:       ids[6],
		IPv6LeaseID:       ids[7],
	})
	if err != nil {
		t.Fatalf("registration.NewMutationIDs() error = %v", err)
	}
	return mutationIDs
}

func registrationCallQueries(calls []registrationTestCall) []string {
	queries := make([]string, len(calls))
	for index := range calls {
		queries[index] = calls[index].query
	}
	return queries
}

func findRegistrationCall(
	t *testing.T,
	calls []registrationTestCall,
	query string,
) registrationTestCall {
	t.Helper()
	for _, call := range calls {
		if call.query == query {
			return call
		}
	}
	t.Fatalf("registration call for query not found: %s", query)
	return registrationTestCall{}
}
