package mapsession

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/control"
	appmapsession "github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
)

const (
	testWorkspaceID = "01890f00-0000-7000-8000-000000000101"
	testNetworkID   = "01890f00-0000-7000-8000-000000000201"
	testNodeID      = "01890f00-0000-7000-8000-000000000701"
)

type fakeDatabase struct {
	transaction *fakeTransaction
	err         error
	beginCalls  int
}

func (database *fakeDatabase) Begin(context.Context) (databaseTransaction, error) {
	database.beginCalls++
	if database.transaction == nil {
		return nil, database.err
	}
	return database.transaction, database.err
}

type fakeTransaction struct {
	rows          []databaseRow
	queries       []string
	arguments     [][]any
	execErr       error
	commitErr     error
	rollbackErr   error
	committed     bool
	rollbackCalls int
}

func (transaction *fakeTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) error {
	transaction.record(query, arguments)
	return transaction.execErr
}

func (transaction *fakeTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) databaseRow {
	transaction.record(query, arguments)
	if len(transaction.rows) == 0 {
		return errorRow{err: errors.New("unexpected query")}
	}
	row := transaction.rows[0]
	transaction.rows = transaction.rows[1:]
	return row
}

func (transaction *fakeTransaction) Commit(context.Context) error {
	transaction.committed = transaction.commitErr == nil
	return transaction.commitErr
}

func (transaction *fakeTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakeTransaction) record(query string, arguments []any) {
	transaction.queries = append(transaction.queries, query)
	transaction.arguments = append(transaction.arguments, append([]any(nil), arguments...))
}

type scopeRow struct {
	workspaceID   string
	networkID     string
	recoveryEpoch int64
}

func (row scopeRow) Scan(destinations ...any) error {
	*destinations[0].(*string) = row.workspaceID
	*destinations[1].(*string) = row.networkID
	*destinations[2].(*int64) = row.recoveryEpoch
	return nil
}

type internalScopeRow struct {
	workspaceID int64
	networkID   int64
}

func (row internalScopeRow) Scan(destinations ...any) error {
	*destinations[0].(*int64) = row.workspaceID
	*destinations[1].(*int64) = row.networkID
	return nil
}

type snapshotRow struct {
	record snapshotRecord
}

func (row snapshotRow) Scan(destinations ...any) error {
	record := row.record
	*destinations[0].(*int64) = record.numericNodeID
	*destinations[1].(*int64) = record.numericOwnerID
	*destinations[2].(*string) = record.nodeID
	*destinations[3].(*string) = record.hostname
	*destinations[4].(*[]byte) = append([]byte(nil), record.machineKey...)
	*destinations[5].(*[]byte) = append([]byte(nil), record.nodeKey...)
	*destinations[6].(*int64) = record.sessionGeneration
	*destinations[7].(*time.Time) = record.createdAt
	*destinations[8].(*time.Time) = record.keyExpiry
	*destinations[9].(*int64) = record.networkRevision
	*destinations[10].(*[]string) = append([]string(nil), record.addresses...)
	return nil
}

type errorRow struct{ err error }

func (row errorRow) Scan(...any) error { return row.err }

type recordingObserver struct {
	operation Operation
	err       error
	calls     int
}

func (observer *recordingObserver) ObserveMapSession(
	operation Operation,
	_ time.Duration,
	err error,
) {
	observer.operation = operation
	observer.err = err
	observer.calls++
}

func validIdentity(t *testing.T) control.AuthenticatedNode {
	t.Helper()
	machineKey, err := node.NewMachineKey(filledBytes(0x11))
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey(filledBytes(0x22))
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("control.NewAuthenticatedMachine() error = %v", err)
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatalf("BindNodeKey() error = %v", err)
	}
	return identity
}

func validSnapshotRecord(t *testing.T, identity control.AuthenticatedNode) snapshotRecord {
	t.Helper()
	machineKey := filledBytes(0x11)
	nodeKey := identity.NodeKey().Bytes()
	return snapshotRecord{
		numericNodeID:     701,
		numericOwnerID:    11,
		nodeID:            testNodeID,
		hostname:          "node-1.example",
		machineKey:        machineKey[:],
		nodeKey:           nodeKey[:],
		sessionGeneration: 3,
		createdAt:         time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC),
		keyExpiry:         time.Date(2026, time.September, 15, 3, 0, 0, 0, time.UTC),
		networkRevision:   7,
		addresses:         []string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128"},
	}
}

func validStoreFixture(
	t *testing.T,
) (*Store, *fakeDatabase, *fakeTransaction, *recordingObserver, control.AuthenticatedNode) {
	t.Helper()
	identity := validIdentity(t)
	transaction := &fakeTransaction{rows: []databaseRow{
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: validSnapshotRecord(t, identity)},
	}}
	database := &fakeDatabase{transaction: transaction}
	observer := &recordingObserver{}
	store, err := newStore(database, Options{
		StatementTimeout: 3 * time.Second,
		IdleTimeout:      5 * time.Second,
	}, observer)
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	return store, database, transaction, observer, identity
}

func filledBytes(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}

var _ appmapsession.SnapshotStore = (*Store)(nil)
var _ databaseRow = errorRow{err: pgx.ErrNoRows}
