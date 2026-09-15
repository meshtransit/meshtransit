package mapsession

import (
	"context"
	"errors"
	"fmt"
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
	testPeerNodeID  = "01890f00-0000-7000-8000-000000000702"
	testRuleID      = "01890f00-0000-7000-8000-000000000801"
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
	candidateRows *peerCandidateRows
	policyRows    *policyRuleRows
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

func (transaction *fakeTransaction) Query(
	_ context.Context,
	query string,
	arguments ...any,
) (databaseRows, error) {
	transaction.record(query, arguments)
	switch query {
	case loadPeerCandidatesSQL:
		if transaction.candidateRows == nil {
			return &peerCandidateRows{}, nil
		}
		return transaction.candidateRows, nil
	case loadPacketPolicySQL:
		if transaction.policyRows == nil {
			return &policyRuleRows{}, nil
		}
		return transaction.policyRows, nil
	default:
		return nil, errors.New("unexpected query")
	}
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
	*destinations[10].(*int64) = record.policyRevision
	*destinations[11].(*[]string) = append([]string(nil), record.addresses...)
	return nil
}

type errorRow struct{ err error }

func (row errorRow) Scan(...any) error { return row.err }

type peerCandidateRows struct {
	records []peerCandidateRecord
	index   int
	err     error
	closed  bool
}

func (rows *peerCandidateRows) Next() bool {
	if rows.index >= len(rows.records) {
		return false
	}
	rows.index++
	return true
}

func (rows *peerCandidateRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.records) {
		return errors.New("scan without current row")
	}
	record := rows.records[rows.index-1]
	*destinations[0].(*string) = record.nodeID
	*destinations[1].(*string) = record.ownerID
	*destinations[2].(*string) = record.hostname
	*destinations[3].(*[]byte) = append([]byte(nil), record.machineKey...)
	*destinations[4].(*[]byte) = append([]byte(nil), record.nodeKey...)
	*destinations[5].(*int64) = record.sessionGeneration
	*destinations[6].(*time.Time) = record.createdAt
	*destinations[7].(*time.Time) = record.keyExpiry
	*destinations[8].(*[]string) = append([]string(nil), record.addresses...)
	return nil
}

func (rows *peerCandidateRows) Err() error { return rows.err }

func (rows *peerCandidateRows) Close() { rows.closed = true }

type policyRuleRows struct {
	records []policyRuleRecord
	index   int
	err     error
	closed  bool
}

func (rows *policyRuleRows) Next() bool {
	if rows.index >= len(rows.records) {
		return false
	}
	rows.index++
	return true
}

func (rows *policyRuleRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.records) {
		return errors.New("scan without current row")
	}
	record := rows.records[rows.index-1]
	*destinations[0].(*int64) = record.policyRevision
	*destinations[1].(**string) = cloneStringPointer(record.ruleID)
	*destinations[2].(**string) = cloneStringPointer(record.sourceNodeID)
	*destinations[3].(**string) = cloneStringPointer(record.destinationNodeID)
	*destinations[4].(**string) = cloneStringPointer(record.protocol)
	*destinations[5].(*[]int32) = append([]int32{}, record.portRangeFirst...)
	*destinations[6].(*[]int32) = append([]int32{}, record.portRangeLast...)
	return nil
}

func (rows *policyRuleRows) Err() error { return rows.err }

func (rows *policyRuleRows) Close() { rows.closed = true }

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

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
		policyRevision:    5,
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
	},
		candidateRows: &peerCandidateRows{records: []peerCandidateRecord{validPeerCandidateRecord(2)}},
		policyRows:    &policyRuleRows{records: []policyRuleRecord{validPolicyRuleRecord()}},
	}
	database := &fakeDatabase{transaction: transaction}
	observer := &recordingObserver{}
	store, err := newStore(database, Options{
		StatementTimeout:   3 * time.Second,
		IdleTimeout:        5 * time.Second,
		PeerCandidateLimit: 100,
		PolicyRuleLimit:    100,
	}, observer)
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	return store, database, transaction, observer, identity
}

func validPolicyRuleRecord() policyRuleRecord {
	ruleID := testRuleID
	sourceNodeID := testNodeID
	destinationNodeID := testPeerNodeID
	protocol := "tcp"
	return policyRuleRecord{
		policyRevision:    5,
		ruleID:            &ruleID,
		sourceNodeID:      &sourceNodeID,
		destinationNodeID: &destinationNodeID,
		protocol:          &protocol,
		portRangeFirst:    []int32{80, 443},
		portRangeLast:     []int32{81, 443},
	}
}

func validPeerCandidateRecord(marker byte) peerCandidateRecord {
	createdAt := time.Date(2026, time.September, 14, 3, int(marker), 0, 0, time.UTC)
	machineKey := filledBytes(marker)
	nodeKey := filledBytes(marker + 100)
	return peerCandidateRecord{
		nodeID:            fmt.Sprintf("01890f00-0000-7000-8000-%012d", 700+int(marker)),
		ownerID:           "01890f00-0000-7000-8000-000000000011",
		hostname:          fmt.Sprintf("node-%d.example", marker),
		machineKey:        machineKey[:],
		nodeKey:           nodeKey[:],
		sessionGeneration: int64(marker),
		createdAt:         createdAt,
		keyExpiry:         createdAt.Add(24 * time.Hour),
		addresses:         []string{fmt.Sprintf("100.64.0.%d/32", marker)},
	}
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
