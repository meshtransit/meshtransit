package mapsession

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/control"
	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/relay"
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
	inventoryRows []*peerCandidateRows // one per shared-inventory read
	// inventoryChanges reports the schema 153 change reader as granted;
	// changeRows answers each of its reads in turn.
	inventoryChanges bool
	changeRows       []*inventoryChangeRows
	// directEndpointReader reports the schema 154 reader as granted; its
	// answer is then queued in rows (directEndpointsRow).
	directEndpointReader bool
	// noNetworkRules serves a Network policy without the Device's rule.
	noNetworkRules bool
	// policyExpiry overrides when the Network policy's Devices expire.
	policyExpiry   time.Time
	policyRows     *policyRuleRows
	directRows     *directEdgeRows
	aliasRows      *directEdgeRows
	dependencyRows *directEdgeRows
	// reachableAliases reports the schema 114 reader as granted.
	reachableAliases bool
	// scaledReaders reports the schema 147 readers as granted.
	scaledReaders bool
	// selectiveReaders reports the schema 149 readers as granted.
	selectiveReaders bool
	// keyedReaders reports the schema 155 readers as granted.
	keyedReaders bool
	// boundDependencies reports the schema 146 dependency reader as granted.
	boundDependencies bool
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
	case loadNetworkPolicyRulesSQL:
		rules, _, _ := networkPolicyRows(transaction.policyExpiry)
		if transaction.noNetworkRules {
			return &genericRows{}, nil
		}
		return rules, nil
	case loadNetworkSelectorMembersSQL:
		_, members, _ := networkPolicyRows(transaction.policyExpiry)
		return members, nil
	case loadNetworkPolicyDevicesSQL:
		_, _, devices := networkPolicyRows(transaction.policyExpiry)
		return devices, nil
	case directEndpointsGrantedSQL:
		return &grantRows{granted: transaction.directEndpointReader}, nil
	case inventoryChangesGrantedSQL:
		return &grantRows{granted: transaction.inventoryChanges}, nil
	case loadNetworkDeviceChangesSQL:
		if len(transaction.changeRows) == 0 {
			return nil, errors.New("unexpected inventory change read")
		}
		rows := transaction.changeRows[0]
		transaction.changeRows = transaction.changeRows[1:]
		return rows, nil
	case loadNetworkDevicesSQL:
		if len(transaction.inventoryRows) == 0 {
			return nil, errors.New("unexpected inventory read")
		}
		rows := transaction.inventoryRows[0]
		transaction.inventoryRows = transaction.inventoryRows[1:]
		return rows, nil
	case loadDirectEdgesSQL:
		if transaction.directRows == nil {
			return &directEdgeRows{}, nil
		}
		return transaction.directRows, nil
	case boundSharingDependenciesGrantedSQL:
		return &grantRows{granted: transaction.boundDependencies}, nil
	case scaledSharingDependenciesGrantedSQL, scaledAliasEdgesGrantedSQL:
		return &grantRows{granted: transaction.scaledReaders}, nil
	case selectiveSharingDependenciesGrantedSQL, selectiveAliasEdgesGrantedSQL:
		return &grantRows{granted: transaction.selectiveReaders}, nil
	case keyedSharingDependenciesGrantedSQL, keyedAliasEdgesGrantedSQL:
		return &grantRows{granted: transaction.keyedReaders}, nil
	case loadSharingDependenciesSQL, loadBoundSharingDependenciesSQL, loadScaledSharingDependenciesSQL,
		loadSelectiveSharingDependenciesSQL, loadKeyedSharingDependenciesSQL:
		if transaction.dependencyRows == nil {
			return &directEdgeRows{}, nil
		}
		return transaction.dependencyRows, nil
	case reachableAliasEdgesGrantedSQL:
		return &grantRows{granted: transaction.reachableAliases}, nil
	case loadAliasEdgesSQL, loadReachableAliasEdgesSQL, loadScaledAliasEdgesSQL, loadSelectiveAliasEdgesSQL,
		loadKeyedAliasEdgesSQL:
		if transaction.aliasRows == nil {
			return &directEdgeRows{}, nil
		}
		return transaction.aliasRows, nil
	case loadPacketPolicySQL:
		if transaction.policyRows == nil {
			return &policyRuleRows{}, nil
		}
		transaction.policyRows.index = 0 // each transaction reads the release afresh
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
	*destinations[2].(*string) = record.networkName
	*destinations[3].(*string) = record.nodeID
	*destinations[4].(*string) = record.hostname
	*destinations[5].(*[]byte) = append([]byte(nil), record.machineKey...)
	*destinations[6].(*[]byte) = append([]byte(nil), record.nodeKey...)
	*destinations[7].(*int64) = record.sessionGeneration
	*destinations[8].(*time.Time) = record.createdAt
	*destinations[9].(*time.Time) = record.keyExpiry
	*destinations[10].(*int64) = record.networkRevision
	*destinations[11].(*int64) = record.policyRevision
	*destinations[12].(*[]string) = append([]string(nil), record.addresses...)
	if len(destinations) > 13 {
		*destinations[13].(*time.Time) = record.readAt
	}
	return nil
}

// inventoryRevisionRow answers loadInventoryRevisionSQL (policy revision 5,
// whose release is active, as in validPolicyRuleRecord).
type inventoryRevisionRow struct {
	revision int64
	readAt   time.Time
}

func (row inventoryRevisionRow) Scan(destinations ...any) error {
	*destinations[0].(*int64) = row.revision
	*destinations[1].(*int64) = 5
	*destinations[2].(*time.Time) = row.readAt
	*destinations[3].(*bool) = true
	return nil
}

// directEndpointsRow answers loadDirectEndpointsSQL.
type directEndpointsRow struct{ present bool }

func (row directEndpointsRow) Scan(destinations ...any) error {
	*destinations[0].(*bool) = row.present
	return nil
}

// changeHeadRow answers loadInventoryChangeHeadSQL.
type changeHeadRow struct{ head int64 }

func (row changeHeadRow) Scan(destinations ...any) error {
	*destinations[0].(*int64) = row.head
	return nil
}

// inventoryChange is one row of loadNetworkDeviceChangesSQL: a listed
// Device's record, or a removed Device's numeric ID.
type inventoryChange struct {
	seq     int64
	removed int64
	record  peerCandidateRecord
}

type inventoryChangeRows struct {
	changes []inventoryChange
	index   int
}

func (rows *inventoryChangeRows) Next() bool {
	if rows.index >= len(rows.changes) {
		return false
	}
	rows.index++
	return true
}

func (rows *inventoryChangeRows) Scan(destinations ...any) error {
	change := rows.changes[rows.index-1]
	*destinations[0].(*int64) = change.seq
	if change.removed != 0 {
		*destinations[1].(*int64) = change.removed
		*destinations[2].(*bool) = false
		return nil
	}
	*destinations[1].(*int64) = change.record.numericNodeID
	*destinations[2].(*bool) = true
	candidate := &peerCandidateRows{records: []peerCandidateRecord{change.record}, index: 1}
	return candidate.Scan(append([]any{new(int64)}, destinations[3:]...)...)
}

func (rows *inventoryChangeRows) Err() error { return nil }

func (rows *inventoryChangeRows) Close() {}

// genericRows serves rows whose columns are scanned positionally.
type genericRows struct {
	rows  [][]any
	index int
}

func (rows *genericRows) Next() bool {
	if rows.index >= len(rows.rows) {
		return false
	}
	rows.index++
	return true
}

func (rows *genericRows) Scan(destinations ...any) error {
	row := rows.rows[rows.index-1]
	if len(row) != len(destinations) {
		return errors.New("unexpected destinations")
	}
	for index, value := range row {
		switch destination := destinations[index].(type) {
		case *string:
			*destination = value.(string)
		case *int64:
			*destination = value.(int64)
		case *[]int32:
			*destination = append([]int32(nil), value.([]int32)...)
		case *time.Time:
			*destination = value.(time.Time)
		case **time.Time:
			if value == nil {
				*destination = nil
			} else {
				at := value.(time.Time)
				*destination = &at
			}
		default:
			return errors.New("unexpected destination type")
		}
	}
	return nil
}

func (rows *genericRows) Err() error { return nil }

func (rows *genericRows) Close() {}

// networkPolicyRows mirror validPolicyRuleRecord at Network level: one
// Device rule 701 -> 702, both Devices live.
func networkPolicyRows(expiry time.Time) (rules, members, devices *genericRows) {
	expires := time.Date(2026, time.September, 15, 3, 0, 0, 0, time.UTC)
	if !expiry.IsZero() {
		expires = expiry
	}
	return &genericRows{rows: [][]any{{"device", testRuleID, "device", int64(701), "device", int64(702), "tcp",
			[]int32{80, 443}, []int32{81, 443}}}},
		&genericRows{},
		&genericRows{rows: [][]any{{int64(701), testNodeID, expires}, {int64(702), testPeerNodeID, expires},
			{int64(703), "01890f00-0000-7000-8000-000000000703", expires}}}
}

type errorRow struct{ err error }

func (row errorRow) Scan(...any) error { return row.err }

// suspendedRow answers schema 126 map_session_suspended_v1.
type suspendedRow struct{ suspended bool }

func (row suspendedRow) Scan(destinations ...any) error {
	if len(destinations) != 1 {
		return errors.New("unexpected suspension destinations")
	}
	value, ok := destinations[0].(*bool)
	if !ok {
		return errors.New("unexpected suspension destination")
	}
	*value = row.suspended
	return nil
}

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
	*destinations[0].(*int64) = record.numericNodeID
	*destinations[1].(*int64) = record.numericOwnerID
	*destinations[2].(*string) = record.nodeID
	*destinations[3].(*string) = record.ownerID
	*destinations[4].(*string) = record.hostname
	*destinations[5].(*[]byte) = append([]byte(nil), record.machineKey...)
	*destinations[6].(*[]byte) = append([]byte(nil), record.nodeKey...)
	*destinations[7].(*int64) = record.sessionGeneration
	*destinations[8].(*time.Time) = record.createdAt
	*destinations[9].(*time.Time) = record.keyExpiry
	*destinations[10].(*[]string) = append([]string(nil), record.addresses...)
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
		networkName:       "Development Mesh",
		nodeID:            testNodeID,
		hostname:          "node-1.example",
		machineKey:        machineKey[:],
		nodeKey:           nodeKey[:],
		sessionGeneration: 3,
		createdAt:         time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC),
		keyExpiry:         time.Date(2026, time.September, 15, 3, 0, 0, 0, time.UTC),
		networkRevision:   7,
		policyRevision:    5,
		addresses:         []string{"100.64.0.1/32", "fd07:d4de:9d87::1/128"},
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
		RelayDirectory:     relayDirectoryFixture(t),
	}, observer)
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	return store, database, transaction, observer, identity
}

func relayDirectoryFixture(t *testing.T) relay.Directory {
	t.Helper()
	relayNode, err := relay.NewNode(relay.NodeParams{
		Name: "1a", HostName: "relay-sin.example.com", IPv4: "192.0.2.10",
		IPv6: "2001:db8::10", STUNPort: 3478, RelayPort: 443,
	})
	if err != nil {
		t.Fatalf("relay.NewNode() error = %v", err)
	}
	region, err := relay.NewRegion(relay.RegionParams{
		ID: 1, Code: "sin", Name: "Singapore", Nodes: []relay.Node{relayNode},
	})
	if err != nil {
		t.Fatalf("relay.NewRegion() error = %v", err)
	}
	directory, err := relay.NewDirectory(relay.DirectoryParams{
		Revision: 1, Regions: []relay.Region{region},
	})
	if err != nil {
		t.Fatalf("relay.NewDirectory() error = %v", err)
	}
	return directory
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
		numericNodeID:     int64(700) + int64(marker),
		numericOwnerID:    11,
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

type grantRows struct {
	granted bool
	done    bool
}

func (rows *grantRows) Next() bool {
	if rows.done {
		return false
	}
	rows.done = true
	return true
}

func (rows *grantRows) Scan(destinations ...any) error {
	if len(destinations) != 1 {
		return errors.New("unexpected grant scan")
	}
	target, ok := destinations[0].(*bool)
	if !ok {
		return errors.New("unexpected grant target")
	}
	*target = rows.granted
	return nil
}

func (*grantRows) Err() error { return nil }

func (*grantRows) Close() {}

// networkSharingRow answers loadNetworkSharingDevicesSQL: the numeric node
// identifiers of the Devices a share binds.
type networkSharingRow struct{ devices []int64 }

func (row networkSharingRow) Scan(destinations ...any) error {
	*destinations[0].(*[]int64) = append([]int64{}, row.devices...)
	return nil
}

// networkHeaderRow answers loadNetworkHeaderSQL.
type networkHeaderRow struct{}

func (networkHeaderRow) Scan(destinations ...any) error {
	*destinations[0].(*string) = "Development Mesh"
	*destinations[1].(*int64) = 2
	return nil
}
