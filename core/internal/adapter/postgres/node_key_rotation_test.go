package postgres

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/keyrotation"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestNodeKeyRotationTransactionPersistsAtomicAuthority(t *testing.T) {
	t.Parallel()

	command := nodeKeyRotationCommandFixture(t)
	ids := nodeKeyRotationMutationIDsFixture(t)
	decisionTime := nodeKeyRotationTimeFixture()
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueNodeKeyRotationSetup(t, databaseTransaction, command)
	enqueueOpenNodeKeyRotationResolution(t, databaseTransaction, command, decisionTime)
	enqueueNodeKeyRotationApply(databaseTransaction)
	store := beginTestNodeKeyRotationStore(t, databaseTransaction)

	transaction, err := store.Begin(t.Context(), command)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change, err := keyrotation.NewChange(command, resolution, ids, decisionTime)
	if err != nil {
		t.Fatalf("keyrotation.NewChange() error = %v", err)
	}
	result, err := transaction.Apply(t.Context(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if result.NodeID() != resolution.NodeID() || result.DeviceVersion() != 5 ||
		result.NodeKeyEpoch() != 3 || result.SessionGeneration() != 4 ||
		result.NetworkRevision() != 11 || result.InventoryRevision() != 8 {
		t.Fatalf("Apply() result = %#v, want exact +1 authority", result)
	}
	if databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf(
			"database close calls = commit %d rollback %d, want 1/0",
			databaseTransaction.commitCalls,
			databaseTransaction.rollbackCalls,
		)
	}
	wantQueries := []string{
		configureNodeKeyRotationTransactionSQL,
		resolveNodeKeyRotationScopeSQL,
		setNodeKeyRotationScopeSQL,
		lockNodeKeyRotationRevisionSQL,
		lockNodeKeyRotationTargetSQL,
		lockNodeKeyRotationAuditStreamSQL,
		setNodeKeyRotationChangeSQL,
		expireNodeKeyRotationEpochSQL,
		insertNodeKeyRotationEpochSQL,
		rotateDeviceNodeKeySQL,
		advanceNodeKeyRotationRevisionSQL,
		appendNodeKeyRotationEvidenceSQL,
	}
	if got := deviceRevocationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("query order = %#v, want %#v", got, wantQueries)
	}
	insertCall := databaseTransaction.calls[8]
	if got := insertCall.arguments[0]; got != ids.NodeKeyEpochID().String() {
		t.Fatalf("new key epoch ID = %v, want %s", got, ids.NodeKeyEpochID())
	}
	if got := insertCall.arguments[4]; got != int64(3) {
		t.Fatalf("new key epoch = %v, want 3", got)
	}
}

func TestNodeKeyRotationResolveConvergesExactCommittedReplay(t *testing.T) {
	t.Parallel()

	command := nodeKeyRotationCommandFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueNodeKeyRotationSetup(t, databaseTransaction, command)
	enqueueNodeKeyRotationRevisions(databaseTransaction, 11, 8)
	enqueueNodeKeyRotationTarget(
		t,
		databaseTransaction,
		command,
		command.NewNodeKey(),
		5,
		4,
		3,
		nodeKeyRotationTimeFixture(),
	)
	proof, err := command.RotationProofHash()
	if err != nil {
		t.Fatalf("RotationProofHash() error = %v", err)
	}
	oldNodeKey := command.OldNodeKey().Bytes()
	databaseTransaction.enqueueRow(lockNodeKeyRotationReplaySQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*[]byte) = append([]byte(nil), oldNodeKey[:]...)
			*destinations[1].(*[]byte) = append([]byte(nil), proof[:]...)
			*destinations[2].(*string) = "expired"
			*destinations[3].(*sql.NullTime) = sql.NullTime{
				Time:  nodeKeyRotationTimeFixture(),
				Valid: true,
			}
			return nil
		},
	})
	store := beginTestNodeKeyRotationStore(t, databaseTransaction)

	transaction, err := store.Begin(t.Context(), command)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve(replay) error = %v", err)
	}
	result, found := resolution.CompletedResult()
	if !found || result.NodeKeyEpoch() != 3 || result.SessionGeneration() != 4 ||
		result.NetworkRevision() != 11 || result.InventoryRevision() != 8 {
		t.Fatalf("CompletedResult() = %#v, %t, want exact committed replay", result, found)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	wantQueries := []string{
		configureNodeKeyRotationTransactionSQL,
		resolveNodeKeyRotationScopeSQL,
		setNodeKeyRotationScopeSQL,
		lockNodeKeyRotationRevisionSQL,
		lockNodeKeyRotationTargetSQL,
		lockNodeKeyRotationReplaySQL,
	}
	if got := deviceRevocationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("replay query order = %#v, want %#v", got, wantQueries)
	}
}

func TestNodeKeyRotationStoreHidesUnresolvedAuthority(t *testing.T) {
	t.Parallel()

	command := nodeKeyRotationCommandFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	databaseTransaction.enqueueRow(
		resolveNodeKeyRotationScopeSQL,
		deviceRevocationTestRow{err: pgx.ErrNoRows},
	)
	store := beginTestNodeKeyRotationStore(t, databaseTransaction)

	_, err := store.Begin(t.Context(), command)
	if !errors.Is(err, keyrotation.ErrNotFound) {
		t.Fatalf("Begin() error = %v, want ErrNotFound", err)
	}
	if databaseTransaction.rollbackCalls != 1 {
		t.Fatalf("setup rollback calls = %d, want 1", databaseTransaction.rollbackCalls)
	}
}

func TestNewNodeKeyRotationStoreRejectsWorkerPool(t *testing.T) {
	t.Parallel()

	pool := &Pool{
		role:                     PoolRoleWorker,
		deviceRevocationDatabase: &fakeDeviceRevocationDatabase{},
	}
	if _, err := NewNodeKeyRotationStore(pool, testNodeKeyRotationOptions()); !errors.Is(
		err,
		ErrInvalidNodeKeyRotationStore,
	) {
		t.Fatalf("NewNodeKeyRotationStore() error = %v, want invalid store", err)
	}
}

func beginTestNodeKeyRotationStore(
	t *testing.T,
	databaseTransaction *fakeDeviceRevocationTransaction,
) *NodeKeyRotationStore {
	t.Helper()
	store, err := newNodeKeyRotationStore(
		&fakeDeviceRevocationDatabase{transactions: []*fakeDeviceRevocationTransaction{
			databaseTransaction,
		}},
		testNodeKeyRotationOptions(),
		nil,
	)
	if err != nil {
		t.Fatalf("newNodeKeyRotationStore() error = %v", err)
	}
	return store
}

func testNodeKeyRotationOptions() NodeKeyRotationOptions {
	return NodeKeyRotationOptions{
		StatementTimeout: 5 * time.Second,
		LockTimeout:      time.Second,
		IdleTimeout:      10 * time.Second,
	}
}

func enqueueNodeKeyRotationSetup(
	t *testing.T,
	transaction *fakeDeviceRevocationTransaction,
	command keyrotation.Command,
) {
	t.Helper()
	scope := nodeKeyRotationScopeFixture(t)
	transaction.enqueueRow(resolveNodeKeyRotationScopeSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = scope.WorkspaceID().String()
			*destinations[1].(*string) = scope.NetworkID().String()
			return nil
		},
	})
	transaction.enqueueRow(setNodeKeyRotationScopeSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 101
			*destinations[1].(*int64) = 201
			return nil
		},
	})
	_ = command
}

func enqueueOpenNodeKeyRotationResolution(
	t *testing.T,
	transaction *fakeDeviceRevocationTransaction,
	command keyrotation.Command,
	decisionTime time.Time,
) {
	t.Helper()
	enqueueNodeKeyRotationRevisions(transaction, 10, 7)
	enqueueNodeKeyRotationTarget(
		t,
		transaction,
		command,
		command.OldNodeKey(),
		4,
		3,
		2,
		decisionTime.Add(-time.Hour),
	)
	transaction.enqueueRow(lockNodeKeyRotationAuditStreamSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 3
			*destinations[1].(*int64) = 4
			*destinations[2].(*[]byte) = make([]byte, 32)
			return nil
		},
	})
}

func enqueueNodeKeyRotationRevisions(
	transaction *fakeDeviceRevocationTransaction,
	networkRevision int64,
	inventoryRevision int64,
) {
	transaction.enqueueRow(lockNodeKeyRotationRevisionSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			values := [...]int64{networkRevision, inventoryRevision, 1, 1, 1, 1, 1, 1}
			for index, value := range values {
				*destinations[index].(*int64) = value
			}
			return nil
		},
	})
}

func enqueueNodeKeyRotationTarget(
	t *testing.T,
	transaction *fakeDeviceRevocationTransaction,
	command keyrotation.Command,
	currentNodeKey node.Key,
	deviceVersion int64,
	sessionGeneration int64,
	nodeKeyEpoch int64,
	validFrom time.Time,
) {
	t.Helper()
	machineKey := command.MachineKey().Bytes()
	nodeKey := currentNodeKey.Bytes()
	nodeID := nodeKeyRotationNodeIDFixture(t)
	transaction.enqueueRow(lockNodeKeyRotationTargetSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 301
			*destinations[1].(*string) = nodeID.String()
			*destinations[2].(*string) = "node-one.example"
			*destinations[3].(*int64) = deviceVersion
			*destinations[4].(*int64) = sessionGeneration
			*destinations[5].(*int64) = nodeKeyEpoch
			*destinations[6].(*[]byte) = append([]byte(nil), machineKey[:]...)
			*destinations[7].(*int64) = 321
			*destinations[8].(*int64) = 1
			*destinations[9].(*[]byte) = append([]byte(nil), nodeKey[:]...)
			*destinations[10].(*time.Time) = validFrom
			return nil
		},
	})
}

func enqueueNodeKeyRotationApply(transaction *fakeDeviceRevocationTransaction) {
	transaction.enqueueRow(expireNodeKeyRotationEpochSQL, nodeKeyRotationInt64Row(2))
	transaction.enqueueRow(insertNodeKeyRotationEpochSQL, nodeKeyRotationInt64Row(1))
	transaction.enqueueRow(rotateDeviceNodeKeySQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 5
			*destinations[1].(*int64) = 4
			*destinations[2].(*int64) = 3
			return nil
		},
	})
	transaction.enqueueRow(advanceNodeKeyRotationRevisionSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 11
			*destinations[1].(*int64) = 8
			return nil
		},
	})
	transaction.enqueueRow(appendNodeKeyRotationEvidenceSQL, nodeKeyRotationInt64Row(4))
}

func nodeKeyRotationInt64Row(value int64) deviceRevocationTestRow {
	return deviceRevocationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = value
		return nil
	}}
}

func nodeKeyRotationCommandFixture(t *testing.T) keyrotation.Command {
	t.Helper()
	operationID, err := enrollment.ParseRegistrationID("01890f90-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("enrollment.ParseRegistrationID() error = %v", err)
	}
	machineKey, err := node.NewMachineKey([32]byte{0: 1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	oldNodeKey, err := node.NewKey([32]byte{0: 2})
	if err != nil {
		t.Fatalf("node.NewKey(old) error = %v", err)
	}
	newNodeKey, err := node.NewKey([32]byte{0: 3})
	if err != nil {
		t.Fatalf("node.NewKey(new) error = %v", err)
	}
	command, err := keyrotation.NewCommand(keyrotation.CommandParams{
		OperationID: operationID,
		MachineKey:  machineKey,
		OldNodeKey:  oldNodeKey,
		NewNodeKey:  newNodeKey,
	})
	if err != nil {
		t.Fatalf("keyrotation.NewCommand() error = %v", err)
	}
	return command
}

func nodeKeyRotationMutationIDsFixture(t *testing.T) keyrotation.MutationIDs {
	t.Helper()
	ids, err := keyrotation.NewMutationIDs(keyrotation.MutationIDParams{
		ChangeID:       nodeKeyRotationPublicIDFixture(t, "000000000010"),
		NodeKeyEpochID: nodeKeyRotationPublicIDFixture(t, "000000000011"),
		AuditEventID:   nodeKeyRotationPublicIDFixture(t, "000000000012"),
		OutboxEventID:  nodeKeyRotationPublicIDFixture(t, "000000000013"),
	})
	if err != nil {
		t.Fatalf("keyrotation.NewMutationIDs() error = %v", err)
	}
	return ids
}

func nodeKeyRotationScopeFixture(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f90-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f90-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func nodeKeyRotationNodeIDFixture(t *testing.T) node.ID {
	t.Helper()
	id, err := node.ParseID("01890f90-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	return id
}

func nodeKeyRotationPublicIDFixture(t *testing.T, suffix string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse("01890f90-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}

func nodeKeyRotationTimeFixture() time.Time {
	return time.Date(2026, time.September, 16, 4, 5, 6, 0, time.UTC)
}

func TestNodeKeyRotationResolveReadsTheBudgetUnderTheDeviceLock(t *testing.T) {
	t.Parallel()

	command := nodeKeyRotationCommandFixture(t)
	decisionTime := nodeKeyRotationTimeFixture()
	budgetStart := decisionTime.Add(-30 * time.Minute)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueNodeKeyRotationSetup(t, databaseTransaction, command)
	enqueueNodeKeyRotationRevisions(databaseTransaction, 10, 7)
	enqueueNodeKeyRotationTarget(t, databaseTransaction, command, command.OldNodeKey(), 4, 3, 6,
		decisionTime.Add(-time.Minute))
	databaseTransaction.enqueueRow(readNodeKeyRotationBudgetSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*time.Time) = budgetStart
			return nil
		},
	})
	databaseTransaction.enqueueRow(lockNodeKeyRotationAuditStreamSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 3
			*destinations[1].(*int64) = 4
			*destinations[2].(*[]byte) = make([]byte, 32)
			return nil
		},
	})
	store := beginTestNodeKeyRotationStore(t, databaseTransaction)
	transaction, err := store.Begin(t.Context(), command)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := transaction.Resolve(t.Context(), command); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	var budgetCall *deviceRevocationTestCall
	for index := range databaseTransaction.calls {
		if databaseTransaction.calls[index].query == readNodeKeyRotationBudgetSQL {
			budgetCall = &databaseTransaction.calls[index]
		}
	}
	if budgetCall == nil {
		t.Fatal("the rotation budget was not read")
	}
	// Epoch 6 is the Device's fifth key change; the budget compares with
	// the oldest of the last four, epoch 3, of the locked Device.
	if got := budgetCall.arguments[2:]; !reflect.DeepEqual(got, []any{int64(301), int64(3)}) {
		t.Fatalf("budget arguments = %#v, want Device 301 epoch 3", got)
	}
}

func TestNodeKeyRotationResolveRefusesMissingBudgetEvidence(t *testing.T) {
	t.Parallel()

	command := nodeKeyRotationCommandFixture(t)
	databaseTransaction := newFakeDeviceRevocationTransaction()
	enqueueNodeKeyRotationSetup(t, databaseTransaction, command)
	enqueueNodeKeyRotationRevisions(databaseTransaction, 10, 7)
	enqueueNodeKeyRotationTarget(t, databaseTransaction, command, command.OldNodeKey(), 4, 3, 6,
		nodeKeyRotationTimeFixture())
	databaseTransaction.enqueueRow(readNodeKeyRotationBudgetSQL, deviceRevocationTestRow{
		scan: func(...any) error { return pgx.ErrNoRows },
	})
	store := beginTestNodeKeyRotationStore(t, databaseTransaction)
	transaction, err := store.Begin(t.Context(), command)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := transaction.Resolve(t.Context(), command); !errors.Is(err, ErrNodeKeyRotationEvidence) {
		t.Fatalf("Resolve() error = %v, want missing budget evidence", err)
	}
}
