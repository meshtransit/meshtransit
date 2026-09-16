package keyrotation_test

import (
	"context"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/node/keyrotation"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestServiceRotatesOneAuthenticatedNodeKeyEpoch(t *testing.T) {
	t.Parallel()

	command := rotationCommand(t)
	resolution := openResolution(t, command)
	transaction := &rotationTransaction{resolution: resolution}
	service, err := keyrotation.NewService(
		keyrotation.Options{MaxAttempts: 3, RollbackTimeout: time.Second},
		keyrotation.Dependencies{
			Transactions: &rotationTransactions{transaction: transaction},
			MutationIDs:  rotationIDGenerator{ids: rotationMutationIDs(t)},
			Clock:        rotationClock{now: rotationTime()},
			Retry:        rotationRetry{},
		},
	)
	if err != nil {
		t.Fatalf("keyrotation.NewService() error = %v", err)
	}

	result, err := service.Rotate(t.Context(), command)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !result.IsValid() || result.NodeID() != resolution.NodeID() ||
		result.NodeKeyEpoch() != resolution.NodeKeyEpoch()+1 ||
		result.SessionGeneration() != resolution.SessionGeneration()+1 ||
		result.NetworkRevision() != resolution.NetworkRevision()+1 {
		t.Fatalf("Rotate() result = %#v, want one atomic epoch/session/revision advance", result)
	}
	if !transaction.applied || !transaction.committed || transaction.rolledBack {
		t.Fatalf("transaction state = applied:%t committed:%t rolledBack:%t", transaction.applied, transaction.committed, transaction.rolledBack)
	}
}

func TestServiceReturnsCommittedReplayWithoutMutation(t *testing.T) {
	t.Parallel()

	command := rotationCommand(t)
	open := openResolution(t, command)
	committed, err := keyrotation.NewResult(keyrotation.ResultParams{
		OperationID:       command.OperationID(),
		Scope:             open.Scope(),
		NodeID:            open.NodeID(),
		Hostname:          open.Hostname(),
		DeviceVersion:     open.DeviceVersion() + 1,
		NodeKeyEpoch:      open.NodeKeyEpoch() + 1,
		SessionGeneration: open.SessionGeneration() + 1,
		NetworkRevision:   open.NetworkRevision() + 1,
		InventoryRevision: open.InventoryRevision() + 1,
	})
	if err != nil {
		t.Fatalf("keyrotation.NewResult() error = %v", err)
	}
	resolution, err := keyrotation.NewCompletedResolution(committed)
	if err != nil {
		t.Fatalf("keyrotation.NewCompletedResolution() error = %v", err)
	}
	transaction := &rotationTransaction{resolution: resolution}
	service, err := keyrotation.NewService(
		keyrotation.Options{MaxAttempts: 1, RollbackTimeout: time.Second},
		keyrotation.Dependencies{
			Transactions: &rotationTransactions{transaction: transaction},
			MutationIDs:  rotationIDGenerator{ids: rotationMutationIDs(t)},
			Clock:        rotationClock{now: rotationTime()},
			Retry:        rotationRetry{},
		},
	)
	if err != nil {
		t.Fatalf("keyrotation.NewService() error = %v", err)
	}

	result, err := service.Rotate(t.Context(), command)
	if err != nil {
		t.Fatalf("Rotate(replay) error = %v", err)
	}
	if result != committed || transaction.applied || transaction.committed || !transaction.rolledBack {
		t.Fatal("committed replay mutated durable authority")
	}
}

type rotationTransactions struct{ transaction *rotationTransaction }

func (transactions *rotationTransactions) Begin(
	context.Context,
	keyrotation.Command,
) (keyrotation.Transaction, error) {
	return transactions.transaction, nil
}

type rotationTransaction struct {
	resolution keyrotation.Resolution
	applied    bool
	committed  bool
	rolledBack bool
}

func (transaction *rotationTransaction) Resolve(
	context.Context,
	keyrotation.Command,
) (keyrotation.Resolution, error) {
	return transaction.resolution, nil
}

func (transaction *rotationTransaction) Apply(
	_ context.Context,
	change keyrotation.Change,
) (keyrotation.Result, error) {
	transaction.applied = true
	resolution := change.Resolution()
	return keyrotation.NewResult(keyrotation.ResultParams{
		OperationID:       change.Command().OperationID(),
		Scope:             resolution.Scope(),
		NodeID:            resolution.NodeID(),
		Hostname:          resolution.Hostname(),
		DeviceVersion:     resolution.DeviceVersion() + 1,
		NodeKeyEpoch:      resolution.NodeKeyEpoch() + 1,
		SessionGeneration: resolution.SessionGeneration() + 1,
		NetworkRevision:   resolution.NetworkRevision() + 1,
		InventoryRevision: resolution.InventoryRevision() + 1,
	})
}

func (transaction *rotationTransaction) Commit(context.Context) error {
	transaction.committed = true
	return nil
}

func (transaction *rotationTransaction) Rollback(context.Context) error {
	transaction.rolledBack = true
	return nil
}

type rotationIDGenerator struct{ ids keyrotation.MutationIDs }

func (generator rotationIDGenerator) NewMutationIDs() (keyrotation.MutationIDs, error) {
	return generator.ids, nil
}

type rotationClock struct{ now time.Time }

func (clock rotationClock) Now() time.Time { return clock.now }

type rotationRetry struct{}

func (rotationRetry) Wait(context.Context, int) error { return nil }

func rotationCommand(t *testing.T) keyrotation.Command {
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

func openResolution(t *testing.T, command keyrotation.Command) keyrotation.Resolution {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f90-0000-7000-8000-000000000002")
	networkID, _ := network.ParseID("01890f90-0000-7000-8000-000000000003")
	scope, _ := network.NewScope(workspaceID, networkID)
	nodeID, _ := node.ParseID("01890f90-0000-7000-8000-000000000004")
	hostname, _ := node.ParseHostname("node-one.example")
	resolution, err := keyrotation.NewOpenResolution(keyrotation.OpenResolutionParams{
		Scope:             scope,
		NodeID:            nodeID,
		Hostname:          hostname,
		MachineKey:        command.MachineKey(),
		CurrentNodeKey:    command.OldNodeKey(),
		NetworkRevision:   10,
		InventoryRevision: 7,
		DeviceVersion:     4,
		SessionGeneration: 3,
		NodeKeyEpoch:      2,
		NodeKeyVersion:    1,
		NodeKeyValidFrom:  rotationTime().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("keyrotation.NewOpenResolution() error = %v", err)
	}
	return resolution
}

func rotationMutationIDs(t *testing.T) keyrotation.MutationIDs {
	t.Helper()
	values := [...]string{
		"01890f90-0000-7000-8000-000000000010",
		"01890f90-0000-7000-8000-000000000011",
		"01890f90-0000-7000-8000-000000000012",
		"01890f90-0000-7000-8000-000000000013",
	}
	ids := make([]publicid.ID, len(values))
	for index, value := range values {
		id, err := publicid.Parse(value)
		if err != nil {
			t.Fatalf("publicid.Parse() error = %v", err)
		}
		ids[index] = id
	}
	result, err := keyrotation.NewMutationIDs(keyrotation.MutationIDParams{
		ChangeID:       ids[0],
		NodeKeyEpochID: ids[1],
		AuditEventID:   ids[2],
		OutboxEventID:  ids[3],
	})
	if err != nil {
		t.Fatalf("keyrotation.NewMutationIDs() error = %v", err)
	}
	return result
}

func rotationTime() time.Time {
	return time.Date(2026, time.September, 16, 4, 5, 6, 0, time.UTC)
}
