package keyrotation_test

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node/keyrotation"
)

// budgetResolution is the open resolution of a Device at its fifth epoch,
// whose budget epoch (2) became active at windowStart.
func budgetResolution(t *testing.T, command keyrotation.Command, windowStart time.Time) keyrotation.Resolution {
	t.Helper()
	base := openResolution(t, command)
	resolution, err := keyrotation.NewOpenResolution(keyrotation.OpenResolutionParams{
		Scope: base.Scope(), NodeID: base.NodeID(), Hostname: base.Hostname(), MachineKey: base.MachineKey(),
		CurrentNodeKey: base.CurrentNodeKey(), NetworkRevision: base.NetworkRevision(),
		InventoryRevision: base.InventoryRevision(), DeviceVersion: base.DeviceVersion(),
		SessionGeneration: base.SessionGeneration(), NodeKeyEpoch: 5, NodeKeyVersion: base.NodeKeyVersion(),
		NodeKeyValidFrom: rotationTime().Add(-time.Minute), BudgetWindowStart: windowStart,
	})
	if err != nil {
		t.Fatalf("keyrotation.NewOpenResolution() error = %v", err)
	}
	return resolution
}

func budgetService(t *testing.T, transaction *rotationTransaction) *keyrotation.Service {
	t.Helper()
	service, err := keyrotation.NewService(
		keyrotation.Options{MaxAttempts: 3, RollbackTimeout: time.Second},
		keyrotation.Dependencies{
			Transactions: &rotationTransactions{transaction: transaction},
			MutationIDs:  rotationIDGenerator{ids: rotationMutationIDs(t)},
			Retry:        rotationRetry{},
		},
	)
	if err != nil {
		t.Fatalf("keyrotation.NewService() error = %v", err)
	}
	return service
}

func TestServiceRefusesARotationOverTheDeviceBudget(t *testing.T) {
	t.Parallel()

	command := rotationCommand(t)
	// Four key changes within the last 20 minutes: the budget is spent until
	// the oldest of them leaves the window.
	transaction := &rotationTransaction{resolution: budgetResolution(t, command, rotationTime().Add(-20*time.Minute))}
	_, err := budgetService(t, transaction).Rotate(t.Context(), command)
	var limited *keyrotation.RateLimitedError
	if !errors.Is(err, keyrotation.ErrRateLimited) || !errors.As(err, &limited) {
		t.Fatalf("Rotate() error = %v, want the rotation budget", err)
	}
	if limited.RetryAfter != 40*time.Minute {
		t.Fatalf("RetryAfter = %s, want 40m", limited.RetryAfter)
	}
	if transaction.applied || transaction.committed || !transaction.rolledBack {
		t.Fatal("a refused rotation changed durable authority")
	}
}

func TestServiceRotatesOnceTheBudgetWindowPassed(t *testing.T) {
	t.Parallel()

	command := rotationCommand(t)
	transaction := &rotationTransaction{resolution: budgetResolution(t, command, rotationTime().Add(-keyrotation.RotationWindow))}
	if _, err := budgetService(t, transaction).Rotate(t.Context(), command); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !transaction.committed {
		t.Fatal("rotation outside the window was not committed")
	}
}

func TestBudgetEpoch(t *testing.T) {
	t.Parallel()

	for current, want := range map[int64]struct {
		epoch  int64
		counts bool
	}{1: {}, 4: {}, 5: {epoch: 2, counts: true}, 12: {epoch: 9, counts: true}} {
		epoch, counts := keyrotation.BudgetEpoch(current, false)
		if counts != want.counts || (counts && epoch != want.epoch) {
			t.Errorf("BudgetEpoch(%d) = %d, %t; want %d, %t", current, epoch, counts, want.epoch, want.counts)
		}
	}
	// A Kubernetes gateway rotates at every start: 30 an hour.
	for current, want := range map[int64]struct {
		epoch  int64
		counts bool
	}{5: {}, 30: {}, 31: {epoch: 2, counts: true}, 40: {epoch: 11, counts: true}} {
		epoch, counts := keyrotation.BudgetEpoch(current, true)
		if counts != want.counts || (counts && epoch != want.epoch) {
			t.Errorf("gateway BudgetEpoch(%d) = %d, %t; want %d, %t", current, epoch, counts, want.epoch,
				want.counts)
		}
	}
}

func TestOpenResolutionRequiresConsistentBudgetEvidence(t *testing.T) {
	t.Parallel()

	command := rotationCommand(t)
	base := openResolution(t, command)
	for name, params := range map[string]struct {
		epoch int64
		start time.Time
	}{
		"start without an epoch that counts": {epoch: 2, start: rotationTime().Add(-2 * time.Hour)},
		"epoch that counts without a start":  {epoch: 5},
	} {
		_, err := keyrotation.NewOpenResolution(keyrotation.OpenResolutionParams{
			Scope: base.Scope(), NodeID: base.NodeID(), Hostname: base.Hostname(), MachineKey: base.MachineKey(),
			CurrentNodeKey: base.CurrentNodeKey(), NetworkRevision: base.NetworkRevision(),
			InventoryRevision: base.InventoryRevision(), DeviceVersion: base.DeviceVersion(),
			SessionGeneration: base.SessionGeneration(), NodeKeyEpoch: params.epoch,
			NodeKeyVersion: base.NodeKeyVersion(), NodeKeyValidFrom: rotationTime().Add(-time.Minute),
			BudgetWindowStart: params.start,
		})
		if !errors.Is(err, keyrotation.ErrInvalidResolution) {
			t.Errorf("%s: error = %v, want ErrInvalidResolution", name, err)
		}
	}
}
