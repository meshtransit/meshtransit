package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
)

// restoreStore holds a guard and the active intermediates.
type restoreStore struct {
	guard     kubeca.Guard
	active    []kubeca.IntermediateRef
	changes   []kubeca.Changes
	busyOnce  bool
	cleared   []int64
	marked    int
	clearFail bool
}

func (store *restoreStore) ReadGuard(context.Context, deployment.ID) (kubeca.Guard, error) {
	return store.guard, nil
}

func (store *restoreStore) MarkRestored(context.Context, deployment.ID, kubeca.Operator) error {
	store.marked++
	store.guard.Suspected = true
	return nil
}

func (store *restoreStore) ListActiveIntermediates(context.Context, deployment.ID, int) ([]kubeca.IntermediateRef,
	error,
) {
	return append([]kubeca.IntermediateRef(nil), store.active...), nil
}

func (store *restoreStore) ClearRestore(_ context.Context, _ deployment.ID, generation int64,
	_ kubeca.Operator,
) (bool, error) {
	if store.clearFail || generation != store.guard.Generation {
		return false, nil
	}
	store.cleared = append(store.cleared, generation)
	store.guard.Suspected, store.guard.Generation = false, generation+1
	return true, nil
}

func (store *restoreStore) Change(_ context.Context, _ deployment.ID, _ network.Scope,
	plan func(kubeca.Network) (kubeca.Changes, error),
) (bool, error) {
	if store.busyOnce {
		store.busyOnce = false
		return true, nil
	}
	changes, err := plan(kubeca.Network{Now: time.Now()})
	if err != nil {
		return false, err
	}
	store.changes = append(store.changes, changes)
	for _, step := range changes.Steps {
		for index, active := range store.active {
			if active.CA == step.Move.CA {
				store.active = append(store.active[:index], store.active[index+1:]...)
				break
			}
		}
	}
	return false, nil
}

func TestReconcileAfterRestoreRetiresEveryIntermediate(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	first := kubeca.IntermediateRef{Scope: scope, Cluster: testID(t), CA: testID(t), Version: 3}
	second := kubeca.IntermediateRef{Scope: scope, Cluster: testID(t), CA: testID(t), Version: 1}
	store := &restoreStore{
		guard:  kubeca.Guard{Generation: 4, ReadStarted: time.Now(), ReadFinished: time.Now()},
		active: []kubeca.IntermediateRef{first, second}, busyOnce: true,
	}
	operator := kubeca.Operator{Name: "soc@example.com", ChangeRef: "INC-11"}
	retired, err := ReconcileAfterRestore(t.Context(), store, testInstallation(t), operator)
	if err != nil || retired != 2 || store.marked != 1 || len(store.cleared) != 1 || store.cleared[0] != 4 ||
		store.guard.Suspected {
		t.Fatalf("ReconcileAfterRestore() = %d, %v; store %+v", retired, err, store)
	}
	for _, changes := range store.changes {
		move := changes.Steps[0].Move
		if changes.Operator != operator || move.To != kubeca.StateRetired || move.Reason != kubeca.ReasonEmergency ||
			len(changes.Schedules) != 1 {
			t.Fatalf("changes %+v", changes)
		}
	}
	// The busy Network is retried; each is retired at the version listed.
	for _, changes := range store.changes {
		if move := changes.Steps[0].Move; move.CA == first.CA && move.Version != 3 {
			t.Fatalf("retired at version %d, want the listed one", move.Version)
		}
	}
}

func TestReconcileAfterRestoreRefuses(t *testing.T) {
	t.Parallel()
	store := &restoreStore{guard: kubeca.Guard{Suspected: true, Generation: 1, ReadStarted: time.Now(), ReadFinished: time.Now()}, clearFail: true}
	operator := kubeca.Operator{Name: "soc@example.com", ChangeRef: "INC-11"}
	if _, err := ReconcileAfterRestore(t.Context(), store, testInstallation(t), operator); !errors.Is(err,
		ErrReconcileStale) {
		t.Fatalf("a guard cleared meanwhile: %v", err)
	}
	if _, err := ReconcileAfterRestore(t.Context(), store, testInstallation(t), kubeca.Operator{}); !errors.Is(err,
		kubeca.ErrInvalid) {
		t.Fatalf("the worker reconciled: %v", err)
	}
	if err := MarkRestored(t.Context(), store, testInstallation(t), kubeca.Operator{}); !errors.Is(err,
		kubeca.ErrInvalid) {
		t.Fatalf("the worker marked a restore: %v", err)
	}
}

func testInstallation(t *testing.T) deployment.ID {
	t.Helper()
	installation, err := deployment.ParseID(testID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	return installation
}
