package lifecycle

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
)

const (
	// reconcileRounds bounds how often reconcile lists what is left; each
	// round retires up to reconcileBatch intermediates.
	reconcileRounds = 64
	reconcileBatch  = 64
	// reconcilePause is the wait after a round that retired nothing.
	reconcilePause = time.Second
)

var (
	// ErrReconcileIncomplete reports intermediates still active after
	// reconcile's rounds, or retired by another writer in the meantime:
	// run it again.
	ErrReconcileIncomplete = errors.New("kubernetes CA reconcile: intermediates are still active")
	// ErrReconcileStale reports another operator reconciled in the meantime.
	ErrReconcileStale = errors.New("kubernetes CA reconcile: the guard changed")
)

// RestoreStore is what the restore commands need (the postgres adapter).
type RestoreStore interface {
	ReadGuard(ctx context.Context, installation deployment.ID) (kubeca.Guard, error)
	MarkRestored(ctx context.Context, installation deployment.ID, operator kubeca.Operator) error
	ListActiveIntermediates(ctx context.Context, installation deployment.ID, limit int) ([]kubeca.IntermediateRef,
		error)
	ClearRestore(ctx context.Context, installation deployment.ID, generation int64, operator kubeca.Operator) (bool,
		error)
	Change(ctx context.Context, installation deployment.ID, scope network.Scope,
		plan func(kubeca.Network) (kubeca.Changes, error)) (bool, error)
}

// MarkRestored stops the installation's CA work after a database restore,
// before the worker would notice: the runbook's mandatory first step (a3
// §5).
func MarkRestored(ctx context.Context, store RestoreStore, installation deployment.ID,
	operator kubeca.Operator,
) error {
	if operator.IsWorker() || !operator.Valid() {
		return kubeca.ErrInvalid
	}
	return store.MarkRestored(ctx, installation, operator)
}

// ReconcileAfterRestore resumes CA work after a restore (§5): it stops CA
// work if nothing did yet, retires every active intermediate (clients trust
// the roots only, so nothing breaks, and an intermediate retired before the
// restore cannot sign again), then clears the guard. It returns how many it
// retired. What a restore brings back that only records outside the
// database can tell (roots retired for a compromise, revoked Devices,
// deleted clusters) is the operator's to check.
func ReconcileAfterRestore(ctx context.Context, store RestoreStore, installation deployment.ID,
	operator kubeca.Operator,
) (int, error) {
	if operator.IsWorker() || !operator.Valid() {
		return 0, kubeca.ErrInvalid
	}
	guard, err := store.ReadGuard(ctx, installation)
	if err != nil {
		return 0, err
	}
	if !guard.Suspected {
		if err := store.MarkRestored(ctx, installation, operator); err != nil {
			return 0, err
		}
		if guard, err = store.ReadGuard(ctx, installation); err != nil {
			return 0, err
		}
	}
	retired := 0
	for range reconcileRounds {
		left, err := store.ListActiveIntermediates(ctx, installation, reconcileBatch)
		if err != nil {
			return retired, err
		}
		if len(left) == 0 {
			cleared, err := store.ClearRestore(ctx, installation, guard.Generation, operator)
			switch {
			case errors.Is(err, kubeca.ErrIntermediatesActive):
				// One became active since the listing: list again.
				continue
			case err != nil:
				return retired, err
			case !cleared:
				return retired, ErrReconcileStale
			}
			return retired, nil
		}
		before := retired
		for _, intermediate := range left {
			done, err := retireIntermediate(ctx, store, installation, intermediate, operator)
			if err != nil && !errors.Is(err, ErrBusy) && !errors.Is(err, errStaleIntermediate) {
				return retired, err
			}
			if done {
				retired++
			}
		}
		if retired == before {
			// Every Network was busy or changed: give the holder a moment.
			select {
			case <-ctx.Done():
				return retired, ctx.Err()
			case <-time.After(reconcilePause):
			}
		}
	}
	return retired, ErrReconcileIncomplete
}

var errStaleIntermediate = errors.New("kubernetes CA reconcile: the intermediate changed")

// retireIntermediate retires one intermediate at the version listed and
// asks its cluster's next look at once, so it gets a new one as soon as CA
// work resumes. A busy Network or a changed intermediate is listed again.
func retireIntermediate(ctx context.Context, store RestoreStore, installation deployment.ID,
	intermediate kubeca.IntermediateRef, operator kubeca.Operator,
) (bool, error) {
	busy, err := store.Change(ctx, installation, intermediate.Scope, func(locked kubeca.Network) (kubeca.Changes,
		error,
	) {
		return kubeca.Changes{
			Operator: operator,
			Steps: []kubeca.Step{{Move: &kubeca.Move{
				CA: intermediate.CA, Version: intermediate.Version, To: kubeca.StateRetired,
				Reason: kubeca.ReasonEmergency,
			}}},
			Schedules: []kubeca.Schedule{{Cluster: intermediate.Cluster, At: locked.Now}},
		}, nil
	})
	switch {
	case errors.Is(err, kubeca.ErrStale):
		return false, errStaleIntermediate
	case err != nil:
		return false, err
	case busy:
		return false, ErrBusy
	}
	return true, nil
}
