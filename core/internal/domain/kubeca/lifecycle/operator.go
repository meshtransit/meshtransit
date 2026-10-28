package lifecycle

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// OperatorStore is what the operator's commands change (K1a4 §17.6): each
// change names the operator and the change record in the audit trail.
type OperatorStore interface {
	Read(ctx context.Context, installation deployment.ID, scope network.Scope) (kubeca.Network, error)
	Change(ctx context.Context, installation deployment.ID, scope network.Scope,
		plan func(kubeca.Network) (kubeca.Changes, error)) (bool, error)
	AddDataKey(ctx context.Context, installation deployment.ID, scope network.Scope, id publicid.ID,
		wrapped kubeca.WrappedKey, operator kubeca.Operator) (bool, error)
	RewrapDataKey(ctx context.Context, installation deployment.ID, scope network.Scope, id publicid.ID,
		version int64, wrapped kubeca.WrappedKey, operator kubeca.Operator) error
	RotateDataKey(ctx context.Context, installation deployment.ID, scope network.Scope, old publicid.ID,
		version int64, id publicid.ID, wrapped kubeca.WrappedKey, operator kubeca.Operator) error
}

// Rewrap wraps every data key of a Network that the custody's current key
// does not wrap yet, keeping the keys and their CAs (§17.1 C1). It returns
// how many it wrapped. Run it for every Network after a new wrap key
// becomes primary, then drop the old key from the previous keys.
func Rewrap(ctx context.Context, store OperatorStore, custody kubeca.Custody, installation deployment.ID,
	scope network.Scope, operator kubeca.Operator,
) (int, error) {
	if operator.IsWorker() || !operator.Valid() || custody == nil {
		return 0, kubeca.ErrInvalid
	}
	read, err := store.Read(ctx, installation, scope)
	if err != nil {
		return 0, err
	}
	network := scope.NetworkID().String()
	count := 0
	for _, stored := range read.DataKeys {
		dataKey, err := custody.OpenDataKey(ctx, network, stored.Wrapped)
		if err != nil {
			return count, err
		}
		wrapped, err := custody.WrapDataKey(ctx, network, dataKey)
		if err != nil {
			return count, err
		}
		if wrapped.Custody == stored.Wrapped.Custody && wrapped.KeyID == stored.Wrapped.KeyID {
			continue
		}
		// The new wrapping must give back the same key, or every CA it
		// sealed would never open again (review a2a L5).
		if again, err := custody.OpenDataKey(ctx, network, wrapped); err != nil || again != dataKey {
			return count, errors.Join(kubeca.ErrInvalid, err)
		}
		if err := store.RewrapDataKey(ctx, installation, scope, stored.ID, stored.Version, wrapped,
			operator); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// RotateDataKey retires a Network's active data key and adds a new one in
// one transaction: new CAs are sealed under the new key, and CAs the old
// one sealed still open under it until they retire. It returns the new
// key's ID.
func RotateDataKey(ctx context.Context, store OperatorStore, custody kubeca.Custody, installation deployment.ID,
	scope network.Scope, operator kubeca.Operator,
) (publicid.ID, error) {
	if operator.IsWorker() || !operator.Valid() || custody == nil {
		return publicid.ID{}, kubeca.ErrInvalid
	}
	read, err := store.Read(ctx, installation, scope)
	if err != nil {
		return publicid.ID{}, err
	}
	network := scope.NetworkID().String()
	active := activeDataKey(read)
	// The custody must open the key it replaces: a wrong key file would
	// otherwise install a key no worker can open (review a2 M-B).
	if active != nil {
		if _, err := custody.OpenDataKey(ctx, network, active.Wrapped); err != nil {
			return publicid.ID{}, errors.Join(kubeca.ErrMisconfigured, err)
		}
	}
	dataKey, wrapped, err := custody.NewDataKey(ctx, network)
	if err != nil {
		return publicid.ID{}, err
	}
	if again, err := custody.OpenDataKey(ctx, network, wrapped); err != nil || again != dataKey {
		return publicid.ID{}, errors.Join(kubeca.ErrInvalid, err)
	}
	id, err := publicid.New()
	if err != nil {
		return publicid.ID{}, err
	}
	if active == nil {
		added, err := store.AddDataKey(ctx, installation, scope, id, wrapped, operator)
		if err == nil && !added {
			err = ErrBusy
		}
		if err != nil {
			return publicid.ID{}, err
		}
		return id, nil
	}
	if err := store.RotateDataKey(ctx, installation, scope, active.ID, active.Version, id, wrapped,
		operator); err != nil {
		return publicid.ID{}, err
	}
	return id, nil
}

// RetireCA retires one CA at once, for a compromise, an emergency or by an
// administrator's choice: a root together with every intermediate of it
// still trusted. The worker then gives the cluster new CAs; clients that
// trusted a retired root need the new one (§17.2).
func RetireCA(ctx context.Context, store OperatorStore, installation deployment.ID, scope network.Scope,
	ca publicid.ID, reason kubeca.Reason, operator kubeca.Operator,
) error {
	if operator.IsWorker() || !operator.Valid() || !ca.IsValid() ||
		reason != kubeca.ReasonCompromise && reason != kubeca.ReasonEmergency && reason != kubeca.ReasonAdmin {
		return kubeca.ErrInvalid
	}
	busy, err := store.Change(ctx, installation, scope, func(locked kubeca.Network) (kubeca.Changes, error) {
		for _, cluster := range locked.Clusters {
			for _, target := range cluster.CAs {
				if target.ID != ca {
					continue
				}
				changes := kubeca.Changes{Operator: operator, Schedules: []kubeca.Schedule{
					{Cluster: cluster.ID, At: locked.Now},
				}}
				if target.Kind == kubeca.KindRoot {
					for _, below := range cluster.CAs {
						if below.Kind == kubeca.KindIntermediate && below.IssuerID == target.ID {
							changes.Steps = append(changes.Steps, retireStep(below, reason))
						}
					}
				}
				changes.Steps = append(changes.Steps, retireStep(target, reason))
				return changes, nil
			}
		}
		return kubeca.Changes{}, kubeca.ErrInvalid
	})
	if err == nil && busy {
		// Nothing was retired: say so, never report a retirement that did
		// not happen (review a2 H-B).
		return ErrBusy
	}
	return err
}

func retireStep(ca kubeca.StoredCA, reason kubeca.Reason) kubeca.Step {
	return kubeca.Step{Move: &kubeca.Move{CA: ca.ID, Version: ca.Version, To: kubeca.StateRetired, Reason: reason}}
}
