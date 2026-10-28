package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	addKubernetesCADataKeySQL = `SELECT mesh_ops.add_kubernetes_ca_data_key_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::TEXT,$7::TEXT,$8::BYTEA,$9::TEXT,$10::TEXT)::TEXT`
	rewrapKubernetesCADataKeySQL = `SELECT mesh_ops.rewrap_kubernetes_ca_data_key_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::UUID,$7::TEXT,$8::TEXT,$9::BYTEA,$10::TEXT,$11::TEXT)::TEXT`
	retireKubernetesCADataKeySQL = `SELECT mesh_ops.retire_kubernetes_ca_data_key_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::UUID,$7::TEXT,$8::TEXT)::TEXT`
)

func validWrapped(wrapped kubeca.WrappedKey) bool {
	return (wrapped.Custody == "file" || wrapped.Custody == "kms") && wrapped.KeyID != "" &&
		len(wrapped.Ciphertext) > 0
}

// dataKeyChange runs one data key change under the Network's lock, with
// its sealed audit event, redone whole on a serialization conflict.
// existing is true when the Network already had an active data key to add.
func (store *KubernetesClusterCAStore) dataKeyChange(ctx context.Context, installation deployment.ID,
	scope network.Scope, row publicid.ID, operator kubeca.Operator,
	call func(transaction outboxTransaction, change publicid.ID) (string, error),
) (existing bool, resultErr error) {
	if !store.valid(ctx, installation) || !scope.IsValid() || !row.IsValid() || !operator.Valid() {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	return retryReadConflict(ctx, func() (bool, error) {
		existing := false
		err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
			change, err := freshPublicID()
			if err != nil {
				return false, errors.Join(ErrKubernetesClusterCAStore, err)
			}
			encoded, err := call(transaction, change)
			if err != nil {
				return false, errors.Join(ErrKubernetesClusterCAStore, err)
			}
			var head struct {
				Outcome string `json:"outcome"`
			}
			if err := json.Unmarshal([]byte(encoded), &head); err != nil {
				return false, ErrKubernetesClusterCAStore
			}
			if head.Outcome == "existing" {
				if encoded != `{"outcome": "existing"}` {
					return false, ErrKubernetesClusterCAStore
				}
				existing = true
				return false, nil
			}
			proof, err := decodeCAProof(encoded, caDataKeyAggregateKind, row, operator)
			if err != nil {
				return false, err
			}
			apply := clusterCAChange{
				ctx: ctx, transaction: transaction, installation: installation, scope: scope,
				operator: operator,
			}
			return true, apply.evidence(proof, change)
		})
		return existing, err
	})
}

// operatorArguments are the actor and change record columns: NULL for the
// worker's own change.
func operatorArguments(operator kubeca.Operator) (any, any) {
	if operator.IsWorker() {
		return nil, nil
	}
	return operator.Name, operator.ChangeRef
}

// AddDataKey stores a new active data key for the Network, wrapped by the
// custody, unless it has one already or another worker holds the Network:
// added is false then, and the caller reads the Network again.
func (store *KubernetesClusterCAStore) AddDataKey(ctx context.Context, installation deployment.ID,
	scope network.Scope, id publicid.ID, wrapped kubeca.WrappedKey, operator kubeca.Operator,
) (bool, error) {
	if !validWrapped(wrapped) {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	actor, changeRef := operatorArguments(operator)
	existing, err := store.dataKeyChange(ctx, installation, scope, id, operator,
		func(transaction outboxTransaction, change publicid.ID) (string, error) {
			var encoded string
			err := transaction.QueryRow(ctx, addKubernetesCADataKeySQL, installation.String(),
				scope.WorkspaceID().String(), scope.NetworkID().String(), id.String(), change.String(), wrapped.Custody,
				wrapped.KeyID, wrapped.Ciphertext, actor, changeRef).Scan(&encoded)
			return encoded, err
		})
	if errors.Is(err, ErrKubernetesClusterCABusy) {
		return false, nil
	}
	return err == nil && !existing, err
}

// RewrapDataKey wraps a data key again, under another custody key, if it
// is still at version: the data key and its CAs do not change (§17.1 C1).
func (store *KubernetesClusterCAStore) RewrapDataKey(ctx context.Context, installation deployment.ID,
	scope network.Scope, id publicid.ID, version int64, wrapped kubeca.WrappedKey, operator kubeca.Operator,
) error {
	if !validWrapped(wrapped) || version < 1 {
		return ErrInvalidKubernetesClusterCAStore
	}
	actor, changeRef := operatorArguments(operator)
	_, err := store.dataKeyChange(ctx, installation, scope, id, operator,
		func(transaction outboxTransaction, change publicid.ID) (string, error) {
			var encoded string
			err := transaction.QueryRow(ctx, rewrapKubernetesCADataKeySQL, installation.String(),
				scope.WorkspaceID().String(), scope.NetworkID().String(), id.String(), version, change.String(),
				wrapped.Custody, wrapped.KeyID, wrapped.Ciphertext, actor, changeRef).Scan(&encoded)
			return encoded, err
		})
	return err
}

// RotateDataKey retires the Network's active data key, if it is still at
// version, and adds a new one, in one transaction holding the Network's
// lock: no worker adds a key between the two (review a2a M2), and new CAs
// never meet a Network without an active key.
func (store *KubernetesClusterCAStore) RotateDataKey(ctx context.Context, installation deployment.ID,
	scope network.Scope, old publicid.ID, version int64, id publicid.ID, wrapped kubeca.WrappedKey,
	operator kubeca.Operator,
) error {
	if !store.valid(ctx, installation) || !scope.IsValid() || !old.IsValid() || !id.IsValid() || old == id ||
		version < 1 || !validWrapped(wrapped) || operator.IsWorker() || !operator.Valid() {
		return ErrInvalidKubernetesClusterCAStore
	}
	actor, changeRef := operatorArguments(operator)
	_, err := retryReadConflict(ctx, func() (bool, error) {
		return false, store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
			apply := clusterCAChange{
				ctx: ctx, transaction: transaction, installation: installation, scope: scope,
				operator: operator,
			}
			for _, call := range []struct {
				row       publicid.ID
				statement string
				arguments func(change publicid.ID) []any
			}{
				{old, retireKubernetesCADataKeySQL, func(change publicid.ID) []any {
					return []any{
						installation.String(), scope.WorkspaceID().String(), scope.NetworkID().String(),
						old.String(), version, change.String(), actor, changeRef,
					}
				}},
				{id, addKubernetesCADataKeySQL, func(change publicid.ID) []any {
					return []any{
						installation.String(), scope.WorkspaceID().String(), scope.NetworkID().String(),
						id.String(), change.String(), wrapped.Custody, wrapped.KeyID, wrapped.Ciphertext, actor,
						changeRef,
					}
				}},
			} {
				change, err := freshPublicID()
				if err != nil {
					return false, errors.Join(ErrKubernetesClusterCAStore, err)
				}
				var encoded string
				if err := transaction.QueryRow(ctx, call.statement, call.arguments(change)...).Scan(&encoded); err != nil {
					return false, errors.Join(ErrKubernetesClusterCAStore, err)
				}
				proof, err := decodeCAProof(encoded, caDataKeyAggregateKind, call.row, operator)
				if err != nil {
					return false, err
				}
				if err := apply.evidence(proof, change); err != nil {
					return false, err
				}
			}
			return true, nil
		})
	})
	return err
}

// RetireDataKey retires the Network's active data key if it is still at
// version: new CAs then need a new one, and CAs it sealed still open
// under it until they retire.
func (store *KubernetesClusterCAStore) RetireDataKey(ctx context.Context, installation deployment.ID,
	scope network.Scope, id publicid.ID, version int64, operator kubeca.Operator,
) error {
	if version < 1 {
		return ErrInvalidKubernetesClusterCAStore
	}
	actor, changeRef := operatorArguments(operator)
	_, err := store.dataKeyChange(ctx, installation, scope, id, operator,
		func(transaction outboxTransaction, change publicid.ID) (string, error) {
			var encoded string
			err := transaction.QueryRow(ctx, retireKubernetesCADataKeySQL, installation.String(),
				scope.WorkspaceID().String(), scope.NetworkID().String(), id.String(), version, change.String(),
				actor, changeRef).Scan(&encoded)
			return encoded, err
		})
	return err
}
