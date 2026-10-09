package mapsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/control"
	appmapsession "github.com/meshtransit/meshtransit/core/internal/control/mapsession"
)

var _ appmapsession.DeviceAliasVersionObserver = (*Store)(nil)

const observeDeviceAliasVersionSQL = `SELECT mesh_ops.observe_device_alias_version_v1($1::BYTEA,$2::BYTEA,$3::INTEGER)`

type aliasObservationDatabase interface {
	BeginWrite(context.Context) (databaseTransaction, error)
}

// ObserveDeviceAliasVersion binds compatibility metadata to the exact current
// authenticated session. It changes no permission, alias lease or packet policy.
func (store *Store) ObserveDeviceAliasVersion(ctx context.Context, identity control.AuthenticatedNode, version uint8) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || store.observer == nil || !validOptions(store.options) || !identity.IsValid() || version > 1 {
		return ErrInvalidStore
	}
	if !store.options.EnableDeviceAliases {
		return nil
	}
	startedAt := time.Now()
	defer func() {
		store.observer.ObserveMapSession(OperationObserveClientVersion, time.Since(startedAt), resultErr)
	}()
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrLoadSnapshot, err)
	}
	database, ok := store.database.(aliasObservationDatabase)
	if !ok {
		return ErrInvalidStore
	}
	transaction, err := database.BeginWrite(ctx)
	if err != nil || transaction == nil {
		return errors.Join(ErrLoadSnapshot, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollback(transaction))
		}
	}()
	if err := configure(ctx, transaction, store.options); err != nil {
		return errors.Join(ErrLoadSnapshot, err)
	}
	machine := identity.MachineFingerprint()
	key := identity.NodeKey().Bytes()
	var accepted bool
	if err := transaction.QueryRow(ctx, observeDeviceAliasVersionSQL, machine[:], key[:], int(version)).Scan(&accepted); err != nil {
		return fmt.Errorf("%w: record alias compatibility: %w", ErrLoadSnapshot, err)
	}
	if !accepted {
		return suspendedOrUnauthorized(ctx, transaction, machine[:], key[:])
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrLoadSnapshot, err)
	}
	committed = true
	return nil
}
