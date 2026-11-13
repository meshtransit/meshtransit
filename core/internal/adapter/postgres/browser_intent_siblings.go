package postgres

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/node"
)

// MaxBrowserSiblings bounds the sibling machine keys one sign-in records
// (duplicate-device design §5).
const MaxBrowserSiblings = 16

const recordBrowserIntentSiblingsSQL = `SELECT mesh_ops.record_browser_intent_siblings_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA, $5::BYTEA[]
)`

// ErrInvalidBrowserSiblings reports sibling keys the store refuses: too
// many, malformed or the sign-in's own.
var ErrInvalidBrowserSiblings = errors.New("invalid browser sign-in siblings")

// RecordSiblings keeps the sibling machine keys a pending sign-in's machine
// proved in its Noise session (duplicate-device design §6.1). The caller has
// verified each proof; the store replaces the list while the sign-in is
// pending and leaves it once it is approved. An empty list clears it.
func (store *BrowserIntentStore) RecordSiblings(
	ctx context.Context, deploymentID deployment.ID, recoveryEpoch int64,
	identity node.RegistrationIdentity, encodedToken string, siblings [][32]byte,
) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !identity.IsValid() || len(siblings) > MaxBrowserSiblings {
		return ErrInvalidBrowserSiblings
	}
	digest, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken)
	if err != nil {
		return ErrInvalidBrowserSiblings
	}
	machineKey := identity.MachineKey().Bytes()
	keys := make([][]byte, 0, len(siblings))
	for _, sibling := range siblings {
		if sibling == machineKey || sibling == [32]byte{} {
			return ErrInvalidBrowserSiblings
		}
		keys = append(keys, sibling[:])
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return ErrBrowserIntentIssueUnavailable
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	digestBytes := digest.Bytes()
	var recorded int
	if err := transaction.QueryRow(ctx, recordBrowserIntentSiblingsSQL,
		deploymentID.String(), recoveryEpoch, digestBytes[:], machineKey[:], keys,
	).Scan(&recorded); err != nil {
		return errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	closed = true
	return nil
}
