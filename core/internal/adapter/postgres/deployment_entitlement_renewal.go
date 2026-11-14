package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/deployment/entitlement/renewal"
)

// entitlementRenewalLock serializes the api replicas' renewal attempts
// (pg_try_advisory_xact_lock: a replica that does not get it skips its turn).
// The value is arbitrary and used nowhere else.
const entitlementRenewalLock int64 = 0x4d54_454e_5452_4e57 // "MTENTRNW"

const tryEntitlementRenewalLockSQL = `SELECT pg_catalog.pg_try_advisory_xact_lock($1::BIGINT)`

const readCurrentDeploymentEntitlementSQL = `SELECT current_generation, current_profile,
 current_max_active_workspaces, current_max_owned_workspaces_per_account, current_capabilities,
 current_not_before, current_expires_at, current_signer_key_id, database_now
FROM mesh_ops.read_current_deployment_entitlement_v1($1::UUID)`

// RenewDeploymentEntitlement runs one renewal attempt in one transaction:
// the renewal lock, the current generation read while holding the
// Deployment row, and, when next returns one, the next generation recorded
// with its audit evidence before the lock and row are released.
func (store *DeploymentEntitlementStore) RenewDeploymentEntitlement(ctx context.Context, deploymentID deployment.ID,
	next renewal.NextFunc) (_ renewal.Outcome, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !deploymentID.IsValid() || next == nil {
		return "", ErrEntitlementUnavailable
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return "", ErrEntitlementUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return "", errors.Join(ErrEntitlementUnavailable, err)
	}
	var locked bool
	if err := tx.QueryRow(ctx, tryEntitlementRenewalLockSQL, entitlementRenewalLock).Scan(&locked); err != nil {
		return "", errors.Join(ErrEntitlementUnavailable, err)
	}
	if !locked {
		return renewal.OutcomeBusy, nil
	}
	current, found, err := readCurrentEntitlement(ctx, tx, deploymentID)
	if err != nil {
		return "", err
	}
	if !found {
		return renewal.OutcomeNoEntitlement, nil
	}
	renewed, due, err := next(current)
	if err != nil {
		return "", err
	}
	if !due {
		return renewal.OutcomeNotDue, nil
	}
	if renewed.DeploymentID != deploymentID || renewed.Generation != current.Generation+1 {
		return "", ErrEntitlementUnavailable
	}
	outcome, err := recordInTransaction(ctx, tx, renewed)
	if err != nil {
		return "", err
	}
	if outcome != EntitlementRecorded {
		return "", ErrEntitlementUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return "", errors.Join(ErrEntitlementUnavailable, err)
	}
	committed = true
	return renewal.OutcomeRenewed, nil
}

func readCurrentEntitlement(ctx context.Context, tx accountSessionTransaction, deploymentID deployment.ID) (
	renewal.Current, bool, error) {
	var current renewal.Current
	var profile string
	var capabilities []string
	var notBefore, expiresAt, databaseNow time.Time
	err := tx.QueryRow(ctx, readCurrentDeploymentEntitlementSQL, deploymentID.String()).Scan(&current.Generation,
		&profile, &current.Limits.MaxActiveWorkspaces, &current.Limits.MaxOwnedWorkspacesPerAccount, &capabilities,
		&notBefore, &expiresAt, &current.SignerKeyID, &databaseNow)
	if errors.Is(err, pgx.ErrNoRows) {
		return renewal.Current{}, false, nil
	}
	if err != nil {
		return renewal.Current{}, false, entitlementError(err)
	}
	current.Profile = deployment.Profile(profile)
	current.NotBefore, current.ExpiresAt, current.DatabaseNow = notBefore.UTC(), expiresAt.UTC(), databaseNow.UTC()
	current.Capabilities = make([]entitlement.Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		current.Capabilities = append(current.Capabilities, entitlement.Capability(capability))
	}
	return current, true, nil
}

// CurrentDeploymentEntitlement reads the recorded current generation in a
// short transaction of its own (startup decides on a generation conflict
// with it).
func (store *DeploymentEntitlementStore) CurrentDeploymentEntitlement(ctx context.Context,
	deploymentID deployment.ID) (_ renewal.Current, _ bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !deploymentID.IsValid() {
		return renewal.Current{}, false, ErrEntitlementUnavailable
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return renewal.Current{}, false, ErrEntitlementUnavailable
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return renewal.Current{}, false, errors.Join(ErrEntitlementUnavailable, err)
	}
	return readCurrentEntitlement(ctx, tx, deploymentID)
}
