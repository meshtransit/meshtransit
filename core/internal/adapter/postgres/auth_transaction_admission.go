package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

// ErrAdmitAuthTransactionRoute classifies failed durable login-route admission.
var ErrAdmitAuthTransactionRoute = errors.New("admit postgres auth transaction route")

const admitAuthTransactionRouteSQL = `SELECT mesh_ops.admit_oidc_login_route_v2(
    $1::UUID, $2::UUID, $3::UUID,
    $4::BIGINT, $5::BIGINT,
    $6::TEXT, $7::TEXT, $8::TEXT, $9::TEXT, $10::TEXT,
    $11::TEXT, $12::TEXT, $13::TEXT[], $14::TEXT[], $15::TEXT
)`

// Admit checks one current durable route without granting membership or session
// authority. Its read-only snapshot and resources close before OIDC I/O. Creation
// must still lock and recheck the route: admission is not a revocation lease.
// Redirect/return labels are trusted Core-owned registry configuration, not
// browser selectors; PostgreSQL independently checks the registered redirect URI.
func (store *AuthTransactionStore) Admit(ctx context.Context, route oidcauth.Route) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationAuthTransactionAdmission, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !route.IsValid() ||
		!validAuthTransactionOptions(store.options) {
		return ErrInvalidAuthTransactionStore
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrAdmitAuthTransactionRoute, err)
	}
	transaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return errors.Join(ErrAdmitAuthTransactionRoute, classifyAuthTransactionDatabaseError(ctx, err))
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		// This method owns cleanup even after request cancellation. No background
		// work survives the call; the independently bounded rollback is joined.
		cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
		defer cleanupCancel()
		if err := transaction.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, ErrAdmitAuthTransactionRoute, fmt.Errorf(
				"close route admission: %w", classifyAuthTransactionDatabaseError(cleanup, err),
			))
		}
	}()
	if err := store.configure(ctx, transaction); err != nil {
		return errors.Join(ErrAdmitAuthTransactionRoute, err)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrAdmitAuthTransactionRoute, err)
	}
	var admitted bool
	err = transaction.QueryRow(
		ctx,
		admitAuthTransactionRouteSQL,
		route.DeploymentID().String(),
		route.ProviderID().String(),
		route.ClientID().String(),
		route.ProviderGeneration(),
		route.RecoveryEpoch(),
		route.Issuer(),
		route.DiscoveryURI(),
		route.AuthorizationEndpoint(),
		route.TokenEndpoint(),
		route.JWKSURI(),
		route.OIDCClientID(),
		route.ClientAuthMethod(),
		route.Scopes(),
		route.AllowedAlgorithms(),
		route.RedirectURI(),
	).Scan(&admitted)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.Join(ErrAdmitAuthTransactionRoute, ErrAuthTransactionRouteUnavailable)
	}
	if err != nil {
		return errors.Join(ErrAdmitAuthTransactionRoute, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrAdmitAuthTransactionRoute, err)
	}
	if !admitted {
		return errors.Join(ErrAdmitAuthTransactionRoute, ErrAuthTransactionRouteUnavailable)
	}
	if err := transaction.Commit(ctx); err != nil {
		// This unit is read-only. Failure cannot justify a write replay or an
		// unknown-write resolver, and must not release a positive admission.
		return errors.Join(ErrAdmitAuthTransactionRoute, classifyAuthTransactionDatabaseError(ctx, err))
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrAdmitAuthTransactionRoute, err)
	}
	return nil
}
