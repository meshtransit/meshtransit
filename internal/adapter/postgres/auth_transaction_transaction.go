package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

type authTransactionState uint8

const (
	authTransactionOpen authTransactionState = iota
	authTransactionCreated
	authTransactionClosed
)

type authTransactionAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type authTransactionTransaction struct {
	mu sync.Mutex

	database authTransactionDatabaseTransaction
	route    oidcauth.Route
	metrics  *postgresPoolMetrics
	state    authTransactionState
	audit    authTransactionAuditHead
}

var _ oidcauth.Transaction = (*authTransactionTransaction)(nil)

func (transaction *authTransactionTransaction) Create(
	ctx context.Context,
	pending oidcauth.Pending,
) (created oidcauth.Created, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationAuthTransactionCreate, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !pending.IsValid() {
		return oidcauth.Created{}, ErrAuthTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != authTransactionOpen ||
		!sameAuthTransactionRoute(transaction.route, pending.Route()) {
		return oidcauth.Created{}, ErrAuthTransactionState
	}
	created, err := transaction.createLocked(ctx, pending)
	if err != nil {
		return oidcauth.Created{}, errors.Join(
			ErrCreateAuthTransaction,
			classifyAuthTransactionDatabaseError(ctx, err),
		)
	}
	transaction.state = authTransactionCreated
	return created, nil
}

func (transaction *authTransactionTransaction) createLocked(
	ctx context.Context,
	pending oidcauth.Pending,
) (oidcauth.Created, error) {
	ids := pending.MutationIDs()
	if err := transaction.database.Exec(
		ctx,
		setAuthTransactionChangeSQL,
		ids.ChangeID().String(),
	); err != nil {
		return oidcauth.Created{}, fmt.Errorf("set authority change context: %w", err)
	}
	route := pending.Route()
	stateDigest := pending.StateDigest()
	nonceDigest := pending.NonceDigest()
	verifierCiphertext := pending.VerifierCiphertext()
	stateDigestBytes := stateDigest.Bytes()
	nonceDigestBytes := nonceDigest.Bytes()
	semanticHash := pending.SemanticHash()
	created, err := scanAuthTransactionCreated(transaction.database.QueryRow(
		ctx,
		createAuthTransactionSQL,
		pending.TransactionID().String(),
		route.DeploymentID().String(),
		route.WorkspaceID().String(),
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
		route.RedirectID(),
		route.RedirectURI(),
		route.ReturnRouteID(),
		stateDigest.Algorithm(),
		stateDigest.KeyID().String(),
		stateDigestBytes[:],
		nonceDigest.Algorithm(),
		nonceDigest.KeyID().String(),
		nonceDigestBytes[:],
		verifierCiphertext.Algorithm(),
		verifierCiphertext.KeyID().String(),
		verifierCiphertext.Bytes(),
		semanticHash[:],
		pending.CreatedAt(),
		pending.ExpiresAt(),
	))
	if err != nil {
		return oidcauth.Created{}, fmt.Errorf("insert pending auth transaction: %w", err)
	}
	if created.TransactionID() != pending.TransactionID() ||
		!created.CreatedAt().Equal(pending.CreatedAt()) ||
		!created.ExpiresAt().Equal(pending.ExpiresAt()) {
		return oidcauth.Created{}, ErrAuthTransactionEvidence
	}

	var previousHash []byte
	if err := transaction.database.QueryRow(
		ctx,
		lockAuthTransactionAuditStreamSQL,
		route.DeploymentID().String(),
	).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return oidcauth.Created{}, fmt.Errorf("lock Deployment audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return oidcauth.Created{}, ErrAuthTransactionEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)
	if err := transaction.appendAuthTransactionEvidence(ctx, pending, created); err != nil {
		return oidcauth.Created{}, err
	}
	return created, nil
}

func scanAuthTransactionCreated(row authTransactionRow) (oidcauth.Created, error) {
	var transactionIDValue string
	var version int64
	var createdAt, expiresAt time.Time
	if err := row.Scan(&transactionIDValue, &version, &createdAt, &expiresAt); err != nil {
		return oidcauth.Created{}, err
	}
	transactionID, err := oidcauth.ParseTransactionID(transactionIDValue)
	if err != nil {
		return oidcauth.Created{}, ErrAuthTransactionEvidence
	}
	created, err := oidcauth.NewCreated(transactionID, version, createdAt, expiresAt)
	if err != nil {
		return oidcauth.Created{}, ErrAuthTransactionEvidence
	}
	return created, nil
}

func (transaction *authTransactionTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationAuthTransactionCommit, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrAuthTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != authTransactionCreated {
		return ErrAuthTransactionState
	}
	transaction.state = authTransactionClosed
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(
			ErrCommitAuthTransaction,
			classifyAuthTransactionCommitError(ctx, err),
		)
	}
	return nil
}

func (transaction *authTransactionTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationAuthTransactionRollback, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrAuthTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrAuthTransactionState
	}
	if transaction.state == authTransactionClosed {
		return nil
	}
	transaction.state = authTransactionClosed
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(
			ErrRollbackAuthTransaction,
			fmt.Errorf("roll back database transaction: %w", err),
		)
	}
	return nil
}

func (transaction *authTransactionTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction == nil {
		return
	}
	transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
}
