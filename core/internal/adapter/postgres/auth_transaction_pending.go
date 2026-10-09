package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

// ErrLoadPendingAuthTransaction classifies failed browser evidence reads.
var ErrLoadPendingAuthTransaction = errors.New("load pending postgres auth transaction")

var _ oidcauth.PendingLoader = (*AuthTransactionStore)(nil)

const loadPendingAuthTransactionSQL = `SELECT
    transaction_public_id::TEXT, transaction_version, transaction_state,
    transaction_flow_kind, transaction_operation_kind,
    transaction_state_algorithm, transaction_state_key_id, transaction_state_digest,
    transaction_nonce_algorithm, transaction_nonce_key_id, transaction_nonce_digest,
    transaction_cipher_algorithm, transaction_cipher_key_id, transaction_ciphertext,
    transaction_binding_hash, transaction_created_at, transaction_expires_at
FROM mesh_ops.load_oidc_pending_browser_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::BIGINT, $5::BIGINT,
    $6::TEXT, $7::TEXT, $8::TEXT, $9::TEXT, $10::TEXT,
    $11::TEXT, $12::TEXT, $13::TEXT[], $14::TEXT[], $15::TEXT,
    $16::TEXT, $17::TEXT, $18::BYTEA, $19::TEXT, $20::TEXT
)`

// LoadPending closes an owned bounded read-only unit before returning immutable
// evidence. No positive evidence escapes cancellation, completion, or cleanup
// failure. It does not consume state or replace the later locked authority check.
func (store *AuthTransactionStore) LoadPending(ctx context.Context, route oidcauth.Route, digest oidcauth.Digest) (snapshot oidcauth.PendingSnapshot, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if resultErr != nil {
			snapshot, found = oidcauth.PendingSnapshot{}, false
		}
		store.observe(postgresOperationAuthTransactionPending, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !route.IsValid() ||
		!digest.IsValid() || !validAuthTransactionOptions(store.options) {
		return oidcauth.PendingSnapshot{}, false, ErrInvalidAuthTransactionStore
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return snapshot, false, errors.Join(ErrLoadPendingAuthTransaction, err)
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	closed := false
	if transaction != nil {
		defer func() {
			if closed {
				return
			}
			cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
			defer cleanupCancel()
			if err := transaction.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				resultErr = errors.Join(resultErr, ErrLoadPendingAuthTransaction, classifyAuthTransactionDatabaseError(cleanup, err))
			}
			if err := ctx.Err(); err != nil {
				resultErr = errors.Join(resultErr, ErrLoadPendingAuthTransaction, err)
			}
		}()
	}
	if beginErr != nil {
		return snapshot, false, errors.Join(ErrLoadPendingAuthTransaction, classifyAuthTransactionDatabaseError(ctx, beginErr))
	}
	if transaction == nil {
		return snapshot, false, errors.Join(ErrLoadPendingAuthTransaction, ErrAuthTransactionEvidence)
	}
	if err := store.configure(ctx, transaction); err != nil {
		return snapshot, false, errors.Join(ErrLoadPendingAuthTransaction, err)
	}
	if err := ctx.Err(); err != nil {
		return snapshot, false, errors.Join(ErrLoadPendingAuthTransaction, err)
	}
	state := digest.Bytes()
	row := transaction.QueryRow(ctx, loadPendingAuthTransactionSQL,
		route.DeploymentID().String(), route.ProviderID().String(), route.ClientID().String(),
		route.ProviderGeneration(), route.RecoveryEpoch(), route.Issuer(), route.DiscoveryURI(),
		route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI(), route.OIDCClientID(),
		route.ClientAuthMethod(), route.Scopes(), route.AllowedAlgorithms(), route.RedirectURI(),
		digest.Algorithm(), digest.KeyID().String(), state[:], route.RedirectID(), route.ReturnRouteID(),
	)
	snapshot, err := scanPendingAuthTransaction(row, route)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := ctx.Err(); err != nil {
			return oidcauth.PendingSnapshot{}, false, errors.Join(ErrLoadPendingAuthTransaction, err)
		}
		return oidcauth.PendingSnapshot{}, false, nil
	}
	if err != nil {
		return oidcauth.PendingSnapshot{}, false, errors.Join(ErrLoadPendingAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	expected := snapshot.StateDigest().Bytes()
	if snapshot.StateDigest().KeyID() != digest.KeyID() || !hmac.Equal(state[:], expected[:]) {
		return oidcauth.PendingSnapshot{}, false, errors.Join(ErrLoadPendingAuthTransaction, ErrAuthTransactionEvidence)
	}
	if err := ctx.Err(); err != nil {
		return oidcauth.PendingSnapshot{}, false, errors.Join(ErrLoadPendingAuthTransaction, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		// Read completion never invokes creation replay or grants exchange authority.
		return oidcauth.PendingSnapshot{}, false, errors.Join(ErrLoadPendingAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return oidcauth.PendingSnapshot{}, false, errors.Join(ErrLoadPendingAuthTransaction, err)
	}
	return snapshot, true, nil
}

func scanPendingAuthTransaction(row authTransactionRow, route oidcauth.Route) (oidcauth.PendingSnapshot, error) {
	var transactionID, state, flow, operation, stateAlgorithm, stateKeyID, nonceAlgorithm, nonceKeyID, cipherAlgorithm, cipherKeyID string
	var version int64
	var stateBytes, nonceBytes, ciphertext, bindingHash []byte
	var createdAt, expiresAt time.Time
	if err := row.Scan(&transactionID, &version, &state, &flow, &operation,
		&stateAlgorithm, &stateKeyID, &stateBytes, &nonceAlgorithm, &nonceKeyID, &nonceBytes,
		&cipherAlgorithm, &cipherKeyID, &ciphertext, &bindingHash, &createdAt, &expiresAt); err != nil {
		return oidcauth.PendingSnapshot{}, err
	}
	if stateAlgorithm != oidcauth.DigestAlgorithmHMACSHA256V1 || nonceAlgorithm != oidcauth.DigestAlgorithmHMACSHA256V1 ||
		cipherAlgorithm != oidcauth.VerifierEncryptionAlgorithmAES256GCMV1 || len(stateBytes) != 32 ||
		len(nonceBytes) != 32 || len(bindingHash) != 32 || len(ciphertext) < 95 || len(ciphertext) > 222 {
		return oidcauth.PendingSnapshot{}, ErrAuthTransactionEvidence
	}
	id, idErr := oidcauth.ParseTransactionID(transactionID)
	stateKey, stateKeyErr := oidcauth.NewDigestKeyID(stateKeyID)
	nonceKey, nonceKeyErr := oidcauth.NewDigestKeyID(nonceKeyID)
	cipherKey, cipherKeyErr := oidcauth.NewVerifierEncryptionKeyID(cipherKeyID)
	if idErr != nil || stateKeyErr != nil || nonceKeyErr != nil || cipherKeyErr != nil {
		return oidcauth.PendingSnapshot{}, ErrAuthTransactionEvidence
	}
	stateDigest, stateErr := oidcauth.NewDigest(stateKey, [32]byte(stateBytes))
	nonceDigest, nonceErr := oidcauth.NewDigest(nonceKey, [32]byte(nonceBytes))
	verifierCiphertext, cipherErr := oidcauth.NewCiphertext(cipherKey, ciphertext)
	if stateErr != nil || nonceErr != nil || cipherErr != nil {
		return oidcauth.PendingSnapshot{}, ErrAuthTransactionEvidence
	}
	snapshot, err := oidcauth.NewPendingSnapshot(oidcauth.PendingSnapshotParams{
		TransactionID: id, Route: route, Version: version, State: state, FlowKind: flow, OperationKind: operation,
		StateDigest: stateDigest, NonceDigest: nonceDigest, VerifierCiphertext: verifierCiphertext,
		SemanticHash: [32]byte(bindingHash), CreatedAt: createdAt, ExpiresAt: expiresAt,
	})
	if err != nil {
		return oidcauth.PendingSnapshot{}, ErrAuthTransactionEvidence
	}
	return snapshot, nil
}
