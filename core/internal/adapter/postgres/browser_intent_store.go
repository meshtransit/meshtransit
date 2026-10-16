package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const issueBrowserIntentSQL = `SELECT
    intent_public_id::TEXT, issued_recovery_epoch, token_nonce,
    token_key_id, token_digest, intent_state, intent_expires_at
FROM mesh_ops.issue_browser_registration_intent_v1(
    $1::UUID, $2::BIGINT, $3::UUID, $4::BYTEA, $5::BYTEA,
    $6::BYTEA, $7::TEXT, $8::BYTEA, $9::TEXT, $10::BYTEA, $11::TIMESTAMPTZ
)`

const readBrowserIntentFollowupSQL = `SELECT
    intent_public_id::TEXT, intent_state,
    pending_registration_public_id::TEXT, intent_expires_at
FROM mesh_ops.read_browser_registration_followup_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA,
    $5::BYTEA, $6::BYTEA, $7::TEXT
)`

const readBrowserIntentLandingSQL = `SELECT
    intent_public_id::TEXT, intent_state, requested_hostname, intent_expires_at
FROM mesh_ops.read_browser_registration_landing_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA
)`

var (
	// ErrInvalidBrowserIntentIssue reports incomplete server-owned issuance input.
	ErrInvalidBrowserIntentIssue = errors.New("invalid browser registration intent issuance")
	// ErrBrowserIntentIssueUnavailable reports a missing deployment or database failure.
	ErrBrowserIntentIssueUnavailable = errors.New("browser registration intent issuance unavailable")
	// ErrBrowserIntentIssueConflict reports another active Node request for the machine.
	ErrBrowserIntentIssueConflict = errors.New("browser registration intent conflict")
	// ErrBrowserIntentIssueEvidence reports malformed or unverifiable persisted state.
	ErrBrowserIntentIssueEvidence = errors.New("browser registration intent evidence invalid")
)

// BrowserIntentStore issues a durable URL bearer without retaining it in memory.
type BrowserIntentStore struct {
	database browserIntentDatabase
	options  AccountSessionOptions
	keys     *enrollment.BrowserIntentKeyring
}

// NewBrowserIntentStore binds the runtime pool to a dedicated rotating keyring.
func NewBrowserIntentStore(
	pool *Pool, options AccountSessionOptions, keys *enrollment.BrowserIntentKeyring,
) (*BrowserIntentStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.browserIntentDatabase == nil {
		return nil, ErrInvalidBrowserIntentIssue
	}
	return newBrowserIntentStore(pool.browserIntentDatabase, options, keys)
}

func newBrowserIntentStore(
	database browserIntentDatabase, options AccountSessionOptions,
	keys *enrollment.BrowserIntentKeyring,
) (*BrowserIntentStore, error) {
	if database == nil || !validAccountSessionOptions(options) || keys == nil {
		return nil, ErrInvalidBrowserIntentIssue
	}
	return &BrowserIntentStore{database: database, options: options, keys: keys}, nil
}

// Issue creates one machine-bound intent or reconstructs the exact prior URL.
// The caller must have bound identity to a Noise-authenticated machine.
func (store *BrowserIntentStore) Issue(
	ctx context.Context,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	identity node.RegistrationIdentity,
	hostname node.Hostname,
	proposedID enrollment.BrowserIntentID,
	proposedNonce enrollment.BrowserIntentNonce,
	lifetime time.Duration,
) (_ enrollment.BrowserIntentToken, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || store.keys == nil ||
		!validAccountSessionOptions(store.options) || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !identity.IsValid() || !hostname.IsValid() ||
		!proposedID.IsValid() || lifetime <= 0 {
		return enrollment.BrowserIntentToken{}, ErrInvalidBrowserIntentIssue
	}
	proposedToken, proposedDigest, proposedKeyID, err := store.keys.Issue(
		deploymentID, recoveryEpoch, proposedID, proposedNonce,
	)
	if err != nil {
		return enrollment.BrowserIntentToken{}, ErrInvalidBrowserIntentIssue
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueUnavailable
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
		return enrollment.BrowserIntentToken{}, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	// The intent's lifetime starts at the database clock's time.
	issuedAt, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return enrollment.BrowserIntentToken{}, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	expiresAt := issuedAt.Add(lifetime)
	machineKey := identity.MachineKey().Bytes()
	fingerprint := identity.MachineKey().Fingerprint()
	nodeKey := identity.NodeKey().Bytes()
	nonceBytes := proposedNonce.Bytes()
	digestBytes := proposedDigest.Bytes()
	var issuedID, keyID, state string
	var issuedEpoch int64
	var issuedNonce, issuedDigest []byte
	var issuedExpiry time.Time
	err = transaction.QueryRow(ctx, issueBrowserIntentSQL,
		deploymentID.String(), recoveryEpoch, proposedID.String(), machineKey[:],
		fingerprint[:], nodeKey[:], hostname.String(), nonceBytes[:],
		proposedKeyID.String(), digestBytes[:], expiresAt,
	).Scan(&issuedID, &issuedEpoch, &issuedNonce, &keyID, &issuedDigest, &state, &issuedExpiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueUnavailable
	}
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueConflict
		}
		return enrollment.BrowserIntentToken{}, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	intentID, err := enrollment.ParseBrowserIntentID(issuedID)
	if err != nil || issuedEpoch != recoveryEpoch ||
		(state != "pending" && state != "approved") ||
		!issuedExpiry.After(issuedAt) || len(issuedNonce) != 32 ||
		len(issuedDigest) != 32 {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueEvidence
	}
	var rawNonce, rawDigest [32]byte
	copy(rawNonce[:], issuedNonce)
	copy(rawDigest[:], issuedDigest)
	nonce, err := enrollment.ParseBrowserIntentNonce(rawNonce)
	if err != nil {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueEvidence
	}
	digest, err := enrollment.ParseBrowserIntentDigest(rawDigest)
	if err != nil {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueEvidence
	}
	parsedKeyID, err := enrollment.NewBrowserIntentKeyID(keyID)
	if err != nil {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueEvidence
	}
	issuedToken, err := store.keys.Reissue(
		deploymentID, recoveryEpoch, intentID, nonce, parsedKeyID, digest,
	)
	if err != nil {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueEvidence
	}
	if issuedID == proposedID.String() && issuedToken.Encoded() != proposedToken.Encoded() {
		return enrollment.BrowserIntentToken{}, ErrBrowserIntentIssueEvidence
	}
	if issuedID == proposedID.String() {
		eventID, err := publicid.New()
		if err != nil {
			return enrollment.BrowserIntentToken{}, errors.Join(ErrBrowserIntentIssueUnavailable, err)
		}
		outboxID, err := publicid.New()
		if err != nil {
			return enrollment.BrowserIntentToken{}, errors.Join(ErrBrowserIntentIssueUnavailable, err)
		}
		if err := appendBrowserIntentEvidence(ctx, transaction, deploymentID,
			intentID, identity, eventID, outboxID); err != nil {
			return enrollment.BrowserIntentToken{}, err
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return enrollment.BrowserIntentToken{}, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	closed = true
	return issuedToken, nil
}

// ReadFollowup admits the exact token and Noise-bound machine/Node pair.
// A missing or stale intent returns found=false without revealing which input
// failed. Approval is not registration completion; the caller must still run
// the authoritative Device registration transaction.
func (store *BrowserIntentStore) ReadFollowup(
	ctx context.Context,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	identity node.RegistrationIdentity,
	hostname node.Hostname,
	encodedToken string,
) (_ enrollment.BrowserIntentFollowup, found bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !identity.IsValid() || !hostname.IsValid() {
		return enrollment.BrowserIntentFollowup{}, false, ErrInvalidBrowserIntentIssue
	}
	digest, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken)
	if err != nil {
		return enrollment.BrowserIntentFollowup{}, false, ErrInvalidBrowserIntentIssue
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return enrollment.BrowserIntentFollowup{}, false, ErrBrowserIntentIssueUnavailable
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
		return enrollment.BrowserIntentFollowup{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	// Expiry is judged on the database clock.
	evaluatedAt, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return enrollment.BrowserIntentFollowup{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	machineKey := identity.MachineKey().Bytes()
	fingerprint := identity.MachineKey().Fingerprint()
	nodeKey := identity.NodeKey().Bytes()
	digestBytes := digest.Bytes()
	var intentPublicID, state string
	var pendingRegistrationPublicID *string
	var expiresAt time.Time
	err = transaction.QueryRow(ctx, readBrowserIntentFollowupSQL,
		deploymentID.String(), recoveryEpoch, digestBytes[:], machineKey[:],
		fingerprint[:], nodeKey[:], hostname.String(),
	).Scan(&intentPublicID, &state, &pendingRegistrationPublicID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return enrollment.BrowserIntentFollowup{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
		}
		closed = true
		return enrollment.BrowserIntentFollowup{}, false, nil
	}
	if err != nil {
		return enrollment.BrowserIntentFollowup{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	intentID, err := enrollment.ParseBrowserIntentID(intentPublicID)
	if err != nil || !expiresAt.After(evaluatedAt) {
		return enrollment.BrowserIntentFollowup{}, false, ErrBrowserIntentIssueEvidence
	}
	var registrationID enrollment.RegistrationID
	switch state {
	case "pending":
		if pendingRegistrationPublicID != nil {
			return enrollment.BrowserIntentFollowup{}, false, ErrBrowserIntentIssueEvidence
		}
	case "approved":
		if pendingRegistrationPublicID == nil {
			return enrollment.BrowserIntentFollowup{}, false, ErrBrowserIntentIssueEvidence
		}
		registrationID, err = enrollment.ParseRegistrationID(*pendingRegistrationPublicID)
		if err != nil {
			return enrollment.BrowserIntentFollowup{}, false, ErrBrowserIntentIssueEvidence
		}
	default:
		return enrollment.BrowserIntentFollowup{}, false, ErrBrowserIntentIssueEvidence
	}
	followup := enrollment.BrowserIntentFollowup{
		IntentID: intentID, State: state,
		PendingRegistrationID: registrationID, ExpiresAt: expiresAt,
	}
	if !followup.IsValid() {
		return enrollment.BrowserIntentFollowup{}, false, ErrBrowserIntentIssueEvidence
	}
	if err := transaction.Commit(ctx); err != nil {
		return enrollment.BrowserIntentFollowup{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	closed = true
	return followup, true, nil
}

// ReadLanding reveals minimal intent detail only when PostgreSQL confirms the
// exact SSO Account Session and URL token under the current recovery epoch.
func (store *BrowserIntentStore) ReadLanding(
	ctx context.Context, deploymentID deployment.ID, recoveryEpoch int64,
	sessionDigest accountsession.Digest, encodedToken string,
) (_ enrollment.BrowserIntentLanding, found bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !sessionDigest.IsValid() {
		return enrollment.BrowserIntentLanding{}, false, ErrInvalidBrowserIntentIssue
	}
	tokenDigest, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken)
	if err != nil {
		return enrollment.BrowserIntentLanding{}, false, ErrInvalidBrowserIntentIssue
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return enrollment.BrowserIntentLanding{}, false, ErrBrowserIntentIssueUnavailable
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
		return enrollment.BrowserIntentLanding{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	// Expiry is judged on the database clock.
	evaluatedAt, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return enrollment.BrowserIntentLanding{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	sessionBytes := sessionDigest.Bytes()
	tokenBytes := tokenDigest.Bytes()
	var intentPublicID, state, hostname string
	var expiresAt time.Time
	err = transaction.QueryRow(ctx, readBrowserIntentLandingSQL,
		deploymentID.String(), recoveryEpoch, sessionDigest.KeyID().String(),
		sessionBytes[:], tokenBytes[:],
	).Scan(&intentPublicID, &state, &hostname, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return enrollment.BrowserIntentLanding{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
		}
		closed = true
		return enrollment.BrowserIntentLanding{}, false, nil
	}
	if err != nil {
		return enrollment.BrowserIntentLanding{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	intentID, err := enrollment.ParseBrowserIntentID(intentPublicID)
	if err != nil {
		return enrollment.BrowserIntentLanding{}, false, ErrBrowserIntentIssueEvidence
	}
	landing := enrollment.BrowserIntentLanding{
		IntentID: intentID, State: state, Hostname: hostname, ExpiresAt: expiresAt,
	}
	if !landing.IsValid() || !expiresAt.After(evaluatedAt) {
		return enrollment.BrowserIntentLanding{}, false, ErrBrowserIntentIssueEvidence
	}
	if err := transaction.Commit(ctx); err != nil {
		return enrollment.BrowserIntentLanding{}, false, errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	closed = true
	return landing, true, nil
}
