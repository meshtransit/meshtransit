package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

// ErrIssueAuthTransaction classifies atomic Session/claim/evidence rejection.
var ErrIssueAuthTransaction = errors.New("issue postgres OIDC account session")

type authIssueTransaction struct {
	state    atomic.Uint32
	database authTransactionDatabaseTransaction
	route    oidcauth.Route
	metrics  *postgresPoolMetrics
}

var (
	_ oidcauth.IssueTransactions = (*AuthTransactionStore)(nil)
	_ oidcauth.IssueTransaction  = (*authIssueTransaction)(nil)
)

// BeginIssue owns one READ COMMITTED write unit with bounded setup cleanup.
// No current-authority snapshot, provider I/O, entropy or retry belongs here.
func (store *AuthTransactionStore) BeginIssue(
	ctx context.Context, route oidcauth.Route,
) (result oidcauth.IssueTransaction, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationAuthIssueBegin, startedAt, resultErr) }()
	if ctx == nil || store == nil || store.database == nil || !route.IsValid() ||
		!validAuthTransactionOptions(store.options) {
		return nil, ErrInvalidAuthTransactionStore
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, ctx.Err())
	}
	database, beginErr := store.database.Begin(ctx, false)
	if database == nil {
		return nil, errors.Join(
			ErrBeginAuthTransaction, classifyAuthTransactionDatabaseError(ctx, beginErr), ErrAuthTransactionEvidence,
		)
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
		defer cancel()
		if err := database.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, ErrRollbackAuthTransaction, classifyAuthTransactionDatabaseError(cleanup, err))
		}
		resultErr = errors.Join(resultErr, cleanup.Err(), ctx.Err())
	}()
	if beginErr != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, classifyAuthTransactionDatabaseError(ctx, beginErr))
	}
	if err := store.configure(ctx, database); err != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, err)
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, ctx.Err())
	}
	unit := &authIssueTransaction{database: database, route: route, metrics: store.metrics}
	unit.state.Store(authClaimOpen)
	owned = true
	return unit, nil
}

func (unit *authIssueTransaction) Issue(
	ctx context.Context, command oidcauth.IssueCommand,
) (result oidcauth.Issued, resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthIssueApply, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil || !command.IsValid() ||
		!sameAuthTransactionRoute(unit.route, command.Lookup().Snapshot().Route()) ||
		!unit.state.CompareAndSwap(authClaimOpen, authClaimBusy) {
		return result, ErrAuthTransactionState
	}
	defer func() {
		if resultErr != nil {
			unit.state.Store(authClaimCleanup)
		} else {
			unit.state.Store(authClaimReady)
		}
	}()
	if ctx.Err() != nil {
		return result, errors.Join(ErrIssueAuthTransaction, ctx.Err())
	}
	if err := unit.database.Exec(ctx, setAuthTransactionChangeSQL, command.IDs().ChangeID().String()); err != nil {
		return result, errors.Join(ErrIssueAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	row := unit.database.QueryRow(ctx, issueAuthTransactionSQL, authIssueArguments(command)...)
	issued, head, err := scanAuthIssue(row, command)
	if err != nil {
		return result, errors.Join(ErrIssueAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if ctx.Err() != nil {
		return result, errors.Join(ErrIssueAuthTransaction, ctx.Err())
	}
	if err := unit.appendIssueEvidence(ctx, command, issued, head); err != nil {
		return result, errors.Join(ErrIssueAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if ctx.Err() != nil {
		return result, errors.Join(ErrIssueAuthTransaction, ctx.Err())
	}
	return issued, nil
}

func authIssueArguments(command oidcauth.IssueCommand) []any {
	lookup, subject := command.Lookup(), command.Subject()
	snapshot, claimed := lookup.Snapshot(), lookup.Claimed()
	route, digests := snapshot.Route(), lookup.Digests()
	hash, active := snapshot.SemanticHash(), digests[0].Bytes()
	// Nil optional values mean SQL NULL, never uninitialized JSON collections.
	var previousID, sidAlgorithm, sidID, acr *string
	var previousBytes, sidBytes []byte
	var memberExpiry *time.Time
	if len(digests) == 2 {
		id := digests[1].KeyID().String()
		previousID = &id
		value := digests[1].Bytes()
		previousBytes = value[:]
	}
	if sid := command.ProviderSessionDigest(); sid.IsValid() {
		algorithm, id, value := sid.Algorithm(), sid.KeyID().String(), sid.Bytes()
		sidAlgorithm, sidID, sidBytes = &algorithm, &id, value[:]
	}
	if value := command.ACR(); value != "" {
		acr = &value
	}
	if value := subject.MembershipExpiresAt(); !value.IsZero() {
		memberExpiry = &value
	}
	token := command.TokenDigest().Bytes()
	methods := command.AMR()
	if methods == nil {
		methods = []string{}
	}
	return []any{
		route.DeploymentID().String(), command.Subject().WorkspaceID().String(), route.ProviderID().String(),
		route.ClientID().String(), route.ProviderGeneration(), route.RecoveryEpoch(),
		route.Issuer(), route.DiscoveryURI(), route.AuthorizationEndpoint(), route.TokenEndpoint(),
		route.JWKSURI(), route.OIDCClientID(), route.ClientAuthMethod(), route.Scopes(),
		route.AllowedAlgorithms(), route.RedirectURI(),
		snapshot.TransactionID().String(), claimed.Version(), hash[:], claimed.ConsumedAt(),
		route.RedirectID(), route.ReturnRouteID(),
		digests[0].Algorithm(), digests[0].KeyID().String(), active[:], previousID, previousBytes,
		subject.PrincipalID().String(), subject.IdentitySubjectID().String(), subject.MembershipID().String(),
		subject.SubjectVersion(), subject.AccountVersion(), subject.MembershipVersion(),
		subject.PrincipalAuthorityGeneration(), subject.AccountSessionGeneration(),
		subject.MembershipAuthorityGeneration(), memberExpiry, subject.EvaluatedAt(),
		command.IDs().SessionID().String(), command.TokenDigest().Algorithm(),
		command.TokenDigest().KeyID().String(), token[:],
		sidAlgorithm, sidID, sidBytes, command.AuthenticationTime(), acr, methods, command.ProviderExpiresAt(),
		int64(command.IdleLifetime() / time.Second), int64(command.AbsoluteLifetime() / time.Second),
	}
}

func scanAuthIssue(
	row authTransactionRow, command oidcauth.IssueCommand,
) (oidcauth.Issued, authTransactionAuditHead, error) {
	var transactionID, state, kind, resultID, sessionID string
	var transactionVersion, sessionVersion int64
	var consumedAt, at, idle, absolute time.Time
	var hash, previousHash []byte
	var head authTransactionAuditHead
	if err := row.Scan(
		&transactionID, &transactionVersion, &hash, &consumedAt, &state, &kind, &resultID,
		&sessionID, &sessionVersion, &at, &idle, &absolute, &head.streamInternalID, &head.nextSequence, &previousHash,
	); err != nil {
		return oidcauth.Issued{}, head, err
	}
	expected := command.Lookup().Snapshot().SemanticHash()
	boundClaim := transactionID == command.Lookup().Claimed().TransactionID().String() &&
		transactionVersion == 3 && len(hash) == 32 &&
		hmac.Equal(hash, expected[:]) && consumedAt.Equal(command.Lookup().Claimed().ConsumedAt())
	boundResult := state == "succeeded" && kind == "account_session" &&
		resultID == command.IDs().SessionID().String() && resultID == sessionID
	validHead := head.streamInternalID > 0 && head.nextSequence > 0 &&
		head.nextSequence < 9223372036854775807 && len(previousHash) == 32
	if !boundClaim || !boundResult || !validHead {
		return oidcauth.Issued{}, authTransactionAuditHead{}, ErrAuthTransactionEvidence
	}
	issued, err := oidcauth.NewIssued(oidcauth.IssuedParams{
		Command: command, SessionID: command.IDs().SessionID(), Version: sessionVersion,
		IssuedAt: at, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
	})
	if err != nil {
		return oidcauth.Issued{}, authTransactionAuditHead{}, ErrAuthTransactionEvidence
	}
	copy(head.previousHash[:], previousHash)
	return issued, head, nil
}

func (unit *authIssueTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthIssueCommit, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil || !unit.state.CompareAndSwap(authClaimReady, authClaimBusy) {
		return ErrAuthTransactionState
	}
	if ctx.Err() != nil {
		unit.state.Store(authClaimCleanup)
		return errors.Join(ErrCommitAuthTransaction, ctx.Err())
	}
	if err := unit.database.Commit(ctx); err != nil {
		unit.state.Store(authClaimCleanup)
		return errors.Join(ErrCommitAuthTransaction, classifyAuthTransactionCommitError(ctx, err))
	}
	unit.state.Store(authClaimClosed)
	return nil
}
func (unit *authIssueTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthIssueRollback, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil {
		return ErrAuthTransactionState
	}
	state := unit.state.Load()
	if state == authClaimClosed {
		return nil
	}
	canRollback := state == authClaimOpen || state == authClaimReady || state == authClaimCleanup
	if !canRollback || !unit.state.CompareAndSwap(state, authClaimBusy) {
		return ErrAuthTransactionState
	}
	defer unit.state.Store(authClaimClosed)
	if err := unit.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(ErrRollbackAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	return ctx.Err()
}
func (unit *authIssueTransaction) observe(operation postgresOperation, startedAt time.Time, err error) {
	if unit != nil {
		unit.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
