package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const resolveLoginSubjectSQL = `SELECT transaction_public_id::TEXT, transaction_version,
    transaction_consumed_at, transaction_binding_hash,
    principal_public_id::TEXT, subject_public_id::TEXT, membership_public_id::TEXT,
    subject_version, account_version, membership_version,
    principal_authority_generation, account_session_generation, membership_authority_generation,
    subject_algorithm, subject_key_id, subject_digest, evaluated_at, membership_expires_at
FROM mesh_ops.resolve_oidc_login_subject_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,
    $7::TEXT,$8::TEXT,$9::TEXT,$10::TEXT,$11::TEXT,$12::TEXT,$13::TEXT,$14::TEXT[],$15::TEXT[],$16::TEXT,
    $17::UUID,$18::BIGINT,$19::BYTEA,$20::TIMESTAMPTZ,$21::TEXT,$22::TEXT,
    $23::TEXT,$24::TEXT,$25::BYTEA,$26::TEXT,$27::BYTEA
)`

var _ oidcauth.LoginSubjectResolver = (*AuthTransactionStore)(nil)

// ResolveLoginSubject owns one bounded primary READ COMMITTED, READ ONLY unit.
// No identity/last-seen/membership/session mutation, positive cache or replay is
// performed. The complete route and original consuming claim are SQL predicates;
// the result is a snapshot, not final authorization or a Session issuance grant.
func (store *AuthTransactionStore) ResolveLoginSubject(
	ctx context.Context,
	query oidcauth.SubjectLookup,
) (result oidcauth.LoginSubjectSnapshot, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationAuthSubjectResolve, startedAt, resultErr) }()
	validStore := store != nil && store.database != nil && validAuthTransactionOptions(store.options)
	if ctx == nil || !validStore || !query.IsValid() {
		return result, oidcauth.ErrInvalidSubjectResolution
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return result, errors.Join(oidcauth.ErrSubjectResolutionUnavailable, ctx.Err())
	}
	transaction, err := store.database.Begin(ctx, true)
	closed := false
	if transaction != nil {
		defer func() {
			if closed {
				return
			}
			cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
			defer cleanupCancel()
			if cleanupErr := transaction.Rollback(cleanup); cleanupErr != nil && !errors.Is(cleanupErr, pgx.ErrTxClosed) {
				result = oidcauth.LoginSubjectSnapshot{}
				resultErr = errors.Join(resultErr, classifyLoginSubjectReadError(cleanup, cleanupErr))
			}
		}()
	}
	if err != nil {
		return result, classifyLoginSubjectReadError(ctx, err)
	}
	if transaction == nil {
		return result, oidcauth.ErrSubjectResolutionUnavailable
	}
	if err := store.configure(ctx, transaction); err != nil {
		return result, classifyLoginSubjectReadError(ctx, err)
	}
	if ctx.Err() != nil {
		return result, errors.Join(oidcauth.ErrSubjectResolutionUnavailable, ctx.Err())
	}
	snapshot := query.Snapshot()
	route, claimed := snapshot.Route(), query.Claimed()
	digests := query.Digests()
	active := digests[0].Bytes()
	var previousID *string
	// Nil is meaningful SQL absence for the optional previous candidate, not JSON.
	var previousBytes []byte
	if len(digests) == 2 {
		id := digests[1].KeyID().String()
		previousID = &id
		previous := digests[1].Bytes()
		previousBytes = previous[:]
	}
	hash := snapshot.SemanticHash()
	var transactionID, principalID, subjectID, membershipID, algorithm, keyID string
	var version int64
	var consumedAt, evaluatedAt time.Time
	var membershipExpiresAt *time.Time
	// Keep raw byte slices absent until strict scan-length validation; no padding.
	var bindingHash, digestBytes []byte
	params := oidcauth.LoginSubjectParams{Lookup: query}
	err = transaction.QueryRow(
		ctx,
		resolveLoginSubjectSQL,
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
		route.RedirectURI(),
		snapshot.TransactionID().String(),
		claimed.Version(),
		hash[:],
		claimed.ConsumedAt(),
		route.RedirectID(),
		route.ReturnRouteID(),
		digests[0].Algorithm(),
		digests[0].KeyID().String(),
		active[:],
		previousID,
		previousBytes,
	).Scan(
		&transactionID,
		&version,
		&consumedAt,
		&bindingHash,
		&principalID,
		&subjectID,
		&membershipID,
		&params.SubjectVersion,
		&params.AccountVersion,
		&params.MembershipVersion,
		&params.PrincipalAuthorityGeneration,
		&params.AccountSessionGeneration,
		&params.MembershipAuthorityGeneration,
		&algorithm,
		&keyID,
		&digestBytes,
		&evaluatedAt,
		&membershipExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	if err != nil {
		return result, classifyLoginSubjectReadError(ctx, err)
	}
	validClaim := transactionID == snapshot.TransactionID().String() && version == claimed.Version() && consumedAt.Equal(claimed.ConsumedAt())
	validHashes := len(bindingHash) == 32 && hmac.Equal(bindingHash, hash[:]) && len(digestBytes) == 32
	if !validClaim || !validHashes || algorithm != oidcauth.DigestAlgorithmHMACSHA256V1 {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	params.PrincipalID, err = identity.ParsePrincipalID(principalID)
	if err != nil {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	params.IdentitySubjectID, err = accountsession.ParseIdentitySubjectID(subjectID)
	if err != nil {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	params.MembershipID, err = oidcauth.ParseLoginMembershipID(membershipID)
	if err != nil {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	loadedKeyID, err := oidcauth.NewDigestKeyID(keyID)
	if err != nil {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	var loadedDigest [32]byte
	copy(loadedDigest[:], digestBytes)
	params.Digest, err = oidcauth.NewSubjectDigest(loadedKeyID, loadedDigest)
	if err != nil {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	params.EvaluatedAt = evaluatedAt.UTC()
	if membershipExpiresAt != nil {
		params.MembershipExpiresAt = membershipExpiresAt.UTC()
	}
	candidate, err := oidcauth.NewLoginSubjectSnapshot(params)
	if err != nil || !candidate.Matches(query) {
		return result, oidcauth.ErrSubjectResolutionRejected
	}
	if ctx.Err() != nil {
		return result, errors.Join(oidcauth.ErrSubjectResolutionUnavailable, ctx.Err())
	}
	if err := transaction.Commit(ctx); err != nil {
		// A failed read completion cannot justify uncertain-write resolution,
		// positive evidence or a retry. The owned cleanup above remains joined.
		return result, classifyLoginSubjectReadError(ctx, err)
	}
	closed = true
	if ctx.Err() != nil {
		return result, errors.Join(oidcauth.ErrSubjectResolutionUnavailable, ctx.Err())
	}
	return candidate, nil
}

func classifyLoginSubjectReadError(ctx context.Context, err error) error {
	if _, ok := errors.AsType[*pgconn.PgError](err); ok {
		return errors.Join(oidcauth.ErrSubjectResolutionUnavailable, classifyAuthTransactionDatabaseError(ctx, err))
	}
	// Transport/driver errors can include private connection or identity details.
	// Retain only the local cancellation cause, never a raw dependency message.
	return errors.Join(oidcauth.ErrSubjectResolutionUnavailable, ctx.Err())
}
