package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	maximumAccountSessionStatementTimeout = 30 * time.Second
	maximumAccountSessionIdleTimeout      = time.Minute
	accountSessionRollbackTimeout         = 2 * time.Second
)

var (
	// ErrInvalidAccountSessionStore reports an unsafe dependency or option.
	ErrInvalidAccountSessionStore = errors.New("invalid postgres account session store")
	// ErrResolveAccountSession classifies durable Account Session resolution failure.
	ErrResolveAccountSession = errors.New("resolve postgres account session")
	// ErrAccountSessionEvidence reports malformed authority returned by PostgreSQL.
	ErrAccountSessionEvidence = errors.New("postgres account session evidence is invalid")
)

// AccountSessionOptions bounds every database wait during session resolution.
type AccountSessionOptions struct {
	StatementTimeout time.Duration
	IdleTimeout      time.Duration
}

// AccountSessionStore resolves current session authority through a narrow function.
type AccountSessionStore struct {
	database activityAccountSessionDatabase
	options  AccountSessionOptions
	metrics  *postgresPoolMetrics
}

var _ accountsession.Resolver = (*AccountSessionStore)(nil)
var _ sessioncontext.Reader = (*AccountSessionStore)(nil)
var _ sessioncontext.CapabilityReader = (*AccountSessionStore)(nil)

// NewAccountSessionStore constructs a resolver from a runtime-authenticated pool.
func NewAccountSessionStore(
	pool *Pool,
	options AccountSessionOptions,
) (*AccountSessionStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.accountSessionDatabase == nil {
		return nil, ErrInvalidAccountSessionStore
	}
	return newAccountSessionStore(pool.accountSessionDatabase, options, pool.metrics)
}

func newAccountSessionStore(
	database activityAccountSessionDatabase,
	options AccountSessionOptions,
	metrics *postgresPoolMetrics,
) (*AccountSessionStore, error) {
	if database == nil || !validAccountSessionOptions(options) {
		return nil, ErrInvalidAccountSessionStore
	}
	return &AccountSessionStore{database: database, options: options, metrics: metrics}, nil
}

// Resolve returns current authority for one exact Deployment, recovery epoch, and digest.
func (store *AccountSessionStore) Resolve(
	ctx context.Context,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	digest accountsession.Digest,
) (_ accountsession.Session, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !digest.IsValid() {
		return accountsession.Session{}, false, ErrInvalidAccountSessionStore
	}
	begin := store.database.Begin
	if accountsession.IsActivity(ctx) {
		begin = store.database.BeginActivity
	}
	transaction, err := begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidAccountSessionStore
		}
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
	}()

	if err := transaction.Exec(
		ctx,
		configureAccountSessionReadTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	digestBytes := digest.Bytes()
	session, err := scanAccountSession(transaction.QueryRow(
		ctx,
		resolveAccountSessionSQL,
		deploymentID.String(),
		recoveryEpoch,
		digest.Algorithm(),
		digest.KeyID().String(),
		digestBytes[:],
	))
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
		}
		closed = true
		return accountsession.Session{}, false, nil
	}
	if err != nil {
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	if session.DeploymentID() != deploymentID ||
		session.DeploymentRecoveryEpoch() != recoveryEpoch {
		return accountsession.Session{}, false, errors.Join(
			ErrResolveAccountSession,
			ErrAccountSessionEvidence,
		)
	}
	if accountsession.IsActivity(ctx) && shouldTouchAccountSession(session, time.Now().UTC()) {
		session, err = touchResolvedAccountSession(ctx, transaction, session, digest)
		if err != nil {
			return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	closed = true
	return session, true, nil
}

// A normal request can renew a live session after 15 minutes of use. This
// check only avoids unnecessary write transactions; SQL enforces the boundary.
func shouldTouchAccountSession(session accountsession.Session, now time.Time) bool {
	return session.IsValid() && now.Before(session.AbsoluteExpiresAt()) &&
		now.After(session.IdleExpiresAt().Add(-45*time.Minute))
}

func touchResolvedAccountSession(
	ctx context.Context,
	transaction accountSessionTransaction,
	session accountsession.Session,
	digest accountsession.Digest,
) (accountsession.Session, error) {
	ids, err := newAccountSessionLogoutEvidenceIDs(ctx)
	if err != nil {
		return accountsession.Session{}, err
	}
	if err := transaction.Exec(ctx, setAccountSessionLogoutChangeSQL, ids.changeID.String()); err != nil {
		return accountsession.Session{}, err
	}
	digestBytes := digest.Bytes()
	var version int64
	var lastUsedAt, idleExpiresAt time.Time
	err = transaction.QueryRow(ctx, touchAccountSessionSQL,
		session.ID().String(), session.Version(), session.DeploymentID().String(),
		session.DeploymentRecoveryEpoch(), digest.Algorithm(), digest.KeyID().String(), digestBytes[:],
	).Scan(&version, &lastUsedAt, &idleExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return session, nil
	}
	if err != nil {
		return accountsession.Session{}, err
	}
	if version != session.Version()+1 || !idleExpiresAt.After(lastUsedAt) ||
		idleExpiresAt.After(session.AbsoluteExpiresAt()) {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	var head accountSessionLogoutAuditHead
	var previousHash []byte
	if err := transaction.QueryRow(ctx, lockAccountSessionLogoutAuditStreamSQL,
		session.DeploymentID().String()).Scan(
		&head.streamInternalID, &head.nextSequence, &previousHash,
	); err != nil {
		return accountsession.Session{}, err
	}
	if head.streamInternalID <= 0 || head.nextSequence <= 0 || len(previousHash) != len(head.previousHash) {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	copy(head.previousHash[:], previousHash)
	evidence, err := buildAccountSessionTouchEvidence(ids, head, session.DeploymentID(),
		session.DeploymentRecoveryEpoch(), session.ID(), publicid.ID(session.PrincipalID()),
		version, lastUsedAt, idleExpiresAt)
	if err != nil {
		return accountsession.Session{}, err
	}
	var sequence int64
	if err := transaction.QueryRow(ctx, appendAccountSessionTouchEvidenceSQL,
		head.streamInternalID, ids.auditID.String(), ids.outboxID.String(), head.nextSequence,
		head.previousHash[:], evidence.eventHash[:], session.ID().String(), version,
		session.PrincipalID().String(), evidence.afterHash[:], evidence.payload,
	).Scan(&sequence); err != nil {
		return accountsession.Session{}, err
	}
	if sequence != head.nextSequence {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	refreshed, err := scanAccountSession(transaction.QueryRow(ctx, resolveAccountSessionSQL,
		session.DeploymentID().String(), session.DeploymentRecoveryEpoch(), digest.Algorithm(),
		digest.KeyID().String(), digestBytes[:],
	))
	if err != nil || refreshed.ID() != session.ID() || refreshed.Version() != version ||
		refreshed.DeploymentID() != session.DeploymentID() ||
		refreshed.DeploymentRecoveryEpoch() != session.DeploymentRecoveryEpoch() {
		return accountsession.Session{}, errors.Join(ErrAccountSessionEvidence, err)
	}
	return refreshed, nil
}

// ReadManagementScopes returns one fresh login-Workspace policy-approval projection.
func (store *AccountSessionStore) ReadManagementScopes(
	ctx context.Context,
	session accountsession.Session,
	after network.ID,
	limit int,
	evaluatedAt time.Time,
) (_ sessioncontext.ReadResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observeOperation(postgresOperationAccountSessionScopes, startedAt, resultErr)
	}()
	workspaceID, hasWorkspace := session.LoginWorkspaceID()
	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !session.IsValid() || !hasWorkspace ||
		(!after.IsValid() && after != (network.ID{})) || limit < 1 ||
		limit > sessioncontext.MaximumPageSize+1 || evaluatedAt.IsZero() {
		return sessioncontext.ReadResult{}, sessioncontext.ErrInvalidRequest
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidAccountSessionStore
		}
		return sessioncontext.ReadResult{}, errors.Join(sessioncontext.ErrUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
		}
	}()
	if err := transaction.Exec(
		ctx,
		configureAccountSessionReadTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return sessioncontext.ReadResult{}, errors.Join(sessioncontext.ErrUnavailable, err)
	}
	var afterValue any
	if after.IsValid() {
		afterValue = after.String()
	}
	var encoded *string
	err = transaction.QueryRow(
		ctx,
		readAccountSessionManagementScopesSQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		workspaceID.String(),
		evaluatedAt,
		afterValue,
		limit,
	).Scan(&encoded)
	if err != nil {
		return sessioncontext.ReadResult{}, errors.Join(sessioncontext.ErrUnavailable, err)
	}
	if encoded == nil {
		if err := transaction.Commit(ctx); err != nil {
			return sessioncontext.ReadResult{}, errors.Join(sessioncontext.ErrUnavailable, err)
		}
		closed = true
		return sessioncontext.ReadResult{}, sessioncontext.ErrUnauthenticated
	}
	result, err := decodeAccountSessionManagementScopes(*encoded)
	if err != nil {
		return sessioncontext.ReadResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return sessioncontext.ReadResult{}, errors.Join(sessioncontext.ErrUnavailable, err)
	}
	closed = true
	return result, nil
}

// ReadDeploymentCapabilities returns one fresh non-secret Deployment projection.
func (store *AccountSessionStore) ReadDeploymentCapabilities(
	ctx context.Context,
	session accountsession.Session,
	evaluatedAt time.Time,
) (_ sessioncontext.CapabilityReadResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observeOperation(postgresOperationAccountSessionCaps, startedAt, resultErr)
	}()
	workspaceID, hasWorkspace := session.LoginWorkspaceID()
	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !session.IsValid() || !hasWorkspace || evaluatedAt.IsZero() {
		return sessioncontext.CapabilityReadResult{}, sessioncontext.ErrInvalidCapabilityRequest
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidAccountSessionStore
		}
		return sessioncontext.CapabilityReadResult{}, errors.Join(sessioncontext.ErrCapabilitiesUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
		}
	}()
	if err := transaction.Exec(
		ctx,
		configureAccountSessionReadTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return sessioncontext.CapabilityReadResult{}, errors.Join(sessioncontext.ErrCapabilitiesUnavailable, err)
	}
	var encoded *string
	err = transaction.QueryRow(
		ctx,
		readAccountSessionDeploymentCapabilitiesSQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		workspaceID.String(),
		evaluatedAt,
	).Scan(&encoded)
	if err != nil {
		return sessioncontext.CapabilityReadResult{}, errors.Join(sessioncontext.ErrCapabilitiesUnavailable, err)
	}
	if encoded == nil {
		if err := transaction.Commit(ctx); err != nil {
			return sessioncontext.CapabilityReadResult{}, errors.Join(sessioncontext.ErrCapabilitiesUnavailable, err)
		}
		closed = true
		return sessioncontext.CapabilityReadResult{}, sessioncontext.ErrCapabilitiesUnauthenticated
	}
	result, err := decodeAccountSessionDeploymentCapabilities(*encoded)
	if err != nil {
		return sessioncontext.CapabilityReadResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return sessioncontext.CapabilityReadResult{}, errors.Join(sessioncontext.ErrCapabilitiesUnavailable, err)
	}
	closed = true
	return result, nil
}

type accountSessionEntitlementRecord struct {
	ID                           string   `json:"id"`
	Generation                   int64    `json:"generation"`
	MaxActiveWorkspaces          int64    `json:"max_active_workspaces"`
	MaxOwnedWorkspacesPerAccount int64    `json:"max_owned_workspaces_per_account"`
	Capabilities                 []string `json:"capabilities"`
	ExpiresAt                    string   `json:"expires_at"`
	GraceSeconds                 int64    `json:"grace_seconds"`
	State                        string   `json:"state"`
}

type accountSessionDeploymentCapabilitiesRecord struct {
	DeploymentID string                           `json:"deployment_id"`
	Profile      string                           `json:"profile"`
	Revision     int64                            `json:"revision"`
	Entitlement  *accountSessionEntitlementRecord `json:"entitlement"`
}

func decodeAccountSessionDeploymentCapabilities(encoded string) (sessioncontext.CapabilityReadResult, error) {
	var record accountSessionDeploymentCapabilitiesRecord
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return sessioncontext.CapabilityReadResult{}, sessioncontext.ErrInvalidCapabilityResult
	}
	deploymentID, err := deployment.ParseID(record.DeploymentID)
	profile := deployment.Profile(record.Profile)
	if err != nil || !profile.IsValid() || record.Revision <= 0 {
		return sessioncontext.CapabilityReadResult{}, sessioncontext.ErrInvalidCapabilityResult
	}
	result := sessioncontext.CapabilityReadResult{
		DeploymentID: deploymentID,
		Profile:      profile,
		Revision:     record.Revision,
	}
	if entitlement := record.Entitlement; entitlement != nil {
		if _, err := publicid.Parse(entitlement.ID); err != nil || entitlement.Capabilities == nil {
			return sessioncontext.CapabilityReadResult{}, sessioncontext.ErrInvalidCapabilityResult
		}
		result.Entitlement = &sessioncontext.EntitlementEvidence{
			Generation: entitlement.Generation, MaxActiveWorkspaces: entitlement.MaxActiveWorkspaces,
			MaxOwnedWorkspacesPerAccount: entitlement.MaxOwnedWorkspacesPerAccount,
			Capabilities:                 entitlement.Capabilities, State: entitlement.State,
		}
	}
	return result, nil
}

type accountSessionManagementScopesRecord struct {
	WorkspaceID          string                                `json:"workspace_id"`
	WorkspaceDisplayName string                                `json:"workspace_display_name"`
	WorkspaceDisplayCode string                                `json:"workspace_display_code"`
	WorkspaceVersion     int64                                 `json:"workspace_version"`
	WorkspaceCanRename   bool                                  `json:"workspace_can_rename"`
	Scopes               []accountSessionManagementScopeRecord `json:"scopes"`
}

type accountSessionManagementScopeRecord struct {
	NetworkID          string   `json:"network_id"`
	NetworkDisplayName string   `json:"network_display_name"`
	NetworkDisplayCode string   `json:"network_display_code"`
	Permissions        []string `json:"permissions"`
}

func decodeAccountSessionManagementScopes(encoded string) (sessioncontext.ReadResult, error) {
	var record accountSessionManagementScopesRecord
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		return sessioncontext.ReadResult{}, sessioncontext.ErrInvalidResult
	}
	workspaceID, err := workspace.ParseID(record.WorkspaceID)
	if err != nil {
		return sessioncontext.ReadResult{}, sessioncontext.ErrInvalidResult
	}
	result := sessioncontext.ReadResult{
		WorkspaceID: workspaceID, WorkspaceDisplayName: record.WorkspaceDisplayName,
		WorkspaceDisplayCode: identity.DisplayCode(record.WorkspaceDisplayCode),
		WorkspaceVersion:     record.WorkspaceVersion, WorkspaceCanRename: record.WorkspaceCanRename,
		Scopes: make([]sessioncontext.ManagementScope, len(record.Scopes)),
	}
	for index, item := range record.Scopes {
		networkID, err := network.ParseID(item.NetworkID)
		if err != nil {
			return sessioncontext.ReadResult{}, sessioncontext.ErrInvalidResult
		}
		permissions := make([]authorization.Permission, len(item.Permissions))
		for permissionIndex, permission := range item.Permissions {
			permissions[permissionIndex] = authorization.Permission(permission)
		}
		value, err := sessioncontext.NewManagementScope(
			networkID,
			item.NetworkDisplayName,
			permissions,
		)
		if err != nil {
			return sessioncontext.ReadResult{}, sessioncontext.ErrInvalidResult
		}
		if item.NetworkDisplayCode != "" {
			value, err = value.WithDisplayCode(identity.DisplayCode(item.NetworkDisplayCode))
			if err != nil {
				return sessioncontext.ReadResult{}, sessioncontext.ErrInvalidResult
			}
		}
		result.Scopes[index] = value
	}
	return result, nil
}

func scanAccountSession(row accountSessionRow) (accountsession.Session, error) {
	var sessionPublicID, deploymentPublicID, principalPublicID, subjectPublicID string
	var loginWorkspacePublicID *string
	var authenticationTime, idleExpiresAt, absoluteExpiresAt time.Time
	var acr *string
	var amr []string
	var sessionVersion, principalGeneration, accountGeneration int64
	var providerGeneration, recoveryEpoch int64
	if err := row.Scan(
		&sessionPublicID,
		&deploymentPublicID,
		&principalPublicID,
		&subjectPublicID,
		&loginWorkspacePublicID,
		&authenticationTime,
		&acr,
		&amr,
		&sessionVersion,
		&principalGeneration,
		&accountGeneration,
		&providerGeneration,
		&recoveryEpoch,
		&idleExpiresAt,
		&absoluteExpiresAt,
	); err != nil {
		return accountsession.Session{}, err
	}
	sessionID, err := accountsession.ParseID(sessionPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	principalID, err := identity.ParsePrincipalID(principalPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(subjectPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	var loginWorkspaceID workspace.ID
	if loginWorkspacePublicID != nil {
		loginWorkspaceID, err = workspace.ParseID(*loginWorkspacePublicID)
		if err != nil {
			return accountsession.Session{}, ErrAccountSessionEvidence
		}
	}
	acrValue := ""
	if acr != nil {
		acrValue = *acr
	}
	session, err := accountsession.NewSession(accountsession.Params{
		ID:                           sessionID,
		DeploymentID:                 deploymentID,
		PrincipalID:                  principalID,
		IdentitySubjectID:            subjectID,
		LoginWorkspaceID:             loginWorkspaceID,
		HasLoginWorkspace:            loginWorkspacePublicID != nil,
		AuthenticationTime:           authenticationTime,
		ACR:                          acrValue,
		AMR:                          amr,
		Version:                      sessionVersion,
		PrincipalAuthorityGeneration: principalGeneration,
		AccountSessionGeneration:     accountGeneration,
		ProviderGeneration:           providerGeneration,
		DeploymentRecoveryEpoch:      recoveryEpoch,
		IdleExpiresAt:                idleExpiresAt,
		AbsoluteExpiresAt:            absoluteExpiresAt,
	})
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	return session, nil
}

func validAccountSessionOptions(options AccountSessionOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maximumAccountSessionStatementTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maximumAccountSessionIdleTimeout
}

func rollbackAccountSessionTransaction(transaction accountSessionTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), accountSessionRollbackTimeout)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back Account Session transaction: %w", err)
	}
	return nil
}

func (store *AccountSessionStore) observe(startedAt time.Time, err error) {
	store.observeOperation(postgresOperationAccountSessionResolve, startedAt, err)
}

func (store *AccountSessionStore) observeOperation(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if store != nil && store.metrics != nil {
		store.metrics.observeOperation(
			operation,
			time.Since(startedAt),
			err,
		)
	}
}
