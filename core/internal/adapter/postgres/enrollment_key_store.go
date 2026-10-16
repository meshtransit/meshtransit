package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const issueEnrollmentKeySQL = `SELECT mesh_ops.issue_enrollment_key_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TEXT,$14::BYTEA,$15::BYTEA,$16::BIGINT,$17::BIGINT,$18::BOOLEAN,
 $19::TEXT,$20::UUID)::TEXT`

const listEnrollmentKeysSQL = `SELECT mesh_ops.list_enrollment_keys_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::INTEGER)::TEXT`

const revokeEnrollmentKeySQL = `SELECT mesh_ops.revoke_enrollment_key_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID)::TEXT`

// EnrollmentKeyStore issues, lists and revokes the enrollment keys of one
// Network through the runtime pool. It digests each new secret with the
// active key of the enrollment keyring and stores only the digest; each
// creation and revocation commits with one event on the Network's stream.
type EnrollmentKeyStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
	keyring  *enrollment.CredentialKeyring
}

var _ enrollmentkey.Store = (*EnrollmentKeyStore)(nil)

// NewEnrollmentKeyStore uses the runtime pool and the enrollment keyring.
func NewEnrollmentKeyStore(pool *Pool, options AccountSessionOptions,
	keyring *enrollment.CredentialKeyring) (*EnrollmentKeyStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) || keyring == nil {
		return nil, enrollmentkey.ErrInvalid
	}
	return &EnrollmentKeyStore{database: pool.workspaceRenameDatabase, options: options, keyring: keyring}, nil
}

func (store *EnrollmentKeyStore) transact(ctx context.Context, scope network.Scope,
	run func(tx accountSessionTransaction) (bool, error)) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return enrollmentkey.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(enrollmentkey.ErrUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(enrollmentkey.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return enrollmentKeyDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return enrollmentkey.ErrForbidden
	}
	commit, err := run(tx)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(enrollmentkey.ErrUnavailable, err)
	}
	return nil
}

func enrollmentKeyDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501", "23503":
			return enrollmentkey.ErrForbidden
		case "P0002":
			return enrollmentkey.ErrNotFound
		case "MTE01":
			return enrollmentkey.ErrNotActive
		case "MTE02":
			return enrollmentkey.ErrLimitReached
		case "22023", "22P02", "23514":
			return enrollmentkey.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return enrollmentkey.ErrForbidden
	}
	return errors.Join(enrollmentkey.ErrUnavailable, err)
}

type enrollmentKeyDocument struct {
	KeyID                 string     `json:"key_id"`
	Description           *string    `json:"description"`
	IssuedByPrincipalID   string     `json:"issued_by_principal_id"`
	CreatedAt             time.Time  `json:"created_at"`
	ExpiresAt             time.Time  `json:"expires_at"`
	RevokedAt             *time.Time `json:"revoked_at"`
	Version               int64      `json:"version"`
	State                 string     `json:"state"`
	DeviceLifetimeSeconds *int64     `json:"device_lifetime_seconds"`
	DeviceNeverExpires    bool       `json:"device_never_expires"`
	DeviceID              *string    `json:"device_id"`
	DeviceName            *string    `json:"device_name"`
}

func (document enrollmentKeyDocument) key() (enrollmentkey.Key, error) {
	id, err := enrollment.ParseCredentialID(document.KeyID)
	if err != nil || document.Version < 1 {
		return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
	}
	issuer, err := identity.ParsePrincipalID(document.IssuedByPrincipalID)
	if err != nil {
		return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
	}
	var lifetime enrollment.DeviceLifetime
	switch {
	case document.DeviceNeverExpires && document.DeviceLifetimeSeconds == nil:
		lifetime = enrollment.NeverExpiringDeviceLifetime()
	case !document.DeviceNeverExpires && document.DeviceLifetimeSeconds != nil:
		lifetime, err = enrollment.NewDeviceLifetime(time.Duration(*document.DeviceLifetimeSeconds) * time.Second)
		if err != nil {
			return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
		}
	default:
		return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
	}
	params := enrollmentkey.KeyParams{
		ID: id, IssuedBy: issuer, CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt,
		State: enrollmentkey.State(document.State), DeviceLifetime: lifetime,
	}
	if document.Description != nil {
		params.Description = *document.Description
	}
	if document.RevokedAt != nil {
		params.RevokedAt = *document.RevokedAt
	}
	if document.DeviceID != nil {
		params.DeviceID, err = node.ParseID(*document.DeviceID)
		if err != nil {
			return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
		}
		if document.DeviceName != nil {
			params.DeviceName = *document.DeviceName
		}
	}
	return enrollmentkey.NewKey(params)
}

type enrollmentKeyRecord struct {
	NetworkID       string                 `json:"network_id"`
	NetworkRevision int64                  `json:"network_revision"`
	Before          *enrollmentKeyDocument `json:"before"`
	Key             enrollmentKeyDocument  `json:"key"`
	Authority       catalogAuthority       `json:"authority"`
}

// enrollmentKeySemanticHash binds the audit event to what changed: the key,
// its state and the lifetimes chosen, never its secret or digest.
func enrollmentKeySemanticHash(networkID network.ID, document enrollmentKeyDocument) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		NetworkID             string `json:"network_id"`
		KeyID                 string `json:"key_id"`
		State                 string `json:"state"`
		ExpiresAt             string `json:"expires_at"`
		DeviceLifetimeSeconds *int64 `json:"device_lifetime_seconds"`
		DeviceNeverExpires    bool   `json:"device_never_expires"`
	}{networkID.String(), document.KeyID, document.State, document.ExpiresAt.UTC().Format(time.RFC3339Nano),
		document.DeviceLifetimeSeconds, document.DeviceNeverExpires})
	return sha256.Sum256(encoded), err
}

// enrollmentKeyDeviceLifetimeEvidence is "never" or a number of seconds.
func enrollmentKeyDeviceLifetimeEvidence(document enrollmentKeyDocument) any {
	if document.DeviceNeverExpires || document.DeviceLifetimeSeconds == nil {
		return "never"
	}
	return *document.DeviceLifetimeSeconds
}

// IssueEnrollmentKey authorizes enrollment_credential.issue, stores the
// digest of the new secret and records enrollment_key.created.
func (store *EnrollmentKeyStore) IssueEnrollmentKey(ctx context.Context, issue enrollmentkey.Issue) (
	enrollmentkey.Key, error) {
	if !issue.IsValid() {
		return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
	}
	digest, err := store.keyring.Digest(issue.Session.DeploymentID(), issue.Session.DeploymentRecoveryEpoch(),
		issue.Token)
	if err != nil {
		return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
	}
	digestBytes, fingerprint := digest.Bytes(), digest.Fingerprint()
	var deviceSeconds any
	never := issue.DeviceLifetime.Kind() == enrollment.DeviceLifetimeNever
	if !never {
		deviceSeconds = int64(issue.DeviceLifetime.Duration() / time.Second)
	}
	changeID, err := publicid.New()
	if err != nil {
		return enrollmentkey.Key{}, enrollmentkey.ErrUnavailable
	}
	scope := issue.Scope
	var key enrollmentkey.Key
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, issueEnrollmentKeySQL, append(sessionQueryArguments(issue.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), issue.CredentialID.String(),
			digest.KeyID().String(), digestBytes[:], fingerprint[:], int64(issue.KeyLifetime/time.Second),
			deviceSeconds, never, issue.Description, changeID.String())...).Scan(&encoded); err != nil {
			return false, enrollmentKeyDatabaseError(err)
		}
		var record enrollmentKeyRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 {
			return false, enrollmentkey.ErrInvalid
		}
		decoded, err := record.Key.key()
		if err != nil || decoded.ID() != issue.CredentialID || decoded.State() != enrollmentkey.StateActive ||
			decoded.DeviceLifetime() != issue.DeviceLifetime || decoded.IssuedBy() != issue.Session.PrincipalID() ||
			decoded.ExpiresAt().Sub(decoded.CreatedAt()) != issue.KeyLifetime {
			return false, enrollmentkey.ErrInvalid
		}
		key = decoded
		after, err := enrollmentKeySemanticHash(scope.NetworkID(), record.Key)
		if err != nil {
			return false, enrollmentkey.ErrInvalid
		}
		event := catalogEvent{
			session: issue.Session, correlationID: issue.CorrelationID, changeID: changeID,
			aggregateKind: "enrollment_credential", aggregateID: publicid.ID(issue.CredentialID),
			version: record.Key.Version, networkVersion: record.NetworkRevision,
			action: "enrollment_key.created", permission: "enrollment_credential.issue", after: after,
			payload: struct {
				NetworkID          string           `json:"network_id"`
				SessionID          string           `json:"session_id"`
				KeyID              string           `json:"key_id"`
				Description        string           `json:"description,omitempty"`
				KeyLifetimeSeconds int64            `json:"key_lifetime_seconds"`
				KeyExpiresAt       string           `json:"key_expires_at"`
				DeviceLifetime     any              `json:"device_lifetime"`
				DeviceLifetimeSec  *int64           `json:"device_lifetime_seconds,omitempty"`
				Authority          catalogAuthority `json:"authority"`
			}{scope.NetworkID().String(), issue.Session.ID().String(), issue.CredentialID.String(),
				issue.Description, int64(issue.KeyLifetime / time.Second),
				decoded.ExpiresAt().Format(time.RFC3339), enrollmentKeyDeviceLifetimeEvidence(record.Key),
				record.Key.DeviceLifetimeSeconds, record.Authority},
			outboxClass: "enrollment_key.created",
			outbox: struct {
				NetworkID string `json:"network_id"`
				KeyID     string `json:"key_id"`
				Version   int64  `json:"version"`
			}{scope.NetworkID().String(), issue.CredentialID.String(), record.Key.Version},
		}
		if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
			return false, errors.Join(enrollmentkey.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return enrollmentkey.Key{}, err
	}
	return key, nil
}

// ListEnrollmentKeys authorizes enrollment_credential.issue or .revoke and
// returns the Network's keys: every usable key, then the newest others.
func (store *EnrollmentKeyStore) ListEnrollmentKeys(ctx context.Context, session accountsession.Session,
	scope network.Scope) ([]enrollmentkey.Key, error) {
	if !scope.IsValid() {
		return nil, enrollmentkey.ErrInvalid
	}
	var keys []enrollmentkey.Key
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listEnrollmentKeysSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(),
			enrollmentkey.MaximumListedKeys)...).Scan(&encoded); err != nil {
			return false, enrollmentKeyDatabaseError(err)
		}
		var listing struct {
			NetworkID string                  `json:"network_id"`
			Keys      []enrollmentKeyDocument `json:"keys"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &listing); err != nil ||
			listing.NetworkID != scope.NetworkID().String() || listing.Keys == nil ||
			len(listing.Keys) > enrollmentkey.MaximumListedKeys {
			return false, enrollmentkey.ErrInvalid
		}
		keys = make([]enrollmentkey.Key, 0, len(listing.Keys))
		for _, document := range listing.Keys {
			key, err := document.key()
			if err != nil {
				return false, err
			}
			keys = append(keys, key)
		}
		// A read commits nothing.
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// RevokeEnrollmentKey authorizes enrollment_credential.revoke, revokes the
// key and records enrollment_key.revoked. The Device it enrolled stays.
func (store *EnrollmentKeyStore) RevokeEnrollmentKey(ctx context.Context, revocation enrollmentkey.Revocation) (
	enrollmentkey.Key, error) {
	if !revocation.IsValid() {
		return enrollmentkey.Key{}, enrollmentkey.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return enrollmentkey.Key{}, enrollmentkey.ErrUnavailable
	}
	scope := revocation.Scope
	var key enrollmentkey.Key
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, revokeEnrollmentKeySQL, append(sessionQueryArguments(revocation.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), revocation.KeyID.String(),
			changeID.String())...).Scan(&encoded); err != nil {
			return false, enrollmentKeyDatabaseError(err)
		}
		var record enrollmentKeyRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Before == nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 {
			return false, enrollmentkey.ErrInvalid
		}
		decoded, err := record.Key.key()
		if err != nil || decoded.ID() != revocation.KeyID || decoded.State() != enrollmentkey.StateRevoked ||
			record.Key.Version != record.Before.Version+1 || record.Before.KeyID != record.Key.KeyID {
			return false, enrollmentkey.ErrInvalid
		}
		key = decoded
		before, err := enrollmentKeySemanticHash(scope.NetworkID(), *record.Before)
		if err != nil {
			return false, enrollmentkey.ErrInvalid
		}
		after, err := enrollmentKeySemanticHash(scope.NetworkID(), record.Key)
		if err != nil {
			return false, enrollmentkey.ErrInvalid
		}
		event := catalogEvent{
			session: revocation.Session, correlationID: revocation.CorrelationID, changeID: changeID,
			aggregateKind: "enrollment_credential", aggregateID: publicid.ID(revocation.KeyID),
			version: record.Key.Version, networkVersion: record.NetworkRevision,
			action: "enrollment_key.revoked", permission: "enrollment_credential.revoke",
			before: &before, after: after,
			payload: struct {
				NetworkID      string           `json:"network_id"`
				SessionID      string           `json:"session_id"`
				KeyID          string           `json:"key_id"`
				StateBefore    string           `json:"state_before"`
				DeviceID       *string          `json:"device_id,omitempty"`
				DeviceLifetime any              `json:"device_lifetime"`
				Authority      catalogAuthority `json:"authority"`
			}{scope.NetworkID().String(), revocation.Session.ID().String(), revocation.KeyID.String(),
				record.Before.State, record.Before.DeviceID, enrollmentKeyDeviceLifetimeEvidence(record.Key),
				record.Authority},
			outboxClass: "enrollment_key.revoked",
			outbox: struct {
				NetworkID string `json:"network_id"`
				KeyID     string `json:"key_id"`
				Version   int64  `json:"version"`
			}{scope.NetworkID().String(), revocation.KeyID.String(), record.Key.Version},
		}
		if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
			return false, errors.Join(enrollmentkey.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return enrollmentkey.Key{}, err
	}
	return key, nil
}
