package accountsession

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	maximumACRBytes      = 256
	maximumAMRValues     = 16
	maximumAMRValueBytes = 128
	maximumAMRBytes      = 1024
)

var (
	// ErrInvalidSessionID reports an absent or malformed Account Session public ID.
	ErrInvalidSessionID = errors.New("account session: invalid session id")
	// ErrInvalidIdentitySubjectID reports a malformed identity subject public ID.
	ErrInvalidIdentitySubjectID = errors.New("account session: invalid identity subject id")
	// ErrInvalidSession reports malformed durable Account Session authority.
	ErrInvalidSession = errors.New("account session: invalid session")
)

// ID is a validated Account Session UUIDv7.
type ID publicid.ID

// ParseID validates a canonical Account Session UUIDv7.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalidSessionID
	}
	return ID(id), nil
}

// String returns the canonical Account Session public ID.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the Account Session ID is valid.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }

// IdentitySubjectID is a validated identity-subject UUIDv7.
type IdentitySubjectID publicid.ID

// ParseIdentitySubjectID validates a canonical identity-subject UUIDv7.
func ParseIdentitySubjectID(value string) (IdentitySubjectID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return IdentitySubjectID{}, ErrInvalidIdentitySubjectID
	}
	return IdentitySubjectID(id), nil
}

// String returns the canonical identity-subject public ID.
func (id IdentitySubjectID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the identity-subject ID is valid.
func (id IdentitySubjectID) IsValid() bool { return publicid.ID(id).IsValid() }

// Params contains validated durable fields returned by Account Session authority.
type Params struct {
	ID                           ID
	DeploymentID                 deployment.ID
	PrincipalID                  identity.PrincipalID
	IdentitySubjectID            IdentitySubjectID
	LoginWorkspaceID             workspace.ID
	HasLoginWorkspace            bool
	AuthenticationTime           time.Time
	ACR                          string
	AMR                          []string
	Version                      int64
	PrincipalAuthorityGeneration int64
	AccountSessionGeneration     int64
	ProviderGeneration           int64
	DeploymentRecoveryEpoch      int64
	IdleExpiresAt                time.Time
	AbsoluteExpiresAt            time.Time
}

// Session is immutable authenticated human-session authority.
type Session struct {
	id                           ID
	deploymentID                 deployment.ID
	principalID                  identity.PrincipalID
	identitySubjectID            IdentitySubjectID
	loginWorkspaceID             workspace.ID
	hasLoginWorkspace            bool
	authenticationTime           time.Time
	acr                          string
	amr                          []string
	version                      int64
	principalAuthorityGeneration int64
	accountSessionGeneration     int64
	providerGeneration           int64
	deploymentRecoveryEpoch      int64
	idleExpiresAt                time.Time
	absoluteExpiresAt            time.Time
}

// NewSession validates and defensively copies resolved Account Session authority.
func NewSession(params Params) (Session, error) {
	session := Session{
		id:                           params.ID,
		deploymentID:                 params.DeploymentID,
		principalID:                  params.PrincipalID,
		identitySubjectID:            params.IdentitySubjectID,
		loginWorkspaceID:             params.LoginWorkspaceID,
		hasLoginWorkspace:            params.HasLoginWorkspace,
		authenticationTime:           params.AuthenticationTime.UTC(),
		acr:                          params.ACR,
		amr:                          append([]string(nil), params.AMR...),
		version:                      params.Version,
		principalAuthorityGeneration: params.PrincipalAuthorityGeneration,
		accountSessionGeneration:     params.AccountSessionGeneration,
		providerGeneration:           params.ProviderGeneration,
		deploymentRecoveryEpoch:      params.DeploymentRecoveryEpoch,
		idleExpiresAt:                params.IdleExpiresAt.UTC(),
		absoluteExpiresAt:            params.AbsoluteExpiresAt.UTC(),
	}
	if !session.IsValid() {
		return Session{}, ErrInvalidSession
	}
	return session, nil
}

// ID returns the Account Session public ID.
func (session Session) ID() ID { return session.id }

// DeploymentID returns the exact Deployment boundary.
func (session Session) DeploymentID() deployment.ID { return session.deploymentID }

// PrincipalID returns the stable authenticated Principal.
func (session Session) PrincipalID() identity.PrincipalID { return session.principalID }

// IdentitySubjectID returns the exact provider subject evidence.
func (session Session) IdentitySubjectID() IdentitySubjectID {
	return session.identitySubjectID
}

// LoginWorkspaceID returns the login Workspace qualifier when one exists.
func (session Session) LoginWorkspaceID() (workspace.ID, bool) {
	return session.loginWorkspaceID, session.hasLoginWorkspace
}

// AuthenticationTime returns the provider authentication instant.
func (session Session) AuthenticationTime() time.Time { return session.authenticationTime }

// ACR returns the bounded authentication context class reference.
func (session Session) ACR() string { return session.acr }

// AMR returns a defensive copy of authentication method references.
func (session Session) AMR() []string { return append([]string(nil), session.amr...) }

// Version returns the Account Session optimistic version.
func (session Session) Version() int64 { return session.version }

// PrincipalAuthorityGeneration returns the Principal authority fence.
func (session Session) PrincipalAuthorityGeneration() int64 {
	return session.principalAuthorityGeneration
}

// AccountSessionGeneration returns the Account-wide session fence.
func (session Session) AccountSessionGeneration() int64 {
	return session.accountSessionGeneration
}

// ProviderGeneration returns the identity-provider recovery fence.
func (session Session) ProviderGeneration() int64 { return session.providerGeneration }

// DeploymentRecoveryEpoch returns the Deployment restore fence.
func (session Session) DeploymentRecoveryEpoch() int64 {
	return session.deploymentRecoveryEpoch
}

// IdleExpiresAt returns the exclusive idle expiry.
func (session Session) IdleExpiresAt() time.Time { return session.idleExpiresAt }

// AbsoluteExpiresAt returns the exclusive absolute expiry.
func (session Session) AbsoluteExpiresAt() time.Time { return session.absoluteExpiresAt }

// IsValid reports whether durable session authority is structurally safe.
func (session Session) IsValid() bool {
	if !session.id.IsValid() || !session.deploymentID.IsValid() ||
		!session.principalID.IsValid() || !session.identitySubjectID.IsValid() ||
		session.hasLoginWorkspace != session.loginWorkspaceID.IsValid() ||
		session.authenticationTime.IsZero() || session.version <= 0 ||
		session.principalAuthorityGeneration <= 0 || session.accountSessionGeneration <= 0 ||
		session.providerGeneration <= 0 || session.deploymentRecoveryEpoch <= 0 ||
		!session.idleExpiresAt.After(session.authenticationTime) ||
		!session.absoluteExpiresAt.After(session.authenticationTime) ||
		session.idleExpiresAt.After(session.absoluteExpiresAt) ||
		!validACR(session.acr) || !validAMR(session.amr) {
		return false
	}
	return true
}

// IsActiveAt applies the exclusive session-expiry contract at one decision time.
func (session Session) IsActiveAt(now time.Time) bool {
	return session.IsValid() && !now.IsZero() && !now.Before(session.authenticationTime) &&
		now.Before(session.idleExpiresAt) && now.Before(session.absoluteExpiresAt)
}

func validACR(value string) bool {
	return len(value) <= maximumACRBytes && strings.TrimSpace(value) == value &&
		utf8.ValidString(value)
}

func validAMR(values []string) bool {
	if len(values) > maximumAMRValues {
		return false
	}
	total := 0
	for _, value := range values {
		if value == "" || len(value) > maximumAMRValueBytes ||
			strings.TrimSpace(value) != value || !utf8.ValidString(value) {
			return false
		}
		total += len(value)
	}
	return total <= maximumAMRBytes
}
