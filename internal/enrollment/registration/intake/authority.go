package intake

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/network"
)

var (
	// ErrInvalidAuthority reports inconsistent server-owned credential evidence.
	ErrInvalidAuthority = errors.New("registration intake: invalid authority")
	// ErrInvalidResolution reports inconsistent state returned under lock.
	ErrInvalidResolution = errors.New("registration intake: invalid resolution")
)

// AuthorityParams contains server-owned evidence loaded under database locks.
type AuthorityParams struct {
	DeploymentID  deployment.ID
	Scope         network.Scope
	Profile       enrollment.Profile
	Credential    enrollment.Credential
	Digest        enrollment.CredentialDigest
	RecoveryEpoch int64
}

// Authority is the exact server-derived enrollment authority used to verify a
// bearer proof. It contains no plaintext bearer material.
type Authority struct {
	deploymentID  deployment.ID
	scope         network.Scope
	profile       enrollment.Profile
	credential    enrollment.Credential
	digest        enrollment.CredentialDigest
	recoveryEpoch int64
}

// NewAuthority validates credential evidence resolved by an adapter.
func NewAuthority(params AuthorityParams) (Authority, error) {
	authority := Authority{
		deploymentID:  params.DeploymentID,
		scope:         params.Scope,
		profile:       params.Profile,
		credential:    params.Credential,
		digest:        params.Digest,
		recoveryEpoch: params.RecoveryEpoch,
	}
	if !authority.IsValid() {
		return Authority{}, ErrInvalidAuthority
	}
	return authority, nil
}

// DeploymentID returns the installation identity bound into the token digest.
func (authority Authority) DeploymentID() deployment.ID { return authority.deploymentID }

// Scope returns the exact Workspace and Network derived from durable authority.
func (authority Authority) Scope() network.Scope { return authority.scope }

// Profile returns the locked enrollment profile.
func (authority Authority) Profile() enrollment.Profile { return authority.profile }

// Credential returns the locked enrollment credential.
func (authority Authority) Credential() enrollment.Credential { return authority.credential }

// Digest returns the stored versioned token verifier.
func (authority Authority) Digest() enrollment.CredentialDigest { return authority.digest }

// RecoveryEpoch returns the current server-owned Deployment recovery epoch.
func (authority Authority) RecoveryEpoch() int64 { return authority.recoveryEpoch }

// IsValid reports whether the authority is internally consistent.
func (authority Authority) IsValid() bool {
	return authority.deploymentID.IsValid() && authority.scope.IsValid() &&
		authority.profile.IsValid() && authority.credential.IsValid() && authority.digest.IsValid() &&
		authority.recoveryEpoch > 0 && authority.profile.Scope() == authority.scope &&
		authority.credential.ProfileID() == authority.profile.ID()
}

// Resolution contains locked authority and, when present, the canonical active
// registration intent already associated with the machine identity.
type Resolution struct {
	authority   Authority
	intentID    enrollment.RegistrationID
	requestHash registration.RequestHash
	hasIntent   bool
}

// NewResolution constructs locked authority with no existing active intent.
func NewResolution(authority Authority) Resolution {
	return Resolution{authority: authority}
}

// NewExistingResolution constructs locked authority plus durable replay evidence.
func NewExistingResolution(
	authority Authority,
	intentID enrollment.RegistrationID,
	requestHash registration.RequestHash,
) (Resolution, error) {
	resolution := Resolution{
		authority:   authority,
		intentID:    intentID,
		requestHash: requestHash,
		hasIntent:   true,
	}
	if !resolution.IsValid() {
		return Resolution{}, ErrInvalidResolution
	}
	return resolution, nil
}

// Authority returns the locked server-owned credential evidence.
func (resolution Resolution) Authority() Authority { return resolution.authority }

// ExistingIntent returns canonical replay evidence and whether it exists.
func (resolution Resolution) ExistingIntent() (
	enrollment.RegistrationID,
	registration.RequestHash,
	bool,
) {
	return resolution.intentID, resolution.requestHash, resolution.hasIntent
}

// IsValid reports whether the resolution is internally consistent.
func (resolution Resolution) IsValid() bool {
	if !resolution.authority.IsValid() {
		return false
	}
	if resolution.hasIntent {
		return resolution.intentID.IsValid() && resolution.requestHash.IsValid()
	}
	return !resolution.intentID.IsValid() && !resolution.requestHash.IsValid()
}
