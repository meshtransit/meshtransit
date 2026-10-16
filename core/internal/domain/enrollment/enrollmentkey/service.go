package enrollmentkey

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Store persists keys; PostgreSQL authorizes each call on the database
// clock and records every creation and revocation.
type Store interface {
	IssueEnrollmentKey(ctx context.Context, issue Issue) (Key, error)
	ListEnrollmentKeys(ctx context.Context, session accountsession.Session, scope network.Scope) ([]Key, error)
	RevokeEnrollmentKey(ctx context.Context, revocation Revocation) (Key, error)
}

// Clock reads the host's time; it only refuses sessions that already ended.
type Clock interface {
	Now() time.Time
}

// TokenSource creates key secrets and IDs.
type TokenSource interface {
	NewToken() (enrollment.CredentialToken, error)
	NewCredentialID() (enrollment.CredentialID, error)
}

// Service validates key requests before PostgreSQL authorizes them.
type Service struct {
	store  Store
	clock  Clock
	tokens TokenSource
}

// NewService requires a store and a clock and uses the system CSPRNG.
func NewService(store Store, clock Clock) (*Service, error) {
	return NewServiceWithTokens(store, clock, systemTokens{})
}

// NewServiceWithTokens lets tests choose the secrets.
func NewServiceWithTokens(store Store, clock Clock, tokens TokenSource) (*Service, error) {
	if store == nil || clock == nil || tokens == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock, tokens: tokens}, nil
}

type systemTokens struct{}

func (systemTokens) NewToken() (enrollment.CredentialToken, error) {
	return enrollment.GenerateCredentialToken()
}

func (systemTokens) NewCredentialID() (enrollment.CredentialID, error) {
	id, err := publicid.New()
	if err != nil {
		return enrollment.CredentialID{}, err
	}
	return enrollment.CredentialID(id), nil
}

// admit refuses a session that has already ended on this host's clock. It
// can only deny: the store authorizes the session on the database clock.
func (service *Service) admit(ctx context.Context, session accountsession.Session) error {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// Issue creates one key and returns it with its one-time presentation.
func (service *Service) Issue(ctx context.Context, session accountsession.Session,
	request IssueRequest) (Issued, error) {
	if err := service.admit(ctx, session); err != nil {
		return Issued{}, err
	}
	lifetime := request.KeyLifetime
	if lifetime == 0 {
		lifetime = DefaultKeyLifetime
	}
	token, err := service.tokens.NewToken()
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	credentialID, err := service.tokens.NewCredentialID()
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	issue := Issue{
		Session: session, Scope: request.Scope, Description: request.Description, KeyLifetime: lifetime,
		DeviceLifetime: request.DeviceLifetime, CredentialID: credentialID, Token: token,
		CorrelationID: request.CorrelationID,
	}
	if !issue.IsValid() {
		return Issued{}, ErrInvalid
	}
	key, err := service.store.IssueEnrollmentKey(ctx, issue)
	if err != nil {
		return Issued{}, err
	}
	presentation, err := enrollment.NewCredentialPresentation(credentialID, token)
	if err != nil {
		return Issued{}, ErrInvalid
	}
	return NewIssued(key, presentation)
}

// List returns the Network's keys, every usable one first, then the newest
// spent, expired or revoked ones, without secrets.
func (service *Service) List(ctx context.Context, session accountsession.Session,
	scope network.Scope) ([]Key, error) {
	if err := service.admit(ctx, session); err != nil {
		return nil, err
	}
	if !scope.IsValid() {
		return nil, ErrInvalid
	}
	return service.store.ListEnrollmentKeys(ctx, session, scope)
}

// Revoke ends one active key. The Device it enrolled, if any, is untouched.
func (service *Service) Revoke(ctx context.Context, session accountsession.Session, scope network.Scope,
	keyID enrollment.CredentialID, correlationID publicid.ID) (Key, error) {
	if err := service.admit(ctx, session); err != nil {
		return Key{}, err
	}
	revocation := Revocation{Session: session, Scope: scope, KeyID: keyID, CorrelationID: correlationID}
	if !revocation.IsValid() {
		return Key{}, ErrInvalid
	}
	return service.store.RevokeEnrollmentKey(ctx, revocation)
}
