package accountsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
)

var (
	// ErrInvalidService reports missing Account Session authentication dependencies.
	ErrInvalidService = errors.New("account session: invalid authentication service")
	// ErrUnauthenticated reports absent, expired, or mismatched session authority.
	ErrUnauthenticated = errors.New("account session: unauthenticated")
	// ErrAuthenticationUnavailable classifies an authority-store failure.
	ErrAuthenticationUnavailable = errors.New("account session: authentication unavailable")
)

// Resolver loads current Account Session authority from durable storage.
type Resolver interface {
	Resolve(context.Context, deployment.ID, int64, Digest) (Session, bool, error)
}

// Clock supplies the authentication decision time.
type Clock interface {
	Now() time.Time
}

// Service authenticates opaque Account Session tokens against current authority.
type Service struct {
	keyring  *Keyring
	resolver Resolver
	clock    Clock
}

// NewService constructs an Account Session authenticator through explicit dependencies.
func NewService(keyring *Keyring, resolver Resolver, clock Clock) (*Service, error) {
	if keyring == nil || !keyring.active.isValid() || resolver == nil || clock == nil {
		return nil, ErrInvalidService
	}
	return &Service{keyring: keyring, resolver: resolver, clock: clock}, nil
}

// Authenticate resolves at most two key generations and fails closed.
func (service *Service) Authenticate(ctx context.Context, token Token) (Session, error) {
	if ctx == nil || service == nil || service.keyring == nil ||
		service.resolver == nil || service.clock == nil || !token.IsValid() {
		return Session{}, ErrUnauthenticated
	}
	if err := ctx.Err(); err != nil {
		return Session{}, errors.Join(ErrAuthenticationUnavailable, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return Session{}, ErrInvalidService
	}
	digests, err := service.keyring.Digests(token)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	for _, digest := range digests {
		session, found, resolveErr := service.resolver.Resolve(
			ctx,
			token.DeploymentID(),
			token.RecoveryEpoch(),
			digest,
		)
		if resolveErr != nil {
			return Session{}, errors.Join(
				ErrAuthenticationUnavailable,
				fmt.Errorf("resolve account session authority: %w", resolveErr),
			)
		}
		if !found {
			continue
		}
		// The resolver's SQL returns only a session live at the database
		// clock's time; this host-clock check can only refuse more.
		if !session.IsActiveAt(now) ||
			session.DeploymentID() != token.DeploymentID() ||
			session.DeploymentRecoveryEpoch() != token.RecoveryEpoch() {
			return Session{}, ErrUnauthenticated
		}
		return session, nil
	}
	return Session{}, ErrUnauthenticated
}

// SystemClock reads the process wall clock.
type SystemClock struct{}

// Now returns current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }
