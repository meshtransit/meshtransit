package accountsession

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/domain/deployment"
)

var (
	// ErrInvalidLogoutService reports missing durable logout dependencies.
	ErrInvalidLogoutService = errors.New("account session: invalid logout service")
	// ErrLogoutUnavailable classifies an uncertain durable logout attempt.
	ErrLogoutUnavailable = errors.New("account session: logout unavailable")
)

// Revoker atomically ends one exact Deployment-bound Account Session digest.
type Revoker interface {
	Revoke(context.Context, deployment.ID, int64, Digest) (ID, int64, bool, error)
}

// LogoutService ends opaque Account Sessions across the bounded key-rotation window.
type LogoutService struct {
	keyring *Keyring
	revoker Revoker
}

// NewLogoutService constructs a durable, stateless logout use case.
func NewLogoutService(keyring *Keyring, revoker Revoker) (*LogoutService, error) {
	if !keyring.IsValid() || revoker == nil {
		return nil, ErrInvalidLogoutService
	}
	return &LogoutService{keyring: keyring, revoker: revoker}, nil
}

// Logout revokes at most one active Session. A completed no-match is an
// idempotent outcome; it never proves whether authority existed previously.
func (service *LogoutService) Logout(ctx context.Context, token Token) (bool, error) {
	if ctx == nil || service == nil || !service.keyring.IsValid() || service.revoker == nil || !token.IsValid() {
		return false, ErrUnauthenticated
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrLogoutUnavailable, err)
	}
	digests, err := service.keyring.Digests(token)
	if err != nil {
		return false, ErrUnauthenticated
	}
	for _, digest := range digests {
		id, version, revoked, revokeErr := service.revoker.Revoke(
			ctx,
			token.DeploymentID(),
			token.RecoveryEpoch(),
			digest,
		)
		if revokeErr != nil {
			return false, errors.Join(ErrLogoutUnavailable, fmt.Errorf("revoke account session: %w", revokeErr))
		}
		if !revoked {
			if id.IsValid() || version != 0 {
				return false, ErrLogoutUnavailable
			}
			continue
		}
		if !id.IsValid() || version < 2 {
			return false, ErrLogoutUnavailable
		}
		return true, nil
	}
	return false, nil
}
