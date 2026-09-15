package accountsession_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

func TestServiceAuthenticatesActiveAndPreviousKeys(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	token := mustToken(t)
	active := mustDigestKey(t, "active-v2", 0x11)
	previous := mustDigestKey(t, "previous-v1", 0x22)
	keyring, err := accountsession.NewKeyring(active, previous)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	digests, err := keyring.Digests(token)
	if err != nil {
		t.Fatalf("Digests() error = %v", err)
	}
	session, err := accountsession.NewSession(validSessionParams(t, now))
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	resolver := &fakeResolver{resolve: func(
		_ context.Context,
		deploymentID deployment.ID,
		recoveryEpoch int64,
		digest accountsession.Digest,
	) (accountsession.Session, bool, error) {
		if deploymentID != token.DeploymentID() || recoveryEpoch != token.RecoveryEpoch() {
			t.Fatal("Resolve() lost token authority qualifiers")
		}
		if digest.KeyID() == digests[0].KeyID() {
			return accountsession.Session{}, false, nil
		}
		return session, true, nil
	}}
	service, err := accountsession.NewService(keyring, resolver, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	got, err := service.Authenticate(t.Context(), token)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got.ID() != session.ID() || resolver.calls != 2 {
		t.Fatalf("Authenticate() session/calls = %s/%d, want previous-key session/2", got.ID(), resolver.calls)
	}
}

func TestServiceFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	token := mustToken(t)
	keyring, err := accountsession.NewKeyring(mustDigestKey(t, "active-v1", 0x11))
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	storeErr := errors.New("database unavailable")
	tests := []struct {
		name     string
		resolver accountsession.Resolver
		clock    accountsession.Clock
		expected error
	}{
		{
			name: "not found",
			resolver: &fakeResolver{resolve: func(
				context.Context, deployment.ID, int64, accountsession.Digest,
			) (accountsession.Session, bool, error) {
				return accountsession.Session{}, false, nil
			}},
			clock:    fixedClock{now: now},
			expected: accountsession.ErrUnauthenticated,
		},
		{
			name: "store unavailable",
			resolver: &fakeResolver{resolve: func(
				context.Context, deployment.ID, int64, accountsession.Digest,
			) (accountsession.Session, bool, error) {
				return accountsession.Session{}, false, storeErr
			}},
			clock:    fixedClock{now: now},
			expected: accountsession.ErrAuthenticationUnavailable,
		},
		{
			name: "zero clock",
			resolver: &fakeResolver{resolve: func(
				context.Context, deployment.ID, int64, accountsession.Digest,
			) (accountsession.Session, bool, error) {
				return accountsession.Session{}, false, nil
			}},
			clock:    fixedClock{},
			expected: accountsession.ErrInvalidService,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, err := accountsession.NewService(keyring, test.resolver, test.clock)
			if err != nil {
				t.Fatalf("NewService() error = %v", err)
			}
			if _, err := service.Authenticate(t.Context(), token); !errors.Is(err, test.expected) {
				t.Fatalf("Authenticate() error = %v, want %v", err, test.expected)
			}
		})
	}
}

func TestNewServiceRejectsInvalidKeyring(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{resolve: func(
		context.Context, deployment.ID, int64, accountsession.Digest,
	) (accountsession.Session, bool, error) {
		return accountsession.Session{}, false, nil
	}}
	service, err := accountsession.NewService(
		&accountsession.Keyring{},
		resolver,
		fixedClock{now: time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)},
	)
	if !errors.Is(err, accountsession.ErrInvalidService) || service != nil {
		t.Fatalf("NewService() = %#v, %v, want nil, %v", service, err, accountsession.ErrInvalidService)
	}
}

type fakeResolver struct {
	resolve func(
		context.Context,
		deployment.ID,
		int64,
		accountsession.Digest,
	) (accountsession.Session, bool, error)
	calls int
}

func (resolver *fakeResolver) Resolve(
	ctx context.Context,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	digest accountsession.Digest,
) (accountsession.Session, bool, error) {
	resolver.calls++
	return resolver.resolve(ctx, deploymentID, recoveryEpoch, digest)
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }
