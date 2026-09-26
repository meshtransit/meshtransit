package accountsession_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

func TestLogoutServiceRevokesAcrossBoundedKeyWindow(t *testing.T) {
	t.Parallel()
	for _, usePrevious := range []bool{false, true} {
		name := "active key"
		if usePrevious {
			name = "previous key"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			active := logoutDigestKey(t, "active-v2", 0x31)
			previous := logoutDigestKey(t, "previous-v1", 0x42)
			keyring, err := accountsession.NewKeyring(active, previous)
			if err != nil {
				t.Fatal(err)
			}
			token, err := accountsession.GenerateToken(logoutDeploymentID(t), 7)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := keyring.ActiveDigest(token)
			if usePrevious {
				previousRing, ringErr := accountsession.NewKeyring(previous)
				if ringErr != nil {
					t.Fatal(ringErr)
				}
				expected, err = previousRing.ActiveDigest(token)
			}
			if err != nil {
				t.Fatal(err)
			}
			revoker := &logoutRevoker{expected: expected, id: logoutSessionID(t), version: 2}
			service, err := accountsession.NewLogoutService(keyring, revoker)
			if err != nil {
				t.Fatal(err)
			}
			revoked, err := service.Logout(t.Context(), token)
			if err != nil || !revoked {
				t.Fatal("logout did not revoke the matching key generation", err)
			}
			expectedCalls := 1
			if usePrevious {
				expectedCalls = 2
			}
			if revoker.calls != expectedCalls || revoker.deployment != token.DeploymentID() || revoker.epoch != 7 {
				t.Fatal("logout changed the bounded digest/deployment search")
			}
		})
	}
}

func TestLogoutServiceTreatsCompletedReplayAsNoMatch(t *testing.T) {
	t.Parallel()
	keyring := logoutKeyring(t)
	token, err := accountsession.GenerateToken(logoutDeploymentID(t), 7)
	if err != nil {
		t.Fatal(err)
	}
	revoker := &logoutRevoker{}
	service, err := accountsession.NewLogoutService(keyring, revoker)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := service.Logout(t.Context(), token)
	if err != nil || revoked || revoker.calls != 2 {
		t.Fatal("completed replay was not a bounded idempotent no-match", err)
	}
}

func TestLogoutServiceFailsClosedOnInvalidOrUncertainEvidence(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"invalid token", "canceled", "revoker error", "malformed miss", "malformed result"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			keyring := logoutKeyring(t)
			token, err := accountsession.GenerateToken(logoutDeploymentID(t), 7)
			if err != nil {
				t.Fatal(err)
			}
			revoker := &logoutRevoker{}
			ctx := t.Context()
			switch mode {
			case "invalid token":
				token = accountsession.Token{}
			case "canceled":
				canceled, cancel := context.WithCancel(t.Context())
				cancel()
				ctx = canceled
			case "revoker error":
				revoker.err = errors.New("private persistence diagnostic")
			case "malformed miss":
				revoker.id, revoker.version, revoker.malformedMiss = logoutSessionID(t), 2, true
			case "malformed result":
				revoker.revoked, revoker.version = true, 1
			}
			service, err := accountsession.NewLogoutService(keyring, revoker)
			if err != nil {
				t.Fatal(err)
			}
			_, logoutErr := service.Logout(ctx, token)
			if logoutErr == nil {
				t.Fatal("invalid or uncertain logout was accepted")
			}
			if mode == "revoker error" && errors.Is(logoutErr, revoker.err) &&
				!errors.Is(logoutErr, accountsession.ErrLogoutUnavailable) {
				t.Fatal("persistence error was not classified")
			}
		})
	}
}

func TestLogoutServiceRejectsIncompleteConstruction(t *testing.T) {
	t.Parallel()
	if service, err := accountsession.NewLogoutService(nil, &logoutRevoker{}); service != nil ||
		!errors.Is(err, accountsession.ErrInvalidLogoutService) {
		t.Fatal("nil keyring constructed logout service")
	}
	if service, err := accountsession.NewLogoutService(logoutKeyring(t), nil); service != nil ||
		!errors.Is(err, accountsession.ErrInvalidLogoutService) {
		t.Fatal("nil revoker constructed logout service")
	}
}

type logoutRevoker struct {
	expected      accountsession.Digest
	deployment    deployment.ID
	epoch         int64
	id            accountsession.ID
	version       int64
	revoked       bool
	malformedMiss bool
	err           error
	calls         int
}

func (revoker *logoutRevoker) Revoke(
	_ context.Context,
	deploymentID deployment.ID,
	epoch int64,
	digest accountsession.Digest,
) (accountsession.ID, int64, bool, error) {
	revoker.calls++
	revoker.deployment, revoker.epoch = deploymentID, epoch
	if revoker.err != nil {
		return accountsession.ID{}, 0, false, revoker.err
	}
	if revoker.expected.IsValid() && digest == revoker.expected {
		return revoker.id, revoker.version, true, nil
	}
	if revoker.expected.IsValid() && !revoker.malformedMiss {
		return accountsession.ID{}, 0, false, nil
	}
	return revoker.id, revoker.version, revoker.revoked, nil
}

func logoutKeyring(t *testing.T) *accountsession.Keyring {
	t.Helper()
	keyring, err := accountsession.NewKeyring(
		logoutDigestKey(t, "active-v2", 0x31),
		logoutDigestKey(t, "previous-v1", 0x42),
	)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func logoutDigestKey(t *testing.T, id string, fill byte) accountsession.DigestKey {
	t.Helper()
	keyID, err := accountsession.NewDigestKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	key, err := accountsession.NewDigestKey(keyID, bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func logoutDeploymentID(t *testing.T) deployment.ID {
	t.Helper()
	id, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func logoutSessionID(t *testing.T) accountsession.ID {
	t.Helper()
	id, err := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
