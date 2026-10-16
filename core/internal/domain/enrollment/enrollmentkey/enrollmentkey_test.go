package enrollmentkey_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

func mustID(t *testing.T, suffix string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func keyParams(t *testing.T, state enrollmentkey.State) enrollmentkey.KeyParams {
	t.Helper()
	created := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	params := enrollmentkey.KeyParams{
		ID: enrollment.CredentialID(mustID(t, "000000000401")), IssuedBy: identity.PrincipalID(mustID(t, "000000000011")),
		CreatedAt: created, ExpiresAt: created.Add(24 * time.Hour), State: state,
		DeviceLifetime: enrollment.NeverExpiringDeviceLifetime(),
	}
	switch state {
	case enrollmentkey.StateUsed:
		params.DeviceID, params.DeviceName = node.ID(mustID(t, "000000000501")), "build-1"
	case enrollmentkey.StateRevoked:
		params.RevokedAt = created.Add(time.Hour)
	}
	return params
}

func TestNewKeyChecksStateAgainstItsDevice(t *testing.T) {
	t.Parallel()

	for _, state := range []enrollmentkey.State{enrollmentkey.StateActive, enrollmentkey.StateUsed,
		enrollmentkey.StateExpired, enrollmentkey.StateRevoked} {
		if _, err := enrollmentkey.NewKey(keyParams(t, state)); err != nil {
			t.Fatalf("NewKey(%s) error = %v", state, err)
		}
	}
	revokedAfterUse := keyParams(t, enrollmentkey.StateRevoked)
	revokedAfterUse.DeviceID, revokedAfterUse.DeviceName = node.ID(mustID(t, "000000000501")), "build-1"
	if _, err := enrollmentkey.NewKey(revokedAfterUse); err != nil {
		t.Fatalf("a key revoked after use was refused: %v", err)
	}
	for name, mutate := range map[string]func(*enrollmentkey.KeyParams){
		"used without a Device":      func(p *enrollmentkey.KeyParams) { p.State = enrollmentkey.StateUsed },
		"active with a Device":       func(p *enrollmentkey.KeyParams) { p.DeviceID = node.ID(mustID(t, "000000000501")) },
		"revoked without a time":     func(p *enrollmentkey.KeyParams) { p.State = enrollmentkey.StateRevoked },
		"active with a revoked time": func(p *enrollmentkey.KeyParams) { p.RevokedAt = p.CreatedAt },
		"profile lifetime":           func(p *enrollmentkey.KeyParams) { p.DeviceLifetime = enrollment.DeviceLifetime{} },
		"expiry before creation":     func(p *enrollmentkey.KeyParams) { p.ExpiresAt = p.CreatedAt },
		"unknown state":              func(p *enrollmentkey.KeyParams) { p.State = "paused" },
		"control character":          func(p *enrollmentkey.KeyParams) { p.Description = "a\nb" },
		"description too long":       func(p *enrollmentkey.KeyParams) { p.Description = strings.Repeat("x", 129) },
	} {
		params := keyParams(t, enrollmentkey.StateActive)
		mutate(&params)
		if _, err := enrollmentkey.NewKey(params); !errors.Is(err, enrollmentkey.ErrInvalid) {
			t.Fatalf("NewKey with %s error = %v, want ErrInvalid", name, err)
		}
	}
}

type recordingStore struct{ issued []enrollmentkey.Issue }

func (store *recordingStore) IssueEnrollmentKey(_ context.Context, issue enrollmentkey.Issue) (enrollmentkey.Key, error) {
	store.issued = append(store.issued, issue)
	created := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	return enrollmentkey.NewKey(enrollmentkey.KeyParams{
		ID: issue.CredentialID, IssuedBy: issue.Session.PrincipalID(), CreatedAt: created,
		ExpiresAt: created.Add(issue.KeyLifetime), State: enrollmentkey.StateActive,
		DeviceLifetime: issue.DeviceLifetime, Description: issue.Description,
	})
}

func (*recordingStore) ListEnrollmentKeys(context.Context, accountsession.Session, network.Scope) ([]enrollmentkey.Key, error) {
	return nil, nil
}

func (*recordingStore) RevokeEnrollmentKey(context.Context, enrollmentkey.Revocation) (enrollmentkey.Key, error) {
	return enrollmentkey.Key{}, nil
}

type fixedClock time.Time

func (clock fixedClock) Now() time.Time { return time.Time(clock) }

func activeSession(t *testing.T, now time.Time) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: identity.PrincipalID(mustID(t, "000000000011")),
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestServiceIssueDefaultsAndBounds(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	service, err := enrollmentkey.NewService(store, fixedClock(now))
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, now)
	workspaceID, _ := session.LoginWorkspaceID()
	scope, err := network.NewScope(workspaceID, network.ID(mustID(t, "000000000203")))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(context.Background(), session, enrollmentkey.IssueRequest{
		Scope: scope, DeviceLifetime: enrollment.NeverExpiringDeviceLifetime(), CorrelationID: mustID(t, "000000000901"),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if len(store.issued) != 1 || store.issued[0].KeyLifetime != enrollmentkey.DefaultKeyLifetime ||
		!store.issued[0].Token.IsValid() || issued.Presentation().CredentialID() != issued.Key().ID() ||
		issued.Presentation().Token() != store.issued[0].Token {
		t.Fatalf("issued %+v with %d store calls", issued.Key(), len(store.issued))
	}
	fixed, err := enrollment.NewDeviceLifetime(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]enrollmentkey.IssueRequest{
		"profile Device lifetime": {Scope: scope, CorrelationID: mustID(t, "000000000902")},
		"key under 5 minutes":     {Scope: scope, DeviceLifetime: fixed, KeyLifetime: 4 * time.Minute, CorrelationID: mustID(t, "000000000903")},
		"key over 30 days":        {Scope: scope, DeviceLifetime: fixed, KeyLifetime: 31 * 24 * time.Hour, CorrelationID: mustID(t, "000000000904")},
		"fractional seconds":      {Scope: scope, DeviceLifetime: fixed, KeyLifetime: time.Hour + time.Millisecond, CorrelationID: mustID(t, "000000000905")},
		"no correlation":          {Scope: scope, DeviceLifetime: fixed},
		"no scope":                {DeviceLifetime: fixed, CorrelationID: mustID(t, "000000000906")},
		"padded description":      {Scope: scope, DeviceLifetime: fixed, Description: " x", CorrelationID: mustID(t, "000000000907")},
	} {
		if _, err := service.Issue(context.Background(), session, request); !errors.Is(err, enrollmentkey.ErrInvalid) {
			t.Fatalf("Issue with %s error = %v, want ErrInvalid", name, err)
		}
	}
	if len(store.issued) != 1 {
		t.Fatalf("invalid requests reached the store: %d calls", len(store.issued))
	}
	ended, err := enrollmentkey.NewService(store, fixedClock(now.Add(48*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ended.Issue(context.Background(), session, enrollmentkey.IssueRequest{
		Scope: scope, DeviceLifetime: fixed, CorrelationID: mustID(t, "000000000908"),
	}); !errors.Is(err, enrollmentkey.ErrForbidden) {
		t.Fatalf("an ended session issued a key: %v", err)
	}
}
