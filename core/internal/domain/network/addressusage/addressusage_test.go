package addressusage_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/addressusage"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type stubStore struct {
	state addressusage.State
	err   error
	reads int
}

func (store *stubStore) Read(context.Context, accountsession.Session, network.Scope) (addressusage.State, error) {
	store.reads++
	return store.state, store.err
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func sessionAndScope(t *testing.T, now time.Time) (accountsession.Session, network.Scope) {
	t.Helper()
	ids := make([]publicid.ID, 6)
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = id
	}
	session, err := accountsession.NewSession(accountsession.Params{
		ID: accountsession.ID(ids[0]), DeploymentID: deployment.ID(ids[1]), PrincipalID: identity.PrincipalID(ids[2]),
		IdentitySubjectID: accountsession.IdentitySubjectID(ids[3]), LoginWorkspaceID: workspace.ID(ids[4]),
		HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test",
		AMR: []string{"mfa"}, Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspace.ID(ids[4]), network.ID(ids[5]))
	if err != nil {
		t.Fatal(err)
	}
	return session, scope
}

func TestStateValidity(t *testing.T) {
	t.Parallel()
	release := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	ipv4 := addressusage.Range{Prefix: netip.MustParsePrefix("100.80.0.0/16"), Capacity: 65534, InUse: 10,
		HeldByExpired: 2, HeldAfterRevocation: 3, NextRelease: release}
	ipv6 := addressusage.Range{Prefix: netip.MustParsePrefix("fd07:d4de:9d87::/64"), InUse: 10}
	narrow := addressusage.Range{Prefix: netip.MustParsePrefix("fd07:d4de:9d87::/112"), Capacity: 65535, InUse: 10}
	if !(addressusage.State{Ranges: []addressusage.Range{ipv4, ipv6, narrow}}).IsValid() {
		t.Fatal("a sound state was refused")
	}
	for name, usage := range map[string]addressusage.Range{
		"host bits":                   {Prefix: netip.MustParsePrefix("100.80.0.1/16"), Capacity: 65534},
		"wide IPv6 with a capacity":   {Prefix: ipv6.Prefix, Capacity: 10},
		"narrow IPv6 without one":     {Prefix: netip.MustParsePrefix("fd07:d4de:9d87::/112")},
		"IPv4 without a capacity":     {Prefix: ipv4.Prefix},
		"more held than the capacity": {Prefix: netip.MustParsePrefix("100.80.0.0/28"), Capacity: 14, InUse: 15},
		"held without a release time": {Prefix: ipv4.Prefix, Capacity: 65534, HeldAfterRevocation: 1},
		"release time with none held": {Prefix: ipv4.Prefix, Capacity: 65534, NextRelease: release},
		"negative count":              {Prefix: ipv4.Prefix, Capacity: 65534, InUse: -1},
		"no prefix":                   {Capacity: 1},
	} {
		if (addressusage.State{Ranges: []addressusage.Range{usage}}).IsValid() {
			t.Errorf("%s: accepted", name)
		}
	}
	if (addressusage.State{}).IsValid() {
		t.Error("a Network without ranges was accepted")
	}
}

func TestServiceRead(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	session, scope := sessionAndScope(t, now)
	state := addressusage.State{Ranges: []addressusage.Range{
		{Prefix: netip.MustParsePrefix("100.80.0.0/16"), Capacity: 65534, InUse: 3}}}
	store := &stubStore{state: state}
	service, err := addressusage.NewService(store, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Read(t.Context(), session, scope)
	if err != nil || len(got.Ranges) != 1 || got.Ranges[0].InUse != 3 || store.reads != 1 {
		t.Fatalf("Read() = %+v, %v (store reads %d)", got, err, store.reads)
	}
	// A Session that ended reads nothing.
	ended, err := addressusage.NewService(store, fixedClock{now: now.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ended.Read(t.Context(), session, scope); !errors.Is(err, addressusage.ErrForbidden) {
		t.Fatalf("ended Session: %v", err)
	}
	// A store result that does not add up is refused.
	store.state = addressusage.State{}
	if _, err := service.Read(t.Context(), session, scope); !errors.Is(err, addressusage.ErrInvalid) {
		t.Fatalf("invalid result: %v", err)
	}
	store.err = addressusage.ErrForbidden
	if _, err := service.Read(t.Context(), session, scope); !errors.Is(err, addressusage.ErrForbidden) {
		t.Fatalf("store refusal: %v", err)
	}
}
