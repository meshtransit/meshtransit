package aliasrange_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/network/aliasrange"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var (
	frame4 = netip.MustParsePrefix("198.18.0.0/16")
	frame6 = netip.MustParsePrefix("fd02:48de:ec1b:1::/96")
)

func TestValidRanges(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		prefix string
		ipv4   bool
		valid  bool
	}{
		{"198.18.42.0/24", true, true},
		{"198.18.0.0/16", true, true},
		{"198.18.42.240/28", true, true},
		{"198.18.42.1/24", true, false}, // host bits
		{"198.16.0.0/14", true, false},  // larger than /16
		{"198.18.42.0/29", true, false},
		{"fd02:48de:ec1b:1::2a00/120", false, true},
		{"fd02:48de:ec1b:1::/96", false, true},
		{"fd02:48de:ec1b::/80", false, false},
		{"::ffff:198.18.42.0/120", false, false},
	} {
		prefix := netip.MustParsePrefix(test.prefix)
		got := aliasrange.ValidIPv6Range(prefix)
		if test.ipv4 {
			got = aliasrange.ValidIPv4Range(prefix)
		}
		if got != test.valid {
			t.Errorf("%s: valid = %v, want %v", test.prefix, got, test.valid)
		}
	}
}

func TestCommandValidation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 7, 1, 0, 0, 0, time.UTC)
	base := testCommand(t, now)
	for _, test := range []struct {
		name   string
		mutate func(*aliasrange.Command)
		valid  bool
	}{
		{name: "set IPv4", mutate: func(*aliasrange.Command) {}, valid: true},
		{name: "clear IPv6 only", mutate: func(command *aliasrange.Command) {
			command.IPv4 = aliasrange.Change{}
			command.IPv6 = aliasrange.Change{Present: true}
		}, valid: true},
		{name: "nothing requested", mutate: func(command *aliasrange.Command) { command.IPv4 = aliasrange.Change{} }},
		{name: "absent with a prefix", mutate: func(command *aliasrange.Command) {
			command.IPv6 = aliasrange.Change{Prefix: netip.MustParsePrefix("fd02:48de:ec1b:1::2a00/120")}
		}},
		{name: "family swapped", mutate: func(command *aliasrange.Command) {
			command.IPv4 = aliasrange.Change{Present: true, Prefix: netip.MustParsePrefix("fd02:48de:ec1b:1::2a00/120")}
		}},
		{name: "missing version", mutate: func(command *aliasrange.Command) { command.ExpectedVersion = 0 }},
		{name: "missing correlation", mutate: func(command *aliasrange.Command) { command.CorrelationID = publicid.ID{} }},
	} {
		command := base
		test.mutate(&command)
		if command.IsValid() != test.valid {
			t.Errorf("%s: IsValid() = %v, want %v", test.name, command.IsValid(), test.valid)
		}
	}
}

type stubStore struct {
	state  aliasrange.State
	result aliasrange.Result
	err    error
	calls  int
}

func (store *stubStore) Read(context.Context, accountsession.Session, network.Scope, time.Time) (aliasrange.State, error) {
	store.calls++
	return store.state, store.err
}

func (store *stubStore) Update(context.Context, aliasrange.Command, time.Time) (aliasrange.Result, error) {
	store.calls++
	return store.result, store.err
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func committedState(version int64, ipv4 netip.Prefix) aliasrange.State {
	return aliasrange.State{
		Version:    version,
		IPv4:       aliasrange.Family{Family: 4, Frame: frame4, Prefix: ipv4, Retained: 1},
		IPv6:       aliasrange.Family{Family: 6, Frame: frame6},
		LiveShares: 1, ShareLimit: aliasrange.ShareLimit,
	}
}

func TestServiceChecksReceipts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 7, 1, 0, 0, 0, time.UTC)
	chosen := netip.MustParsePrefix("198.18.42.0/24")
	outside := netip.MustParsePrefix("198.19.42.0/24")
	for _, test := range []struct {
		name    string
		result  aliasrange.Result
		err     error
		wantErr error
	}{
		{name: "changed", result: aliasrange.Result{State: committedState(3, chosen), Changed: true}},
		{name: "already current", result: aliasrange.Result{State: committedState(2, chosen)}},
		{name: "changed without a new version", result: aliasrange.Result{State: committedState(2, chosen), Changed: true},
			wantErr: aliasrange.ErrInvalid},
		{name: "different prefix", result: aliasrange.Result{State: committedState(3, netip.MustParsePrefix("198.18.43.0/24")), Changed: true},
			wantErr: aliasrange.ErrInvalid},
		{name: "prefix outside the frame", result: aliasrange.Result{State: committedState(3, outside), Changed: true},
			wantErr: aliasrange.ErrInvalid},
		{name: "store conflict", err: aliasrange.ErrInUse, wantErr: aliasrange.ErrInUse},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := testCommand(t, now)
			command.IPv4 = aliasrange.Change{Present: true, Prefix: chosen}
			if test.name == "prefix outside the frame" {
				command.IPv4.Prefix = outside
			}
			store := &stubStore{result: test.result, err: test.err}
			service, err := aliasrange.NewService(store, fixedClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Update(context.Background(), command); !errors.Is(err, test.wantErr) {
				t.Fatalf("Update() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestServiceRejectsInactiveSessionBeforeStore(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 7, 1, 0, 0, 0, time.UTC)
	command := testCommand(t, now)
	store := &stubStore{state: committedState(1, netip.Prefix{})}
	service, err := aliasrange.NewService(store, fixedClock{now: now.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Read(context.Background(), command.Session, command.Scope); !errors.Is(err, aliasrange.ErrForbidden) {
		t.Fatalf("Read() error = %v, want forbidden", err)
	}
	if _, err := service.Update(context.Background(), command); !errors.Is(err, aliasrange.ErrForbidden) {
		t.Fatalf("Update() error = %v, want forbidden", err)
	}
	if store.calls != 0 {
		t.Fatal("an expired Session reached the store")
	}
	if _, err := aliasrange.NewService(nil, fixedClock{now: now}); !errors.Is(err, aliasrange.ErrInvalid) {
		t.Fatal("missing store accepted")
	}
}

func testCommand(t *testing.T, now time.Time) aliasrange.Command {
	t.Helper()
	ids := make([]publicid.ID, 7)
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
	return aliasrange.Command{Session: session, Scope: scope, ExpectedVersion: 2,
		IPv4: aliasrange.Change{Present: true, Prefix: netip.MustParsePrefix("198.18.42.0/24")}, CorrelationID: ids[6]}
}
