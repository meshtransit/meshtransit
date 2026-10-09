package provisioning_test

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
	"github.com/meshtransit/meshtransit/core/internal/domain/network/provisioning"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestValidPrefixes(t *testing.T) {
	t.Parallel()
	v6 := netip.MustParsePrefix("fd42:42:42:1::/64")
	for _, test := range []struct {
		ipv4, ipv6 string
		valid      bool
	}{
		{"100.64.1.0/24", "fd42:42:42:1::/64", true},
		{"100.127.255.240/28", "fd42:42:42:1::/64", true},
		{"100.64.0.0/16", "fd42:42:42::/56", true},
		{"100.128.0.0/24", "fd42:42:42:1::/64", false}, // outside 100.64.0.0/10
		{"10.0.0.0/24", "fd42:42:42:1::/64", false},
		{"100.64.0.0/10", "fd42:42:42:1::/64", false}, // larger than /16
		{"100.64.1.0/29", "fd42:42:42:1::/64", false},
		{"100.64.1.1/24", "fd42:42:42:1::/64", false}, // host bits
		{"100.64.1.0/24", "fd42:42:42::/48", false},
		{"100.64.1.0/24", "::ffff:100.64.1.0/120", false},
	} {
		ipv4 := netip.MustParsePrefix(test.ipv4)
		ipv6 := netip.MustParsePrefix(test.ipv6)
		if provisioning.ValidPrefixes(ipv4, ipv6) != test.valid {
			t.Errorf("%s %s: want %v", test.ipv4, test.ipv6, test.valid)
		}
	}
	if provisioning.ValidPrefixes(netip.Prefix{}, v6) {
		t.Fatal("zero IPv4 prefix accepted")
	}
	if !provisioning.ValidPrefixes(netip.MustParsePrefix("100.64.1.0/24"), netip.Prefix{}) {
		t.Fatal("an omitted IPv6 prefix asks Core to assign one")
	}
	if provisioning.ValidIPv6Prefix(netip.Prefix{}) {
		t.Fatal("zero IPv6 prefix is not a committed prefix")
	}
}

type stubStore struct{ result provisioning.Result }

func (store stubStore) Create(context.Context, provisioning.Command) (provisioning.Result, error) {
	return store.result, nil
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func TestServiceChecksCommittedPrefixes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 6, 1, 0, 0, 0, time.UTC)
	requested := netip.MustParsePrefix("fd42:42:42:7::/64")
	assigned := netip.MustParsePrefix("fd42:42:42::/64")
	for _, test := range []struct {
		name         string
		ask, receipt netip.Prefix
		receiptIPv4  string
		wantErr      error
	}{
		{name: "assigned when omitted", receipt: assigned, receiptIPv4: "100.64.1.0/24"},
		{name: "requested echoed", ask: requested, receipt: requested, receiptIPv4: "100.64.1.0/24"},
		{name: "requested but different", ask: requested, receipt: assigned, receiptIPv4: "100.64.1.0/24",
			wantErr: provisioning.ErrInvalid},
		{name: "no IPv6 committed", receiptIPv4: "100.64.1.0/24", wantErr: provisioning.ErrInvalid},
		{name: "different IPv4", receipt: assigned, receiptIPv4: "100.64.2.0/24", wantErr: provisioning.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := testCommand(t, now, test.ask)
			code, err := identity.ParseDisplayCode("004218650921")
			if err != nil {
				t.Fatal(err)
			}
			store := stubStore{result: provisioning.Result{NetworkID: command.NetworkID, DisplayCode: code,
				IPv4Prefix: netip.MustParsePrefix(test.receiptIPv4), IPv6Prefix: test.receipt, Version: 1,
				CreatedAt: now}}
			service, err := provisioning.NewService(store, fixedClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Create(context.Background(), command)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Create() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && result.IPv6Prefix != test.receipt {
				t.Fatalf("IPv6Prefix = %s, want %s", result.IPv6Prefix, test.receipt)
			}
		})
	}
}

func testCommand(t *testing.T, now time.Time, ipv6 netip.Prefix) provisioning.Command {
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
	return provisioning.Command{Session: session, WorkspaceID: workspace.ID(ids[4]), NetworkID: network.ID(ids[5]),
		DisplayName: "Office", IPv4Prefix: netip.MustParsePrefix("100.64.1.0/24"), IPv6Prefix: ipv6,
		CorrelationID: ids[6]}
}
