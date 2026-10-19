package site_test

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
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/core/internal/domain/workspace"
)

type recordingStore struct {
	calls   int
	change  site.Change
	router  site.RouterChange
	reading site.Reading
}

func (store *recordingStore) List(context.Context, accountsession.Session, network.Scope, site.ID, int) (site.Listing, error) {
	store.calls++
	return site.Listing{}, nil
}

func (store *recordingStore) Read(context.Context, accountsession.Session, network.Scope, site.ID) (site.Reading, error) {
	store.calls++
	return store.reading, nil
}

func (store *recordingStore) Change(_ context.Context, change site.Change) (site.Result, error) {
	store.calls++
	store.change = change
	return site.Result{}, nil
}

func (store *recordingStore) ChangeRouter(_ context.Context, change site.RouterChange) (site.Result, error) {
	store.calls++
	store.router = change
	return site.Result{}, nil
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func newID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestServiceValidatesBeforeTheStore(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	now := time.Date(2026, time.October, 18, 10, 0, 0, 0, time.UTC)
	denied := []netip.Prefix{netip.MustParsePrefix("18.142.253.199/32")}
	service, err := site.NewService(store, fixedClock{now}, site.SystemIDs{},
		site.Config{Limits: site.DefaultLimits(), Denied: denied})
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, now)
	login, _ := session.LoginWorkspaceID()
	scope, err := network.NewScope(login, network.ID(newID(t)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bad := site.Definition{Name: "VPC", Prefixes: []netip.Prefix{netip.MustParsePrefix("18.142.0.0/16")}}
	if _, err := service.Create(ctx, session, scope, bad, newID(t)); !errors.Is(err, site.ErrInvalidPrefix) {
		t.Fatalf("a Site covering a relay = %v", err)
	}
	if store.calls != 0 {
		t.Fatal("the store saw a refused change")
	}

	definition := site.Definition{Name: "HQ", Masquerade: true, Prefixes: []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("10.0.0.0/8"),
	}}
	if _, err := service.Create(ctx, session, scope, definition, newID(t)); err != nil {
		t.Fatal(err)
	}
	if store.change.Operation != site.OperationCreate || !store.change.SiteID.IsValid() ||
		store.change.SiteLimit != site.MaximumSitesPerNetwork ||
		store.change.Definition.Prefixes[0].String() != "10.0.0.0/8" {
		t.Fatalf("create = %+v", store.change)
	}

	siteID := site.ID(newID(t))
	device := node.ID(newID(t))
	assignment := site.RouterAssignment{DeviceID: device, Priority: 10, State: site.RouterActive}
	store.reading = site.Reading{Site: site.Site{ID: siteID, Version: 3, Definition: definition}}
	if _, err := service.PutRouter(ctx, session, scope, siteID, 3, assignment, newID(t)); err != nil {
		t.Fatal(err)
	}
	if store.router.RouterLimit != site.RoutersSupported || !store.router.RouterRowID.IsValid() ||
		store.router.Operation != site.RouterPut || store.router.ExpectedVersion != 3 {
		t.Fatalf("router = %+v", store.router)
	}
	if _, err := service.PutRouter(ctx, session, scope, siteID, 0, assignment, newID(t)); !errors.Is(err, site.ErrInvalid) {
		t.Fatalf("no expected version = %v", err)
	}

	late, err := site.NewService(store, fixedClock{now.Add(3 * time.Hour)}, site.SystemIDs{},
		site.Config{Limits: site.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.List(ctx, session, scope, site.ID{}, site.MaximumPage+1); !errors.Is(err, site.ErrInvalid) {
		t.Fatalf("an oversized page = %v", err)
	}
	if _, err := late.List(ctx, session, scope, site.ID{}, site.DefaultPage); !errors.Is(err, site.ErrForbidden) {
		t.Fatalf("expired Session listed Sites: %v", err)
	}
	if _, err := site.NewService(store, fixedClock{now}, site.SystemIDs{}, site.Config{}); !errors.Is(err, site.ErrInvalid) {
		t.Fatalf("zero limits accepted: %v", err)
	}
}

func TestServiceKeepsOneRouterWithoutMasquerade(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 19, 10, 0, 0, 0, time.UTC)
	session := activeSession(t, now)
	login, _ := session.LoginWorkspaceID()
	scope, _ := network.NewScope(login, network.ID(newID(t)))
	siteID := site.ID(newID(t))
	first, second := node.ID(newID(t)), node.ID(newID(t))
	routed := site.Definition{Name: "VPC", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}}
	masqueraded := routed
	masqueraded.Masquerade = true
	router := func(id node.ID) site.Router {
		return site.Router{RouterAssignment: site.RouterAssignment{DeviceID: id, Priority: 10, State: site.RouterActive}}
	}
	put := func(id node.ID) site.RouterAssignment {
		return site.RouterAssignment{DeviceID: id, Priority: 20, State: site.RouterActive}
	}
	for name, test := range map[string]struct {
		stored  site.Site
		change  func(*site.Service) error
		wantErr error
	}{
		"a second router without masquerade": {
			stored: site.Site{ID: siteID, Version: 4, Routers: []site.Router{router(first)}, Definition: routed},
			change: func(service *site.Service) error {
				_, err := service.PutRouter(t.Context(), session, scope, siteID, 4, put(second), newID(t))
				return err
			},
			wantErr: site.ErrMasqueradeRequired,
		},
		"the one router changes its priority": {
			stored: site.Site{ID: siteID, Version: 4, Routers: []site.Router{router(first)}, Definition: routed},
			change: func(service *site.Service) error {
				_, err := service.PutRouter(t.Context(), session, scope, siteID, 4, put(first), newID(t))
				return err
			},
		},
		"a second router with masquerade": {
			stored: site.Site{ID: siteID, Version: 4, Routers: []site.Router{router(first)}, Definition: masqueraded},
			change: func(service *site.Service) error {
				_, err := service.PutRouter(t.Context(), session, scope, siteID, 4, put(second), newID(t))
				return err
			},
		},
		"masquerade turned off with two routers": {
			stored: site.Site{ID: siteID, Version: 4, Routers: []site.Router{router(first), router(second)},
				Definition: masqueraded},
			change: func(service *site.Service) error {
				_, err := service.Update(t.Context(), session, scope, siteID, 4, routed, newID(t))
				return err
			},
			wantErr: site.ErrMasqueradeRequired,
		},
		"a decision on an older Site": {
			stored: site.Site{ID: siteID, Version: 5, Routers: []site.Router{router(first)}, Definition: routed},
			change: func(service *site.Service) error {
				_, err := service.PutRouter(t.Context(), session, scope, siteID, 4, put(first), newID(t))
				return err
			},
			wantErr: site.ErrVersionConflict,
		},
	} {
		store := &recordingStore{reading: site.Reading{Site: test.stored}}
		service, err := site.NewService(store, fixedClock{now}, site.SystemIDs{}, site.Config{Limits: site.DefaultLimits()})
		if err != nil {
			t.Fatal(err)
		}
		if err := test.change(service); !errors.Is(err, test.wantErr) {
			t.Errorf("%s: error = %v, want %v", name, err, test.wantErr)
		}
		if wrote := store.router.Operation != "" || store.change.Operation != ""; wrote != (test.wantErr == nil) {
			t.Errorf("%s: wrote = %t", name, wrote)
		}
	}
}

func TestEligible(t *testing.T) {
	t.Parallel()
	if !site.Eligible("active", "workspace", true) {
		t.Fatal("an active Workspace Device offering the Site was not eligible")
	}
	for name, test := range map[string]struct {
		state, ownership string
		offers           bool
	}{
		"suspended":   {"suspended", "workspace", true},
		"member":      {"active", "member", true},
		"not offered": {"active", "workspace", false},
	} {
		if site.Eligible(test.state, test.ownership, test.offers) {
			t.Errorf("%s: eligible", name)
		}
	}
}

func activeSession(t *testing.T, now time.Time) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID, IdentitySubjectID: subjectID,
		LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
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
