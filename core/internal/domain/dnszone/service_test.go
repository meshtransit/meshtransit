package dnszone_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type recordingStore struct {
	calls  int
	change dnszone.Change
	names  dnszone.NameChange
	stored dnszone.Zone
}

func (store *recordingStore) List(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	int) (dnszone.Listing, error) {
	store.calls++
	return dnszone.Listing{WorkspaceCode: "073438549244", NetworkCode: "296056403058"}, nil
}

func (store *recordingStore) Read(context.Context, accountsession.Session, network.Scope,
	dnszone.ID) (dnszone.Reading, error) {
	store.calls++
	return dnszone.Reading{Zone: store.stored}, nil
}

func (store *recordingStore) Change(_ context.Context, change dnszone.Change) (dnszone.Result, error) {
	store.calls++
	store.change = change
	return dnszone.Result{}, nil
}

func (store *recordingStore) ListNames(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	dnszone.NameID, string, int) (dnszone.NameListing, error) {
	store.calls++
	return dnszone.NameListing{}, nil
}

func (store *recordingStore) ReadName(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	dnszone.NameID) (dnszone.NameReading, error) {
	store.calls++
	return dnszone.NameReading{}, nil
}

func (store *recordingStore) ChangeNames(_ context.Context, change dnszone.NameChange) (dnszone.NameResult, error) {
	store.calls++
	store.names = change
	outcomes := make([]dnszone.NameOutcome, 0, len(change.Operations))
	for index, operation := range change.Operations {
		outcomes = append(outcomes, dnszone.NameOutcome{Index: index, Operation: operation.Operation, Changed: true})
	}
	return dnszone.NameResult{Outcomes: outcomes, Changed: true}, nil
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

type fixture struct {
	store   *recordingStore
	service *dnszone.Service
	session accountsession.Session
	scope   network.Scope
	now     time.Time
}

func newFixture(t *testing.T, options dnszone.Options) fixture {
	t.Helper()
	now := time.Date(2026, time.October, 22, 10, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	if !options.Names.Suffix.IsValid() {
		options.Names.Suffix = dnsname.Default()
	}
	service, err := dnszone.NewService(store, fixedClock{now}, dnszone.SystemIDs{}, dnszone.DefaultLimits(), options)
	if err != nil {
		t.Fatal(err)
	}
	session := activeSession(t, now)
	login, _ := session.LoginWorkspaceID()
	scope, err := network.NewScope(login, network.ID(newID(t)))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{store: store, service: service, session: session, scope: scope, now: now}
}

func internetResolver() []dnszone.Resolver {
	return []dnszone.Resolver{{Address: netip.MustParseAddr("1.1.1.1"), Port: dnszone.DNSPort}}
}

func TestServiceCreatesACanonicalZone(t *testing.T) {
	t.Parallel()
	f := newFixture(t, dnszone.Options{Enabled: true})
	correlation := newID(t)
	if _, err := f.service.Create(context.Background(), f.session, f.scope, dnszone.Definition{
		Domain: "Corp.Internal.", FailureMode: dnszone.FailClosed, Resolvers: internetResolver(),
	}, false, correlation); err != nil {
		t.Fatal(err)
	}
	change := f.store.change
	if change.Operation != dnszone.OperationCreate || change.Domain != "corp.internal" ||
		change.Class != dnszone.ClassPrivate || change.Definition.Domain != "corp.internal" ||
		!change.ZoneID.IsValid() || change.ListVersion == "" || change.Limits != dnszone.DefaultLimits() ||
		change.CorrelationID != correlation {
		t.Fatalf("change = %+v", change)
	}
}

func TestServiceRefusesBeforeTheStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, test := range map[string]struct {
		options    dnszone.Options
		definition dnszone.Definition
		want       error
	}{
		"disabled": {dnszone.Options{}, dnszone.Definition{Domain: "corp.internal", FailureMode: dnszone.FailOpen,
			Resolvers: internetResolver()}, dnszone.ErrDisabled},
		"root before D1b": {dnszone.Options{Enabled: true}, dnszone.Definition{Domain: ".",
			FailureMode: dnszone.FailOpen, Resolvers: internetResolver()}, dnszone.ErrRootUnavailable},
		"public unconfirmed": {dnszone.Options{Enabled: true}, dnszone.Definition{Domain: "corp.com",
			FailureMode: dnszone.FailOpen, Resolvers: internetResolver()}, dnszone.ErrPublicUnconfirmed},
		"protected name": {dnszone.Options{Enabled: true, Names: dnszone.Names{Suffix: dnsname.Default(),
			Protected: []string{"mesh.corp.com"}}}, dnszone.Definition{Domain: "corp.com",
			FailureMode: dnszone.FailOpen, Resolvers: internetResolver(), PublicConfirmed: true},
			dnszone.ErrDomainCoversControl},
		"private resolver": {dnszone.Options{Enabled: true}, dnszone.Definition{Domain: "corp.internal",
			FailureMode: dnszone.FailOpen, Resolvers: []dnszone.Resolver{{
				Address: netip.MustParseAddr("10.0.0.2"), Port: dnszone.DNSPort}}}, dnszone.ErrResolverNotInternet},
		"public suffix": {dnszone.Options{Enabled: true}, dnszone.Definition{Domain: "com",
			FailureMode: dnszone.FailOpen, Resolvers: internetResolver()}, dnszone.ErrDomainPublicSuffix},
	} {
		f := newFixture(t, test.options)
		if _, err := f.service.Create(ctx, f.session, f.scope, test.definition, false, newID(t)); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", name, err, test.want)
		}
		if f.store.calls != 0 {
			t.Errorf("%s: reached the store", name)
		}
	}
	f := newFixture(t, dnszone.Options{Enabled: true, Root: true})
	position := 1
	if _, err := f.service.Create(ctx, f.session, f.scope, dnszone.Definition{Domain: ".",
		FailureMode: dnszone.FailOpen, Resolvers: internetResolver(), SearchPosition: &position},
		false, newID(t)); !errors.Is(err, dnszone.ErrInvalid) {
		t.Errorf("a root search domain: %v", err)
	}
	if _, err := f.service.Create(ctx, f.session, f.scope, dnszone.Definition{Domain: ".",
		FailureMode: dnszone.FailOpen, Resolvers: internetResolver()}, false, newID(t)); err != nil {
		t.Errorf("the root where offered: %v", err)
	}
}

func TestServiceUpdateKeepsTheStoredDomain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, dnszone.Options{Enabled: true})
	zone := dnszone.ID(newID(t))
	f.store.stored = dnszone.Zone{ID: zone, Domain: "corp.com", OtherNames: dnszone.OtherForward,
		Class: dnszone.ClassPublic, ListVersion: "x/net v1"}
	definition := dnszone.Definition{FailureMode: dnszone.FailOpen, Resolvers: internetResolver()}
	if _, err := f.service.Update(ctx, f.session, f.scope, zone, 2, definition, newID(t)); !errors.Is(err,
		dnszone.ErrPublicUnconfirmed) {
		t.Fatalf("an unconfirmed public zone: %v", err)
	}
	definition.PublicConfirmed = true
	if _, err := f.service.Update(ctx, f.session, f.scope, zone, 2, definition, newID(t)); err != nil {
		t.Fatal(err)
	}
	change := f.store.change
	if change.Operation != dnszone.OperationUpdate || change.Domain != "corp.com" || change.ExpectedVersion != 2 ||
		change.ListVersion != "x/net v1" || change.Definition.Domain != "corp.com" {
		t.Fatalf("change = %+v", change)
	}
	definition.Domain = "other.com"
	if _, err := f.service.Update(ctx, f.session, f.scope, zone, 3, definition, newID(t)); !errors.Is(err,
		dnszone.ErrInvalid) {
		t.Fatalf("a new domain: %v", err)
	}
	if _, err := f.service.Delete(ctx, f.session, f.scope, zone, 0, false, newID(t)); !errors.Is(err, dnszone.ErrInvalid) {
		t.Fatalf("delete without version: %v", err)
	}
	if _, err := f.service.Delete(ctx, f.session, f.scope, zone, 3, false, newID(t)); err != nil ||
		f.store.change.Operation != dnszone.OperationDelete {
		t.Fatalf("delete: %v", err)
	}
}

func TestServiceRefusesAnExpiredSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t, dnszone.Options{Enabled: true})
	expired := activeSession(t, f.now.Add(-24*time.Hour))
	if _, err := f.service.List(context.Background(), expired, f.scope, dnszone.ID{}, 10); !errors.Is(err,
		dnszone.ErrForbidden) {
		t.Fatalf("expired session: %v", err)
	}
	if _, err := f.service.List(context.Background(), f.session, f.scope, dnszone.ID{},
		dnszone.MaximumPage+1); !errors.Is(err, dnszone.ErrInvalid) {
		t.Fatalf("page too large: %v", err)
	}
}

func TestServiceNamesTheSystemZones(t *testing.T) {
	t.Parallel()
	f := newFixture(t, dnszone.Options{})
	listing, err := f.service.List(context.Background(), f.session, f.scope, dnszone.ID{}, dnszone.DefaultPage)
	if err != nil || listing.System.Network != "073438549244.296056403058.mesh.internal" ||
		listing.System.Shared != "shared.mesh.internal" {
		t.Fatalf("system zones = %+v, error = %v", listing.System, err)
	}
}

func TestServiceZoneKinds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, dnszone.Options{Enabled: true, Root: true})
	if _, err := f.service.Create(ctx, f.session, f.scope, dnszone.Definition{Domain: "corp.com",
		OtherNames: dnszone.OtherNXDomain, PublicConfirmed: true}, false, newID(t)); !errors.Is(err,
		dnszone.ErrNXDomainPublic) {
		t.Errorf("nxdomain on a public domain: %v", err)
	}
	if _, err := f.service.Create(ctx, f.session, f.scope, dnszone.Definition{Domain: ".",
		OtherNames: dnszone.OtherHost}, false, newID(t)); !errors.Is(err, dnszone.ErrInvalid) {
		t.Errorf("a host root zone: %v", err)
	}
	if _, err := f.service.Create(ctx, f.session, f.scope, dnszone.Definition{Domain: "corp.internal",
		OtherNames: dnszone.OtherNXDomain}, true, newID(t)); err != nil {
		t.Fatal(err)
	}
	if change := f.store.change; change.Definition.OtherNames != dnszone.OtherNXDomain ||
		change.Definition.FailureMode != dnszone.FailOpen || !change.WithNames {
		t.Fatalf("nxdomain zone change = %+v", change)
	}
	if _, err := f.service.Create(ctx, f.session, f.scope, dnszone.Definition{Domain: "lan",
		FailureMode: dnszone.FailOpen, Resolvers: internetResolver()}, false, newID(t)); err != nil ||
		f.store.change.Definition.OtherNames != dnszone.OtherForward {
		t.Fatalf("a zone without a kind forwards: %v, %+v", err, f.store.change.Definition)
	}
	zone := dnszone.ID(newID(t))
	f.store.stored = dnszone.Zone{ID: zone, Domain: "corp.internal", OtherNames: dnszone.OtherHost,
		Class: dnszone.ClassPrivate, ListVersion: "x/net v1"}
	if _, err := f.service.Update(ctx, f.session, f.scope, zone, 4, dnszone.Definition{}, newID(t)); err != nil ||
		f.store.change.Definition.OtherNames != dnszone.OtherHost {
		t.Fatalf("an update without a kind keeps the zone's: %v, %+v", err, f.store.change.Definition)
	}
	if _, err := f.service.Delete(ctx, f.session, f.scope, zone, 5, true, newID(t)); err != nil ||
		!f.store.change.WithNames {
		t.Fatalf("delete with names: %v, %+v", err, f.store.change)
	}
}

func TestServiceAppliesCanonicalNames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, dnszone.Options{Enabled: true})
	zone := dnszone.ID(newID(t))
	f.store.stored = dnszone.Zone{ID: zone, Domain: "corp.internal", OtherNames: dnszone.OtherNXDomain}
	device := node.ID(newID(t))
	existing := dnszone.NameID(newID(t))
	correlation := newID(t)
	result, err := f.service.ApplyNames(ctx, f.session, f.scope, zone, []dnszone.NameOperation{
		{Operation: dnszone.OperationDelete, NameID: existing, ExpectedVersion: 2},
		{Operation: dnszone.OperationCreate, Definition: dnszone.NameDefinition{Label: "Wiki", Kind: dnszone.NameCNAME,
			Target: dnszone.NameTarget{CNAME: "Corp.Atlassian.NET."}}},
		{Operation: dnszone.OperationCreate, Definition: dnszone.NameDefinition{Label: "@", Kind: dnszone.NameAddress,
			Target: dnszone.NameTarget{DeviceID: device}}},
	}, correlation)
	if err != nil || !result.Changed || len(result.Outcomes) != 3 {
		t.Fatalf("ApplyNames = %+v, %v", result, err)
	}
	change := f.store.names
	created := change.Operations[1]
	if change.ZoneID != zone || change.CorrelationID != correlation || change.Limits != dnszone.DefaultLimits() ||
		!created.NameID.IsValid() || created.Definition.Label != "wiki" ||
		created.Definition.Target.CNAME != "corp.atlassian.net" || change.Operations[2].Definition.Label != "@" ||
		change.Operations[0].NameID != existing || change.Operations[0].ExpectedVersion != 2 {
		t.Fatalf("change = %+v", change)
	}
}

func TestServiceRefusesNameOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, dnszone.Options{Enabled: true})
	zone := dnszone.ID(newID(t))
	f.store.stored = dnszone.Zone{ID: zone, Domain: "corp.internal", OtherNames: dnszone.OtherNXDomain}
	name := dnszone.NameID(newID(t))
	address := dnszone.NameTarget{Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.20")}}
	valid := dnszone.NameOperation{Operation: dnszone.OperationCreate,
		Definition: dnszone.NameDefinition{Label: "printer", Kind: dnszone.NameAddress, Target: address}}
	for label, test := range map[string]struct {
		operation dnszone.NameOperation
		want      error
	}{
		"CNAME at the apex": {dnszone.NameOperation{Operation: dnszone.OperationCreate,
			Definition: dnszone.NameDefinition{Label: "@", Kind: dnszone.NameCNAME,
				Target: dnszone.NameTarget{CNAME: "corp.atlassian.net"}}}, dnszone.ErrCNAMEAtApex},
		"CNAME to itself": {dnszone.NameOperation{Operation: dnszone.OperationCreate,
			Definition: dnszone.NameDefinition{Label: "wiki", Kind: dnszone.NameCNAME,
				Target: dnszone.NameTarget{CNAME: "wiki.corp.internal"}}}, dnszone.ErrCNAMELoop},
		"CNAME into the mesh": {dnszone.NameOperation{Operation: dnszone.OperationCreate,
			Definition: dnszone.NameDefinition{Label: "wiki", Kind: dnszone.NameCNAME,
				Target: dnszone.NameTarget{CNAME: "git.shared.mesh.internal"}}}, dnszone.ErrNameTargetInvalid},
		"a create with an ID": {dnszone.NameOperation{Operation: dnszone.OperationCreate, NameID: name,
			Definition: valid.Definition}, dnszone.ErrInvalid},
		"an update that moves": {dnszone.NameOperation{Operation: dnszone.OperationUpdate, NameID: name,
			ExpectedVersion: 1, Definition: valid.Definition}, dnszone.ErrInvalid},
		"an update without a version": {dnszone.NameOperation{Operation: dnszone.OperationUpdate, NameID: name,
			Definition: dnszone.NameDefinition{Kind: dnszone.NameAddress, Target: address}}, dnszone.ErrInvalid},
		"a delete with a target": {dnszone.NameOperation{Operation: dnszone.OperationDelete, NameID: name,
			ExpectedVersion: 1, Definition: dnszone.NameDefinition{Kind: dnszone.NameAddress}}, dnszone.ErrInvalid},
	} {
		_, err := f.service.ApplyNames(ctx, f.session, f.scope, zone, []dnszone.NameOperation{valid, test.operation},
			newID(t))
		var failure *dnszone.OperationError
		if !errors.As(err, &failure) || failure.Index != 1 || !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v at operation 1", label, err, test.want)
		}
	}
	twice := dnszone.NameOperation{Operation: dnszone.OperationDelete, NameID: name, ExpectedVersion: 1}
	if _, err := f.service.ApplyNames(ctx, f.session, f.scope, zone, []dnszone.NameOperation{twice, twice},
		newID(t)); !errors.Is(err, dnszone.ErrInvalid) {
		t.Errorf("one name twice: %v", err)
	}
	if _, err := f.service.CreateName(ctx, f.session, f.scope, zone, dnszone.NameDefinition{Label: "@",
		Kind: dnszone.NameCNAME, Target: dnszone.NameTarget{CNAME: "corp.atlassian.net"}}, newID(t)); !errors.Is(err,
		dnszone.ErrCNAMEAtApex) {
		t.Errorf("one create: %v", err)
	}
	if failure := (*dnszone.OperationError)(nil); errors.As(func() error {
		_, err := f.service.DeleteName(ctx, f.session, f.scope, zone, dnszone.NameID{}, 1, newID(t))
		return err
	}(), &failure) {
		t.Error("one operation names its position")
	}
	many := make([]dnszone.NameOperation, dnszone.MaximumNameOperations+1)
	if _, err := f.service.ApplyNames(ctx, f.session, f.scope, zone, many, newID(t)); !errors.Is(err,
		dnszone.ErrInvalid) {
		t.Errorf("101 operations: %v", err)
	}
	f.store.stored.Domain = dnszone.Root
	if _, err := f.service.ApplyNames(ctx, f.session, f.scope, zone, []dnszone.NameOperation{valid},
		newID(t)); !errors.Is(err, dnszone.ErrInvalid) {
		t.Errorf("a name in the root zone: %v", err)
	}
	disabled := newFixture(t, dnszone.Options{})
	if _, err := disabled.service.ApplyNames(ctx, disabled.session, disabled.scope, zone,
		[]dnszone.NameOperation{valid}, newID(t)); !errors.Is(err, dnszone.ErrDisabled) {
		t.Errorf("zones off: %v", err)
	}
	if _, err := f.service.ListNames(ctx, f.session, f.scope, zone, dnszone.NameID{}, "wiki%", 10); !errors.Is(err,
		dnszone.ErrInvalid) {
		t.Errorf("a prefix with a wildcard: %v", err)
	}
	if _, err := f.service.ListNames(ctx, f.session, f.scope, zone, dnszone.NameID{}, "Wiki", 10); err != nil {
		t.Errorf("a prefix in capitals: %v", err)
	}
}
