package dnszone_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/sharing"
)

func TestServiceNameIsCheckedAsAZoneDomain(t *testing.T) {
	t.Parallel()
	f := newFixture(t, dnszone.Options{Enabled: true, Names: dnszone.Names{Protected: []string{"control.example.net"}}})
	for input, want := range map[string]struct {
		name   string
		public bool
	}{
		"App.Corp.com.":   {"app.corp.com", true},
		"wiki.corp.lan":   {"wiki.corp.lan", false},
		"bücher.corp.lan": {"xn--bcher-kva.corp.lan", false},
	} {
		name, public, err := f.service.ServiceName(input)
		if err != nil || name != want.name || public != want.public {
			t.Errorf("%q = %q, %v, %v", input, name, public, err)
		}
	}
	for input, want := range map[string]error{
		"lan":             dnszone.ErrInvalid,
		"co.uk":           dnszone.ErrDomainPublicSuffix,
		"app.local":       dnszone.ErrDomainSpecialUse,
		"x.mesh.internal": dnszone.ErrDomainMeshSuffix,
		"example.net":     dnszone.ErrDomainCoversControl,
		"":                dnszone.ErrInvalid,
		"a b.corp.com":    dnszone.ErrInvalid,
	} {
		if _, _, err := f.service.ServiceName(input); !errors.Is(err, want) {
			t.Errorf("%q: %v, want %v", input, err, want)
		}
	}
}

func TestServiceNamePlans(t *testing.T) {
	t.Parallel()
	f := newFixture(t, dnszone.Options{Enabled: true})
	correlation := newID(t)
	zone, err := f.service.PlanServiceNameZone(f.session, f.scope, "app.corp.com", correlation)
	if err != nil || zone.Operation != dnszone.OperationCreate || zone.Domain != "app.corp.com" ||
		zone.Class != dnszone.ClassPublic || zone.Definition.OtherNames != dnszone.OtherHost ||
		!zone.Definition.PublicConfirmed || len(zone.Definition.Resolvers) != 0 || !zone.ZoneID.IsValid() ||
		zone.CorrelationID != correlation || zone.WithNames {
		t.Fatalf("the zone of a service name = %+v, %v", zone, err)
	}
	private, err := f.service.PlanServiceNameZone(f.session, f.scope, "wiki.corp.lan", correlation)
	if err != nil || private.Class != dnszone.ClassPrivate || private.Definition.PublicConfirmed {
		t.Fatalf("the zone of a private service name = %+v, %v", private, err)
	}
	if _, err := f.service.PlanServiceNameZone(f.session, f.scope, "App.corp.com", correlation); err == nil {
		t.Error("a zone for a name that is not canonical")
	}
	disabled := newFixture(t, dnszone.Options{})
	if _, err := disabled.service.PlanServiceNameZone(disabled.session, disabled.scope, "app.corp.com",
		correlation); !errors.Is(err, dnszone.ErrDisabled) {
		t.Errorf("zones disabled: %v", err)
	}
	if _, _, err := disabled.service.ServiceName("app.corp.com"); !errors.Is(err, dnszone.ErrDisabled) {
		t.Errorf("a service name checked with zones disabled: %v", err)
	}
	if _, err := disabled.service.PlanServiceName("corp.internal", "app.corp.internal",
		sharing.ImportedResourceID(newID(t))); !errors.Is(err, dnszone.ErrDisabled) {
		t.Errorf("a service name planned with zones disabled: %v", err)
	}

	share := sharing.ImportedResourceID(newID(t))
	apex, err := f.service.PlanServiceName("app.corp.com", "app.corp.com", share)
	if err != nil || apex.Definition.Label != dnszone.Apex || apex.Definition.Target.ShareID != share ||
		apex.Definition.Kind != dnszone.NameAddress || !apex.NameID.IsValid() {
		t.Fatalf("a service name at its zone's domain = %+v, %v", apex, err)
	}
	inside, err := f.service.PlanServiceName("corp.internal", "sso.dev.corp.internal", share)
	if err != nil || inside.Definition.Label != "sso.dev" {
		t.Fatalf("a service name inside a zone = %+v, %v", inside, err)
	}
	if _, err := f.service.PlanServiceName("corp.internal", "app.corp.com", share); err == nil {
		t.Error("a name outside the zone")
	}
	if _, err := f.service.PlanServiceName("corp.internal", "app.corp.internal", sharing.ImportedResourceID{}); err == nil {
		t.Error("a name without a share")
	}
}
