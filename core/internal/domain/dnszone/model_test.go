package dnszone

import (
	"errors"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

func mustDevice(t *testing.T) node.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return node.ID(id)
}

func TestResolverValidate(t *testing.T) {
	t.Parallel()
	device := mustDevice(t)
	for name, test := range map[string]struct {
		resolver Resolver
		want     error
	}{
		"device on 53":       {Resolver{DeviceID: device, Port: 53}, nil},
		"device on 5335":     {Resolver{DeviceID: device, Port: 5335}, nil},
		"device on 80":       {Resolver{DeviceID: device, Port: 80}, ErrInvalid},
		"device and address": {Resolver{DeviceID: device, Address: netip.MustParseAddr("1.1.1.1"), Port: 53}, ErrInvalid},
		"internet IPv4":      {Resolver{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}, nil},
		"internet IPv6":      {Resolver{Address: netip.MustParseAddr("2606:4700:4700::1111"), Port: 53}, nil},
		"internet on 5353":   {Resolver{Address: netip.MustParseAddr("1.1.1.1"), Port: 5353}, ErrInvalid},
		"private":            {Resolver{Address: netip.MustParseAddr("10.0.0.2"), Port: 53}, ErrResolverNotInternet},
		"carrier-grade NAT":  {Resolver{Address: netip.MustParseAddr("100.64.0.1"), Port: 53}, ErrResolverNotInternet},
		"unique local":       {Resolver{Address: netip.MustParseAddr("fd00::1"), Port: 53}, ErrResolverNotInternet},
		"documentation":      {Resolver{Address: netip.MustParseAddr("192.0.2.1"), Port: 53}, ErrResolverNotInternet},
		"benchmark":          {Resolver{Address: netip.MustParseAddr("198.18.0.1"), Port: 53}, ErrResolverNotInternet},
		"reserved":           {Resolver{Address: netip.MustParseAddr("240.0.0.1"), Port: 53}, ErrResolverNotInternet},
		"zone":               {Resolver{Address: netip.MustParseAddr("fe80::1%eth0"), Port: 53}, ErrInvalid},
		"neither":            {Resolver{Port: 53}, ErrInvalid},
	} {
		if err := test.resolver.Validate(); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", name, err, test.want)
		}
	}
}

func TestDefinitionValidate(t *testing.T) {
	t.Parallel()
	limits := DefaultLimits()
	device := mustDevice(t)
	group := devicegroup.ID(mustDevice(t))
	one := 1
	valid := Definition{
		Domain: "corp.internal", FailureMode: FailOpen,
		Resolvers: []Resolver{{DeviceID: device, Port: 53}, {Address: netip.MustParseAddr("1.1.1.1"), Port: 53}},
		Groups:    []devicegroup.ID{group}, SearchPosition: &one,
	}
	if err := valid.Validate(limits); err != nil {
		t.Fatal(err)
	}
	zero, tooFar := 0, MaximumSearchPosition+1
	for name, change := range map[string]func(*Definition){
		"no failure mode": func(definition *Definition) { definition.FailureMode = "" },
		"no resolver":     func(definition *Definition) { definition.Resolvers = nil },
		"five resolvers": func(definition *Definition) {
			definition.Resolvers = append(definition.Resolvers, definition.Resolvers...)
			definition.Resolvers = append(definition.Resolvers, Resolver{DeviceID: mustDevice(t), Port: 53})
		},
		"resolver twice": func(definition *Definition) {
			definition.Resolvers = []Resolver{{DeviceID: device, Port: 53}, {DeviceID: device, Port: 5335}}
		},
		"group twice":       func(definition *Definition) { definition.Groups = []devicegroup.ID{group, group} },
		"invalid group":     func(definition *Definition) { definition.Groups = []devicegroup.ID{{}} },
		"search position 0": func(definition *Definition) { definition.SearchPosition = &zero },
		"search too far":    func(definition *Definition) { definition.SearchPosition = &tooFar },
	} {
		definition := valid.Canonical()
		change(&definition)
		if err := definition.Validate(limits); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	groups := make([]devicegroup.ID, MaximumGroupsPerZone+1)
	for index := range groups {
		groups[index] = devicegroup.ID(mustDevice(t))
	}
	tooMany := valid.Canonical()
	tooMany.Groups = groups
	if tooMany.Validate(limits) == nil {
		t.Error("17 groups accepted")
	}
	noSearch := limits
	noSearch.SearchZonesPerNetwork = 0
	if valid.Validate(noSearch) == nil {
		t.Error("a search domain accepted where the plan allows none")
	}
}

func TestCanonicalSortsGroupsKeepsResolverOrder(t *testing.T) {
	t.Parallel()
	first, second := devicegroup.ID(mustDevice(t)), devicegroup.ID(mustDevice(t))
	if first.String() > second.String() {
		first, second = second, first
	}
	resolvers := []Resolver{
		{Address: netip.MustParseAddr("9.9.9.9"), Port: 53}, {Address: netip.MustParseAddr("1.1.1.1"), Port: 53},
	}
	position := 3
	definition := Definition{Resolvers: resolvers, Groups: []devicegroup.ID{second, first}, SearchPosition: &position}
	canonical := definition.Canonical()
	position = 4
	if canonical.Groups[0] != first || canonical.Resolvers[0] != resolvers[0] || *canonical.SearchPosition != 3 {
		t.Fatalf("Canonical() = %+v", canonical)
	}
}

func TestLimitsAndEligibility(t *testing.T) {
	t.Parallel()
	if DefaultLimits().Validate() != nil || (Limits{}).Validate() == nil {
		t.Fatal("limits")
	}
	if !(ResolverDevice{State: "active", Ownership: "workspace"}).Eligible() ||
		(ResolverDevice{State: "active", Ownership: "user"}).Eligible() ||
		(ResolverDevice{State: "active", Ownership: "workspace", ExitNode: true}).Eligible() ||
		(ResolverDevice{State: "suspended", Ownership: "workspace"}).Eligible() {
		t.Fatal("Eligible")
	}
}
