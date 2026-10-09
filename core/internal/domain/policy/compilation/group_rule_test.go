package compilation_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
)

func TestRuleIntentGroupSelectors(t *testing.T) {
	t.Parallel()
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	group, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	resourceID, _ := resource.ParseID("01890f00-0000-7000-8000-000000000b01")
	importedID, _ := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000c01")
	device := compilationNodeID(t, "000000000701")
	people, _ := identitygroup.ParseID("01890f00-0000-7000-8000-000000000d01")
	tag, _ := devicetag.ParseID("01890f00-0000-7000-8000-000000000e01")
	ssh, _ := policy.NewPortRange(22, 22)
	base := compilation.RuleIntentParams{
		ID: ruleID, Scope: compilationScopeFixture(t), Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{ssh},
	}
	with := func(change func(*compilation.RuleIntentParams)) compilation.RuleIntentParams {
		params := base
		change(&params)
		return params
	}
	valid := map[string]compilation.RuleIntentParams{
		"group to group":  with(func(p *compilation.RuleIntentParams) { p.SourceGroupID, p.DestinationDeviceGroupID = group, group }),
		"group to Device": with(func(p *compilation.RuleIntentParams) { p.SourceGroupID, p.DestinationNodeID = group, device }),
		"Device to group": with(func(p *compilation.RuleIntentParams) { p.SourceNodeID, p.DestinationDeviceGroupID = device, group }),
		"identity group to tag": with(func(p *compilation.RuleIntentParams) {
			p.SourceIdentityGroupID, p.DestinationTagID = people, tag
		}),
		"tag to Device": with(func(p *compilation.RuleIntentParams) { p.SourceTagID, p.DestinationNodeID = tag, device }),
		"Device to tag": with(func(p *compilation.RuleIntentParams) { p.SourceNodeID, p.DestinationTagID = device, tag }),
	}
	for name, params := range valid {
		intent, err := compilation.NewRuleIntent(params)
		if err != nil || !intent.SelectsDeviceGroup() {
			t.Errorf("%s: NewRuleIntent() = %v, %v", name, intent, err)
		}
	}
	invalid := map[string]compilation.RuleIntentParams{
		"two sources": with(func(p *compilation.RuleIntentParams) {
			p.SourceNodeID, p.SourceGroupID, p.DestinationNodeID = device, group, device
		}),
		"group to Resource": with(func(p *compilation.RuleIntentParams) { p.SourceGroupID, p.DestinationResourceID = group, resourceID }),
		"group to shared Device": with(func(p *compilation.RuleIntentParams) {
			p.SourceGroupID, p.DestinationImportedResourceID = group, importedID
		}),
		"group and Device destination": with(func(p *compilation.RuleIntentParams) {
			p.SourceGroupID, p.DestinationNodeID, p.DestinationDeviceGroupID = group, device, group
		}),
		"no source": with(func(p *compilation.RuleIntentParams) { p.DestinationDeviceGroupID = group }),
		"identity group to Resource": with(func(p *compilation.RuleIntentParams) {
			p.SourceIdentityGroupID, p.DestinationResourceID = people, resourceID
		}),
		"tag to shared Device": with(func(p *compilation.RuleIntentParams) {
			p.SourceTagID, p.DestinationImportedResourceID = tag, importedID
		}),
		"identity group and tag sources": with(func(p *compilation.RuleIntentParams) {
			p.SourceIdentityGroupID, p.SourceTagID, p.DestinationTagID = people, tag, tag
		}),
		"tag and group destinations": with(func(p *compilation.RuleIntentParams) {
			p.SourceTagID, p.DestinationTagID, p.DestinationDeviceGroupID = tag, tag, group
		}),
	}
	for name, params := range invalid {
		if _, err := compilation.NewRuleIntent(params); !errors.Is(err, compilation.ErrInvalidRequest) {
			t.Errorf("%s: error = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestServiceCompilesGroupRulesWithoutResolvingMembers(t *testing.T) {
	t.Parallel()
	resolver := &compilationResourceResolverFixture{err: errors.New("unexpected Resource resolution")}
	service, err := compilation.NewService(resolver)
	if err != nil {
		t.Fatal(err)
	}
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	group, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: compilationScopeFixture(t), SourceGroupID: group,
		DestinationNodeID: compilationNodeID(t, "000000000702"), Protocol: policy.ProtocolICMP,
		DestinationPortRanges: []policy.PortRange{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: compilationScopeFixture(t), Revision: 2, Rules: []compilation.RuleIntent{intent},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := service.Compile(t.Context(), compilationSessionFixture(t), request)
	if err != nil || resolver.calls != 0 || len(candidate.Snapshot().Rules()) != 0 ||
		len(candidate.GroupRules()) != 1 || candidate.GroupRules()[0].SourceGroupID() != group {
		t.Fatalf("Compile() = %+v, %v (resolver calls %d)", candidate, err, resolver.calls)
	}
}
