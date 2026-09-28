package resource

import (
	"strconv"
	"testing"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestDeviceDefinitionOwnsStableSemantics(t *testing.T) {
	scope := resourceScopeFixture(t, 101, 201)
	owner := principalIDFixture(t, 11)
	deviceID := nodeIDFixture(t, 301)
	name, err := ParseDisplayName("Edge relay 01")
	if err != nil {
		t.Fatalf("ParseDisplayName() error = %v", err)
	}
	definition, err := NewDeviceDefinition(DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: owner,
		CustodianPrincipalID: owner, DeviceID: deviceID,
	})
	if err != nil {
		t.Fatalf("NewDeviceDefinition() error = %v", err)
	}
	if definition.Kind() != KindDevice || definition.State() != StateActive ||
		definition.TargetGeneration() != 1 || definition.NameKey() != "edge relay 01" ||
		!definition.SemanticHash().IsValid() {
		t.Fatalf("device definition = %+v", definition)
	}
	copyValue, err := NewDeviceDefinition(DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: owner,
		CustodianPrincipalID: owner, DeviceID: deviceID,
	})
	if err != nil || copyValue.SemanticHash() != definition.SemanticHash() {
		t.Fatalf("same definition hash = %x, error = %v", copyValue.SemanticHash(), err)
	}
}

func TestGroupDefinitionCanonicalizesMembership(t *testing.T) {
	scope := resourceScopeFixture(t, 101, 201)
	owner := principalIDFixture(t, 11)
	name, err := ParseDisplayName("Production databases")
	if err != nil {
		t.Fatalf("ParseDisplayName() error = %v", err)
	}
	first := referenceFixture(t, scope, 402)
	second := referenceFixture(t, scope, 401)
	definition, err := NewGroupDefinition(GroupDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: owner,
		CustodianPrincipalID: owner, Members: []Reference{first, second},
	})
	if err != nil {
		t.Fatalf("NewGroupDefinition() error = %v", err)
	}
	members := definition.Members()
	if len(members) != 2 || members[0].ResourceID().String() >= members[1].ResourceID().String() ||
		definition.DefinitionVersion() != 1 || !definition.SemanticHash().IsValid() {
		t.Fatalf("group definition = %+v members = %+v", definition, members)
	}
	members[0] = Reference{}
	if !definition.Members()[0].IsValid() {
		t.Fatal("Members() exposed mutable backing storage")
	}
}

func TestGroupDefinitionRejectsUnsafeMembership(t *testing.T) {
	scope := resourceScopeFixture(t, 101, 201)
	otherScope := resourceScopeFixture(t, 102, 202)
	owner := principalIDFixture(t, 11)
	reference := referenceFixture(t, scope, 401)
	for name, members := range map[string][]Reference{
		"empty":       {},
		"duplicate":   {reference, reference},
		"cross scope": {referenceFixture(t, otherScope, 402)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewGroupDefinition(GroupDefinitionParams{
				Scope: scope, DisplayName: nameFixture(t, name), OwnerPrincipalID: owner,
				CustodianPrincipalID: owner, Members: members,
			}); err == nil {
				t.Fatal("NewGroupDefinition() error = nil")
			}
		})
	}
}

func referenceFixture(t *testing.T, scope network.Scope, suffix int) Reference {
	t.Helper()
	id, err := ParseID(integrationID(suffix))
	if err != nil {
		t.Fatalf("ParseID() error = %v", err)
	}
	reference, err := NewReference(scope, id, 1, 1)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func nameFixture(t *testing.T, value string) DisplayName {
	t.Helper()
	name, err := ParseDisplayName(value)
	if err != nil {
		t.Fatalf("ParseDisplayName() error = %v", err)
	}
	return name
}

func resourceScopeFixture(t *testing.T, workspaceSuffix, networkSuffix int) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID(integrationID(workspaceSuffix))
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID(integrationID(networkSuffix))
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func principalIDFixture(t *testing.T, suffix int) identity.PrincipalID {
	t.Helper()
	id, err := identity.ParsePrincipalID(integrationID(suffix))
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	return id
}

func nodeIDFixture(t *testing.T, suffix int) node.ID {
	t.Helper()
	id, err := node.ParseID(integrationID(suffix))
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	return id
}

func integrationID(suffix int) string {
	return "01890f00-0000-7000-8000-000000000" + fmtSuffix(suffix)
}

func fmtSuffix(value int) string {
	valueText := strconv.Itoa(value)
	for len(valueText) < 3 {
		valueText = "0" + valueText
	}
	return valueText
}
