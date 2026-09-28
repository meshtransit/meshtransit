package resource

import "testing"

func TestDeviceRevisionBindsTargetGeneration(t *testing.T) {
	t.Parallel()
	scope := resourceScopeFixture(t, 101, 201)
	owner := principalIDFixture(t, 11)
	name := nameFixture(t, "Database 01")
	deviceID := nodeIDFixture(t, 302)
	revision, err := NewDeviceRevision(DeviceRevisionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: owner,
		CustodianPrincipalID: owner, DeviceID: deviceID, TargetGeneration: 2,
	})
	if err != nil {
		t.Fatalf("NewDeviceRevision() error = %v", err)
	}
	previous, err := NewDeviceRevision(DeviceRevisionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: owner,
		CustodianPrincipalID: owner, DeviceID: deviceID, TargetGeneration: 1,
	})
	if err != nil {
		t.Fatalf("NewDeviceRevision(previous) error = %v", err)
	}
	if !revision.IsValid() || revision.TargetGeneration() != 2 ||
		revision.SemanticHash() == previous.SemanticHash() {
		t.Fatalf("Device revision = %+v", revision)
	}
}

func TestDeviceRevisionMatchesInitialDefinitionHash(t *testing.T) {
	t.Parallel()
	scope := resourceScopeFixture(t, 101, 201)
	owner := principalIDFixture(t, 11)
	name := nameFixture(t, "Database 01")
	deviceID := nodeIDFixture(t, 301)
	definition, err := NewDeviceDefinition(DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: owner,
		CustodianPrincipalID: owner, DeviceID: deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := NewDeviceRevision(DeviceRevisionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: owner,
		CustodianPrincipalID: owner, DeviceID: deviceID, TargetGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if definition.SemanticHash() != revision.SemanticHash() {
		t.Fatal("initial definition and generation-one revision hashes differ")
	}
}
