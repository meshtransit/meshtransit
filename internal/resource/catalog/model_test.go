package catalog

import (
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/resource"
)

func TestResourceAcceptsCurrentReboundDeviceRevision(t *testing.T) {
	t.Parallel()

	scope := catalogScopeFixture(t)
	principalID := catalogSessionFixture(t).PrincipalID()
	id, err := resource.ParseID("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatal(err)
	}
	displayName, err := resource.ParseDisplayName("Rebound database")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: scope, DisplayName: displayName,
		OwnerPrincipalID: principalID, CustodianPrincipalID: principalID,
		DeviceID: deviceID, TargetGeneration: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 29, 1, 0, 0, 0, time.UTC)
	value, err := NewResource(ResourceParams{
		ID: id, Scope: scope, DisplayName: displayName,
		OwnerPrincipalID: principalID, CustodianPrincipalID: principalID,
		DeviceID: deviceID, State: resource.StateActive, Provenance: resource.ProvenanceManual,
		Version: 2, TargetGeneration: 2, SemanticHash: revision.SemanticHash(),
		ActivatedNetworkRevision: 8, InventoryRevision: 7,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	})
	if err != nil || !value.IsValid() || value.TargetGeneration() != 2 {
		t.Fatalf("NewResource() = %+v, %v", value, err)
	}
}
