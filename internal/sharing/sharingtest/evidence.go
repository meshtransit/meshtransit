// Package sharingtest contains synthetic bilateral authority for contract tests.
package sharingtest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// Params selects the synthetic Device pair and protocol under test.
type Params struct {
	ProviderScope    network.Scope
	ConsumerScope    network.Scope
	ProviderDeviceID node.ID
	ConsumerDeviceID node.ID
	ProviderAddress  netip.Addr
	EvaluatedAt      time.Time
	RecoveryEpoch    int64
	Protocol         policy.Protocol
	Ports            []policy.PortRange
}

// Evidence contains independent Resource, published rule and endpoint evidence.
type Evidence struct {
	Target    catalog.Resource
	Export    sharing.Export
	Rule      publication.ImportedResourceDestination
	Authority sharing.EffectiveAccessParams
}

// New constructs valid fixed identities without runtime infrastructure.
func New(t testing.TB, params Params) Evidence {
	t.Helper()
	principal, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	check(t, err)
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000401")
	check(t, err)
	name, err := resource.ParseDisplayName("Shared test Device")
	check(t, err)
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: params.ProviderScope, DisplayName: name,
		OwnerPrincipalID: principal, CustodianPrincipalID: principal,
		DeviceID: params.ProviderDeviceID, TargetGeneration: 1,
	})
	check(t, err)
	target, err := catalog.NewResource(catalog.ResourceParams{
		ID: resourceID, Scope: params.ProviderScope, DisplayName: name,
		OwnerPrincipalID: principal, CustodianPrincipalID: principal,
		DeviceID: params.ProviderDeviceID, State: resource.StateActive,
		Provenance: resource.ProvenanceManual, Version: 1, TargetGeneration: 1,
		SemanticHash: revision.SemanticHash(), ActivatedNetworkRevision: 3,
		InventoryRevision: 3, CreatedAt: params.EvaluatedAt.Add(-time.Hour),
		UpdatedAt: params.EvaluatedAt.Add(-time.Hour),
	})
	check(t, err)
	binding, err := sharing.NewResourceBinding(params.ProviderScope, resourceID, 1, 1, target.SemanticHash())
	check(t, err)
	constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: params.Protocol, DestinationPortRanges: params.Ports,
	})
	check(t, err)
	traffic, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	check(t, err)
	contractID, err := sharing.ParseContractID("01890f00-0000-7000-8000-000000000501")
	check(t, err)
	importID, err := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000502")
	check(t, err)
	offerID, err := sharing.ParseOfferID("01890f00-0000-7000-8000-000000000503")
	check(t, err)
	exportID, err := sharing.ParseExportID("01890f00-0000-7000-8000-000000000504")
	check(t, err)
	export, err := sharing.NewExport(sharing.ExportParams{
		ID: exportID, ProviderScope: params.ProviderScope, ConsumerScope: params.ConsumerScope,
		Resource: binding, MaximumTraffic: traffic, ProviderAuthorityGeneration: 1,
		ExpiresAt: params.EvaluatedAt.Add(time.Hour), State: sharing.ExportStateActive, Version: 1,
	})
	check(t, err)
	contract, err := sharing.NewContract(sharing.ContractParams{
		ID: contractID, ImportedResourceID: importID, OfferID: offerID, ExportID: exportID,
		ProviderScope: params.ProviderScope, ConsumerScope: params.ConsumerScope,
		Resource: binding, MaximumTraffic: traffic, ProviderAuthorityGeneration: 1,
		ConsumerAuthorityGeneration: 1, RecoveryEpoch: params.RecoveryEpoch,
		ExpiresAt: params.EvaluatedAt.Add(30 * time.Minute), State: sharing.ContractStateActive, Version: 1,
	})
	check(t, err)
	endpointID, err := sharing.ParsePrivateEndpointID("01890f00-0000-7000-8000-000000000505")
	check(t, err)
	accessName, err := sharing.ParseAccessName("device.shared.example.com")
	check(t, err)
	endpoint, err := sharing.NewPrivateEndpoint(sharing.PrivateEndpointParams{
		ID: endpointID, Contract: contract, AccessName: accessName, Mode: sharing.EndpointModeDirect,
		ResourceAlias: params.ProviderAddress, Generation: 1, ImportedResourceVersion: 1,
		Grant: traffic, ExpiresAt: contract.ExpiresAt(), State: sharing.EndpointStateReady,
	})
	check(t, err)
	resolution, err := sharing.NewPolicyDestination(sharing.PolicyDestinationParams{
		ImportedResourceID: importID, ImportedResourceVersion: 1, Contract: contract, ExportVersion: 1,
		ProviderInventoryRevision: 3, ProviderSharingRevision: 4, ConsumerSharingRevision: 4,
		EvaluatedAt: params.EvaluatedAt,
	})
	check(t, err)
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	check(t, err)
	rule, err := publication.NewImportedResourceDestination(publication.ImportedResourceDestinationParams{
		RuleID: ruleID, SourceNodeID: params.ConsumerDeviceID, Resolution: resolution,
		Protocol: params.Protocol, DestinationPortRanges: params.Ports,
	})
	check(t, err)
	return Evidence{Target: target, Export: export, Rule: rule, Authority: sharing.EffectiveAccessParams{
		Contract: contract, EvaluatedAt: params.EvaluatedAt, RecoveryEpoch: params.RecoveryEpoch,
		ProviderAuthorityGeneration: 1, ConsumerAuthorityGeneration: 1, ResourceVersion: 1,
		TargetGeneration: 1, ResourceSemanticHash: target.SemanticHash(), IsResourceActive: true,
		IsImportedResourceActive: true, ImportedResourceVersion: 1, Endpoint: endpoint,
		ConsumerRule: traffic, ProviderGuardrail: traffic, ConsumerGuardrail: traffic, ResourceConstraints: traffic,
	}}
}

func check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
