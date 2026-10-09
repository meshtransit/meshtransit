package sharing

import (
	"crypto/sha256"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestExportRequiresDistinctExactScopesAndPinnedResource(t *testing.T) {
	t.Parallel()

	provider := mustScope(t, 1, 2)
	consumer := mustScope(t, 3, 4)
	binding := mustResourceBinding(t, provider)
	export := mustExport(t, provider, consumer, binding)
	if !export.IsUsableAt(export.ExpiresAt().Add(-time.Nanosecond)) ||
		export.IsUsableAt(export.ExpiresAt()) {
		t.Fatal("Export exclusive expiry was not enforced")
	}

	params := export.params
	params.ConsumerScope = provider
	if _, err := NewExport(params); err == nil {
		t.Fatal("NewExport() accepted an intra-Network pseudo-share")
	}
	params = export.params
	params.Resource = mustResourceBinding(t, consumer)
	if _, err := NewExport(params); err == nil {
		t.Fatal("NewExport() accepted a Resource from the consumer scope")
	}
}

func TestContractUsabilityBindsEveryGenerationAndResourceInput(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	evaluatedAt := contract.ExpiresAt().Add(-time.Minute)
	binding := contract.Resource()
	if !contract.IsUsableAt(
		evaluatedAt,
		contract.RecoveryEpoch(),
		contract.ProviderAuthorityGeneration(),
		contract.ConsumerAuthorityGeneration(),
		binding.ResourceVersion(),
		binding.TargetGeneration(),
		binding.SemanticHash(),
	) {
		t.Fatal("Contract denied exact current authority")
	}

	tests := []struct {
		name               string
		recoveryEpoch      int64
		providerGeneration int64
		consumerGeneration int64
		resourceVersion    int64
		targetGeneration   int64
		semanticHash       resource.SemanticHash
	}{
		{
			name: "stale recovery epoch", recoveryEpoch: contract.RecoveryEpoch() + 1,
			providerGeneration: contract.ProviderAuthorityGeneration(),
			consumerGeneration: contract.ConsumerAuthorityGeneration(),
			resourceVersion:    binding.ResourceVersion(), targetGeneration: binding.TargetGeneration(),
			semanticHash: binding.SemanticHash(),
		},
		{
			name: "stale provider authority", recoveryEpoch: contract.RecoveryEpoch(),
			providerGeneration: contract.ProviderAuthorityGeneration() + 1,
			consumerGeneration: contract.ConsumerAuthorityGeneration(),
			resourceVersion:    binding.ResourceVersion(), targetGeneration: binding.TargetGeneration(),
			semanticHash: binding.SemanticHash(),
		},
		{
			name: "stale consumer authority", recoveryEpoch: contract.RecoveryEpoch(),
			providerGeneration: contract.ProviderAuthorityGeneration(),
			consumerGeneration: contract.ConsumerAuthorityGeneration() + 1,
			resourceVersion:    binding.ResourceVersion(), targetGeneration: binding.TargetGeneration(),
			semanticHash: binding.SemanticHash(),
		},
		{
			name: "stale resource version", recoveryEpoch: contract.RecoveryEpoch(),
			providerGeneration: contract.ProviderAuthorityGeneration(),
			consumerGeneration: contract.ConsumerAuthorityGeneration(),
			resourceVersion:    binding.ResourceVersion() + 1, targetGeneration: binding.TargetGeneration(),
			semanticHash: binding.SemanticHash(),
		},
		{
			name: "stale target generation", recoveryEpoch: contract.RecoveryEpoch(),
			providerGeneration: contract.ProviderAuthorityGeneration(),
			consumerGeneration: contract.ConsumerAuthorityGeneration(),
			resourceVersion:    binding.ResourceVersion(), targetGeneration: binding.TargetGeneration() + 1,
			semanticHash: binding.SemanticHash(),
		},
		{
			name: "changed resource semantics", recoveryEpoch: contract.RecoveryEpoch(),
			providerGeneration: contract.ProviderAuthorityGeneration(),
			consumerGeneration: contract.ConsumerAuthorityGeneration(),
			resourceVersion:    binding.ResourceVersion(), targetGeneration: binding.TargetGeneration(),
			semanticHash: mustSemanticHash(t, "changed"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if contract.IsUsableAt(
				evaluatedAt,
				test.recoveryEpoch,
				test.providerGeneration,
				test.consumerGeneration,
				test.resourceVersion,
				test.targetGeneration,
				test.semanticHash,
			) {
				t.Fatal("Contract accepted stale authority")
			}
		})
	}
}

func mustScope(t *testing.T, workspaceSuffix, networkSuffix byte) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID(uuidWithSuffix(workspaceSuffix))
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID(uuidWithSuffix(networkSuffix))
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func mustResourceBinding(t *testing.T, scope network.Scope) ResourceBinding {
	t.Helper()
	resourceID, err := resource.ParseID(uuidWithSuffix(5))
	if err != nil {
		t.Fatalf("resource.ParseID() error = %v", err)
	}
	binding, err := NewResourceBinding(scope, resourceID, 7, 11, mustSemanticHash(t, "resource"))
	if err != nil {
		t.Fatalf("NewResourceBinding() error = %v", err)
	}
	return binding
}

func mustSemanticHash(t *testing.T, value string) resource.SemanticHash {
	t.Helper()
	digest := sha256.Sum256([]byte(value))
	semanticHash, err := resource.NewSemanticHash(digest)
	if err != nil {
		t.Fatalf("resource.NewSemanticHash() error = %v", err)
	}
	return semanticHash
}

func mustExport(
	t *testing.T,
	provider network.Scope,
	consumer network.Scope,
	binding ResourceBinding,
) Export {
	t.Helper()
	id, err := ParseExportID(uuidWithSuffix(6))
	if err != nil {
		t.Fatalf("ParseExportID() error = %v", err)
	}
	export, err := NewExport(ExportParams{
		ID: id, ProviderScope: provider, ConsumerScope: consumer, Resource: binding,
		MaximumTraffic: mustTrafficSet(t,
			mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 80, 100)),
		),
		ProviderAuthorityGeneration: 13,
		ExpiresAt:                   time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC),
		State:                       ExportStateActive,
		Version:                     1,
	})
	if err != nil {
		t.Fatalf("NewExport() error = %v", err)
	}
	return export
}

func mustOffer(t *testing.T) Offer {
	t.Helper()
	provider := mustScope(t, 1, 2)
	consumer := mustScope(t, 3, 4)
	export := mustExport(t, provider, consumer, mustResourceBinding(t, provider))
	id, err := ParseOfferID(uuidWithSuffix(7))
	if err != nil {
		t.Fatalf("ParseOfferID() error = %v", err)
	}
	offer, err := NewOffer(OfferParams{
		ID: id, ExportID: export.ID(), ProviderScope: provider, ConsumerScope: consumer,
		MaximumTraffic: export.MaximumTraffic(), NonceDigest: sha256.Sum256([]byte("nonce")),
		ExpiresAt: export.ExpiresAt().Add(-time.Hour), State: OfferStateOffered, Version: 1,
	})
	if err != nil {
		t.Fatalf("NewOffer() error = %v", err)
	}
	return offer
}

func mustContract(t *testing.T) Contract {
	t.Helper()
	offer := mustOffer(t)
	contractID, err := ParseContractID(uuidWithSuffix(8))
	if err != nil {
		t.Fatalf("ParseContractID() error = %v", err)
	}
	importID, err := ParseImportedResourceID(uuidWithSuffix(9))
	if err != nil {
		t.Fatalf("ParseImportedResourceID() error = %v", err)
	}
	contract, err := NewContract(ContractParams{
		ID: contractID, ImportedResourceID: importID, OfferID: offer.ID(),
		ExportID: offer.ExportID(), ProviderScope: offer.ProviderScope(),
		ConsumerScope: offer.ConsumerScope(), Resource: mustResourceBinding(t, offer.ProviderScope()),
		MaximumTraffic: offer.MaximumTraffic(), ProviderAuthorityGeneration: 13,
		ConsumerAuthorityGeneration: 17, RecoveryEpoch: 19,
		ExpiresAt: offer.ExpiresAt(), State: ContractStateActive, Version: 1,
	})
	if err != nil {
		t.Fatalf("NewContract() error = %v", err)
	}
	return contract
}

func uuidWithSuffix(suffix byte) string {
	hex := "0123456789abcdef"
	return "01890f00-0000-7000-8000-0000000000" + string([]byte{hex[suffix>>4], hex[suffix&0xf]})
}
