package sharing

import (
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/resource"
)

func TestEvaluateEffectiveAccessReturnsExactSixWayIntersection(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	binding := contract.Resource()
	endpoint := mustPrivateEndpoint(t, contract)
	params := EffectiveAccessParams{
		Contract: contract, EvaluatedAt: contract.ExpiresAt().Add(-time.Minute),
		RecoveryEpoch:               contract.RecoveryEpoch(),
		ProviderAuthorityGeneration: contract.ProviderAuthorityGeneration(),
		ConsumerAuthorityGeneration: contract.ConsumerAuthorityGeneration(),
		ResourceVersion:             binding.ResourceVersion(), TargetGeneration: binding.TargetGeneration(),
		ResourceSemanticHash: binding.SemanticHash(), IsResourceActive: true,
		IsImportedResourceActive: true, ImportedResourceVersion: endpoint.ImportedResourceVersion(),
		Endpoint: endpoint,
		ConsumerRule: mustTrafficSet(t,
			mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 90, 110)),
		),
		ProviderGuardrail: mustTrafficSet(t,
			mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 95, 105)),
		),
		ConsumerGuardrail: mustTrafficSet(t,
			mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 96, 104)),
		),
		ResourceConstraints: mustTrafficSet(t,
			mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 97, 103)),
		),
	}
	params.Endpoint.grant = mustTrafficSet(t,
		mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 98, 102)),
	)

	decision := EvaluateEffectiveAccess(params)
	if !decision.IsAllowed() || decision.Reason() != DenialReasonAllowed ||
		!decision.Traffic().Allows(policy.ProtocolTCP, 98) ||
		!decision.Traffic().Allows(policy.ProtocolTCP, 100) ||
		decision.Traffic().Allows(policy.ProtocolTCP, 97) ||
		decision.Traffic().Allows(policy.ProtocolTCP, 103) {
		t.Fatalf("EvaluateEffectiveAccess() = %#v, want TCP 98-100", decision)
	}
}

func TestEvaluateEffectiveAccessFailsClosedForEveryIndependentAuthority(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	binding := contract.Resource()
	endpoint := mustPrivateEndpoint(t, contract)
	allowed := mustTrafficSet(t,
		mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 80, 100)),
	)
	base := EffectiveAccessParams{
		Contract: contract, EvaluatedAt: contract.ExpiresAt().Add(-time.Minute),
		RecoveryEpoch:               contract.RecoveryEpoch(),
		ProviderAuthorityGeneration: contract.ProviderAuthorityGeneration(),
		ConsumerAuthorityGeneration: contract.ConsumerAuthorityGeneration(),
		ResourceVersion:             binding.ResourceVersion(), TargetGeneration: binding.TargetGeneration(),
		ResourceSemanticHash: binding.SemanticHash(), IsResourceActive: true,
		IsImportedResourceActive: true, ImportedResourceVersion: endpoint.ImportedResourceVersion(),
		Endpoint:     endpoint,
		ConsumerRule: allowed, ProviderGuardrail: allowed, ConsumerGuardrail: allowed,
		ResourceConstraints: allowed,
	}

	tests := []struct {
		name   string
		reason DenialReason
		mutate func(*EffectiveAccessParams)
	}{
		{
			name: "expired contract", reason: DenialReasonContractInactive,
			mutate: func(params *EffectiveAccessParams) { params.EvaluatedAt = contract.ExpiresAt() },
		},
		{
			name: "stale provider generation", reason: DenialReasonContractStale,
			mutate: func(params *EffectiveAccessParams) { params.ProviderAuthorityGeneration++ },
		},
		{
			name: "stale consumer generation", reason: DenialReasonContractStale,
			mutate: func(params *EffectiveAccessParams) { params.ConsumerAuthorityGeneration++ },
		},
		{
			name: "stale recovery epoch", reason: DenialReasonContractStale,
			mutate: func(params *EffectiveAccessParams) { params.RecoveryEpoch++ },
		},
		{
			name: "stale Resource version", reason: DenialReasonContractStale,
			mutate: func(params *EffectiveAccessParams) { params.ResourceVersion++ },
		},
		{
			name: "stale target generation", reason: DenialReasonContractStale,
			mutate: func(params *EffectiveAccessParams) { params.TargetGeneration++ },
		},
		{
			name: "inactive Resource", reason: DenialReasonResourceInactive,
			mutate: func(params *EffectiveAccessParams) { params.IsResourceActive = false },
		},
		{
			name: "inactive import", reason: DenialReasonImportInactive,
			mutate: func(params *EffectiveAccessParams) { params.IsImportedResourceActive = false },
		},
		{
			name: "inactive endpoint", reason: DenialReasonEndpointInactive,
			mutate: func(params *EffectiveAccessParams) {
				params.Endpoint.state = EndpointStateProvisioning
			},
		},
		{
			name: "disjoint consumer rule", reason: DenialReasonNoIntersection,
			mutate: func(params *EffectiveAccessParams) {
				params.ConsumerRule = mustTrafficSet(t,
					mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 443, 443)),
				)
			},
		},
		{
			name: "disjoint provider Guardrail", reason: DenialReasonNoIntersection,
			mutate: func(params *EffectiveAccessParams) {
				params.ProviderGuardrail = mustTrafficSet(t,
					mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 443, 443)),
				)
			},
		},
		{
			name: "disjoint consumer Guardrail", reason: DenialReasonNoIntersection,
			mutate: func(params *EffectiveAccessParams) {
				params.ConsumerGuardrail = mustTrafficSet(t,
					mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 443, 443)),
				)
			},
		},
		{
			name: "disjoint Resource constraint", reason: DenialReasonNoIntersection,
			mutate: func(params *EffectiveAccessParams) {
				params.ResourceConstraints = mustTrafficSet(t,
					mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 443, 443)),
				)
			},
		},
		{
			name: "disjoint endpoint grant", reason: DenialReasonNoIntersection,
			mutate: func(params *EffectiveAccessParams) {
				params.Endpoint.grant = mustTrafficSet(t,
					mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 443, 443)),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := base
			test.mutate(&params)
			decision := EvaluateEffectiveAccess(params)
			if decision.IsAllowed() || decision.Reason() != test.reason || decision.Traffic().IsValid() {
				t.Fatalf("EvaluateEffectiveAccess() = %#v, want denial %v", decision, test.reason)
			}
		})
	}
}

func TestEvaluateEffectiveAccessRejectsMalformedCurrentAuthority(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	binding := contract.Resource()
	endpoint := mustPrivateEndpoint(t, contract)
	allowed := mustTrafficSet(t,
		mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 80, 100)),
	)
	base := EffectiveAccessParams{
		Contract: contract, EvaluatedAt: contract.ExpiresAt().Add(-time.Minute),
		RecoveryEpoch:               contract.RecoveryEpoch(),
		ProviderAuthorityGeneration: contract.ProviderAuthorityGeneration(),
		ConsumerAuthorityGeneration: contract.ConsumerAuthorityGeneration(),
		ResourceVersion:             binding.ResourceVersion(),
		TargetGeneration:            binding.TargetGeneration(),
		ResourceSemanticHash:        binding.SemanticHash(),
		IsResourceActive:            true,
		IsImportedResourceActive:    true,
		ImportedResourceVersion:     endpoint.ImportedResourceVersion(),
		Endpoint:                    endpoint,
		ConsumerRule:                allowed,
		ProviderGuardrail:           allowed,
		ConsumerGuardrail:           allowed,
		ResourceConstraints:         allowed,
	}

	mutations := []func(*EffectiveAccessParams){
		func(params *EffectiveAccessParams) { params.RecoveryEpoch = 0 },
		func(params *EffectiveAccessParams) { params.ProviderAuthorityGeneration = 0 },
		func(params *EffectiveAccessParams) { params.ConsumerAuthorityGeneration = 0 },
		func(params *EffectiveAccessParams) { params.ResourceVersion = 0 },
		func(params *EffectiveAccessParams) { params.TargetGeneration = 0 },
		func(params *EffectiveAccessParams) { params.ResourceSemanticHash = resource.SemanticHash{} },
		func(params *EffectiveAccessParams) { params.ImportedResourceVersion = 0 },
		func(params *EffectiveAccessParams) { params.Endpoint = PrivateEndpoint{} },
	}
	for index, mutate := range mutations {
		params := base
		mutate(&params)
		decision := EvaluateEffectiveAccess(params)
		if decision.IsAllowed() || decision.Reason() != DenialReasonInvalidInput {
			t.Fatalf("case %d: EvaluateEffectiveAccess() reason = %v, want invalid input", index, decision.Reason())
		}
	}
}
