package sharing

import (
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
)

// DenialReason is a stable fail-closed sharing decision classification.
type DenialReason uint8

const (
	// DenialReasonUnknown is the unusable zero value.
	DenialReasonUnknown DenialReason = iota
	// DenialReasonAllowed means every authority input produced a non-empty intersection.
	DenialReasonAllowed
	// DenialReasonInvalidInput means the evaluator received malformed authority evidence.
	DenialReasonInvalidInput
	// DenialReasonContractInactive means the Trust Contract is not active at evaluation time.
	DenialReasonContractInactive
	// DenialReasonContractStale means current generations or Resource authority no longer match.
	DenialReasonContractStale
	// DenialReasonResourceInactive means the provider Resource cannot currently receive traffic.
	DenialReasonResourceInactive
	// DenialReasonImportInactive means the consumer-local Imported Resource is unavailable.
	DenialReasonImportInactive
	// DenialReasonEndpointInactive means no current generation-bound enforcement path exists.
	DenialReasonEndpointInactive
	// DenialReasonNoIntersection means one authority narrowed the traffic set to empty.
	DenialReasonNoIntersection
)

// EffectiveAccessParams contains every independent sharing authority input.
type EffectiveAccessParams struct {
	Contract                    Contract
	EvaluatedAt                 time.Time
	RecoveryEpoch               int64
	ProviderAuthorityGeneration int64
	ConsumerAuthorityGeneration int64
	ResourceVersion             int64
	TargetGeneration            int64
	ResourceSemanticHash        resource.SemanticHash
	IsResourceActive            bool
	IsImportedResourceActive    bool
	ImportedResourceVersion     int64
	Endpoint                    PrivateEndpoint
	ConsumerRule                TrafficSet
	ProviderGuardrail           TrafficSet
	ConsumerGuardrail           TrafficSet
	ResourceConstraints         TrafficSet
}

// EffectiveAccess is the exact traffic intersection or a stable denial class.
type EffectiveAccess struct {
	reason  DenialReason
	traffic TrafficSet
}

// IsAllowed reports whether every authority admitted at least one traffic tuple.
func (decision EffectiveAccess) IsAllowed() bool { return decision.reason == DenialReasonAllowed }

// Reason returns the stable fail-closed decision classification.
func (decision EffectiveAccess) Reason() DenialReason { return decision.reason }

// Traffic returns the caller-owned effective traffic set, or an invalid zero set on denial.
func (decision EffectiveAccess) Traffic() TrafficSet {
	if !decision.IsAllowed() {
		return TrafficSet{}
	}
	set, _ := NewTrafficSet(decision.traffic.Constraints())
	return set
}

// EvaluateEffectiveAccess intersects provider, consumer, Guardrail, Resource,
// endpoint, lifecycle, generation, and recovery-epoch authority.
func EvaluateEffectiveAccess(params EffectiveAccessParams) EffectiveAccess {
	if !params.Contract.IsValid() || params.EvaluatedAt.IsZero() ||
		params.RecoveryEpoch <= 0 || params.ProviderAuthorityGeneration <= 0 ||
		params.ConsumerAuthorityGeneration <= 0 || params.ResourceVersion <= 0 ||
		params.TargetGeneration <= 0 || params.ImportedResourceVersion <= 0 ||
		!params.ResourceSemanticHash.IsValid() || !params.Endpoint.IsValid() ||
		!params.ConsumerRule.IsValid() || !params.ProviderGuardrail.IsValid() ||
		!params.ConsumerGuardrail.IsValid() || !params.ResourceConstraints.IsValid() {
		return EffectiveAccess{reason: DenialReasonInvalidInput}
	}
	if params.Contract.State() != ContractStateActive ||
		!params.EvaluatedAt.Before(params.Contract.ExpiresAt()) {
		return EffectiveAccess{reason: DenialReasonContractInactive}
	}
	if !params.Contract.IsUsableAt(
		params.EvaluatedAt,
		params.RecoveryEpoch,
		params.ProviderAuthorityGeneration,
		params.ConsumerAuthorityGeneration,
		params.ResourceVersion,
		params.TargetGeneration,
		params.ResourceSemanticHash,
	) {
		return EffectiveAccess{reason: DenialReasonContractStale}
	}
	if !params.IsResourceActive {
		return EffectiveAccess{reason: DenialReasonResourceInactive}
	}
	if !params.IsImportedResourceActive {
		return EffectiveAccess{reason: DenialReasonImportInactive}
	}
	if !params.Endpoint.IsUsableAt(
		params.Contract,
		params.ImportedResourceVersion,
		params.EvaluatedAt,
	) {
		return EffectiveAccess{reason: DenialReasonEndpointInactive}
	}

	effective := params.Contract.MaximumTraffic()
	for _, narrowing := range []TrafficSet{
		params.ConsumerRule,
		params.ProviderGuardrail,
		params.ConsumerGuardrail,
		params.ResourceConstraints,
		params.Endpoint.Grant(),
	} {
		var ok bool
		effective, ok = IntersectTraffic(effective, narrowing)
		if !ok {
			return EffectiveAccess{reason: DenialReasonNoIntersection}
		}
	}
	return EffectiveAccess{reason: DenialReasonAllowed, traffic: effective}
}
