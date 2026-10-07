package guardrail

import (
	"slices"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// ShareEdge is one path a share opens: Devices in Consumer may reach a
// Device in Provider. Shares are the only way traffic crosses Networks.
type ShareEdge struct {
	Provider network.Scope
	Consumer network.Scope
}

// Finding is one guardrail an edge breaks.
type Finding struct {
	GuardrailID publicid.ID
	Version     int64
	Name        string
	Kind        Kind
	Mode        Mode
	// Reason is a stable code for why the edge breaks the guardrail.
	Reason string
}

// Reasons a finding names.
const (
	ReasonIsolatedNetworks = "isolated_networks"
	ReasonSharingLocked    = "network_sharing_locked"
	ReasonExternalSharing  = "external_sharing_blocked"
)

// Evaluate returns every guardrail of owner the edge breaks. Only the
// guardrails of the Workspace evaluating are passed in; each side of a
// cross-Workspace share applies its own.
func Evaluate(guardrails []Guardrail, owner workspace.ID, edge ShareEdge) []Finding {
	if !owner.IsValid() || !edge.Provider.IsValid() || !edge.Consumer.IsValid() {
		return nil
	}
	findings := []Finding{}
	for _, guardrail := range guardrails {
		if reason := breaks(guardrail.Spec, owner, edge); reason != "" {
			findings = append(findings, Finding{
				GuardrailID: guardrail.ID, Version: guardrail.Version, Name: guardrail.Name,
				Kind: guardrail.Kind, Mode: guardrail.Mode, Reason: reason,
			})
		}
	}
	return findings
}

func breaks(spec Spec, owner workspace.ID, edge ShareEdge) string {
	providerNetwork, consumerNetwork := edge.Provider.NetworkID(), edge.Consumer.NetworkID()
	ownsProvider := edge.Provider.WorkspaceID() == owner
	ownsConsumer := edge.Consumer.WorkspaceID() == owner
	switch spec.Kind {
	case KindNetworkIsolation:
		params := spec.Isolation
		// Traffic flows from the consumer's Devices to the provider's Device.
		if ownsConsumer && ownsProvider &&
			(slices.Contains(params.From, consumerNetwork) && slices.Contains(params.To, providerNetwork) ||
				params.BothDirections && slices.Contains(params.From, providerNetwork) &&
					slices.Contains(params.To, consumerNetwork)) {
			return ReasonIsolatedNetworks
		}
	case KindNetworkSharing:
		params := spec.Sharing
		if ownsProvider && params.Direction.covers(DirectionOutgoing) && slices.Contains(params.Networks, providerNetwork) ||
			ownsConsumer && params.Direction.covers(DirectionIncoming) && slices.Contains(params.Networks, consumerNetwork) {
			return ReasonSharingLocked
		}
	case KindExternalSharing:
		params := spec.External
		if edge.Provider.WorkspaceID() == edge.Consumer.WorkspaceID() {
			return ""
		}
		var side Direction
		var mine network.ID
		var other workspace.ID
		switch {
		case ownsProvider:
			side, mine, other = DirectionOutgoing, providerNetwork, edge.Consumer.WorkspaceID()
		case ownsConsumer:
			side, mine, other = DirectionIncoming, consumerNetwork, edge.Provider.WorkspaceID()
		default:
			return ""
		}
		if params.Direction.covers(side) && (len(params.Networks) == 0 || slices.Contains(params.Networks, mine)) &&
			!slices.Contains(params.AllowedWorkspaces, other) {
			return ReasonExternalSharing
		}
	}
	return ""
}

// Blocking returns the findings of guardrails in enforce mode.
func Blocking(findings []Finding) []Finding {
	blocking := []Finding{}
	for _, finding := range findings {
		if finding.Mode == ModeEnforce {
			blocking = append(blocking, finding)
		}
	}
	return blocking
}

// ViolationError reports a change blocked by enforced guardrails.
type ViolationError struct {
	Findings []Finding
}

func (violation *ViolationError) Error() string {
	return "guardrail: change breaks an enforced guardrail"
}

// Check evaluates an edge and returns a *ViolationError when an enforced
// guardrail blocks it, plus every finding for audit evidence.
func Check(guardrails []Guardrail, owner workspace.ID, edge ShareEdge) ([]Finding, error) {
	findings := Evaluate(guardrails, owner, edge)
	if blocking := Blocking(findings); len(blocking) > 0 {
		return findings, &ViolationError{Findings: blocking}
	}
	return findings, nil
}
