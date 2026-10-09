package postgres

import (
	"context"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/sharing"
)

// guardedShareActions open or keep open a path between Networks; each is
// checked against the acting Workspace's guardrails inside its transaction.
// Declining, withdrawing and revoking only close paths and are never blocked.
var guardedShareActions = map[string]bool{
	"share_offer.created":      true,
	"share_offer.accepted":     true,
	"trust_contract.activated": true,
}

// guardrailFindingEvidence records, in the acting side's audit payload, each
// guardrail a change broke: audit-mode findings on changes that went ahead.
type guardrailFindingEvidence struct {
	GuardrailID string `json:"guardrail_id"`
	Version     int64  `json:"version"`
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Reason      string `json:"reason"`
}

func guardrailFindingsEvidence(findings []guardrail.Finding) []guardrailFindingEvidence {
	if len(findings) == 0 {
		return nil
	}
	evidence := make([]guardrailFindingEvidence, len(findings))
	for index, finding := range findings {
		evidence[index] = guardrailFindingEvidence{
			GuardrailID: finding.GuardrailID.String(), Version: finding.Version, Name: finding.Name,
			Mode: string(finding.Mode), Reason: finding.Reason,
		}
	}
	return evidence
}

// checkShareGuardrails evaluates a share change against the guardrails of
// the acting Workspace, whose verified scope this transaction holds. An
// enforced guardrail returns *guardrail.ViolationError and the transaction
// rolls back; audit-mode findings come back for the evidence.
func checkShareGuardrails(ctx context.Context, transaction resourceAuthorityDatabaseTransaction, action string,
	localScope network.Scope, locator resourceSharingScopeLocator) ([]guardrail.Finding, error) {
	if !guardedShareActions[action] {
		return nil, nil
	}
	var encoded string
	if err := transaction.QueryRow(ctx, activeWorkspaceGuardrailsSQL).Scan(&encoded); err != nil {
		return nil, resourceSharingDatabaseError(ctx, err)
	}
	guardrails, err := decodeActiveGuardrails(encoded)
	if err != nil {
		return nil, sharing.ErrUnavailable
	}
	return guardrail.Check(guardrails, localScope.WorkspaceID(),
		guardrail.ShareEdge{Provider: locator.provider.scope, Consumer: locator.consumer.scope})
}
