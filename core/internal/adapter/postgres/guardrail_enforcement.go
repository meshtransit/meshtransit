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

// shareOfferProviderGuardrailsSQL reads the provider Workspace's guardrails
// for an offer this consumer scope received (schema 163).
const shareOfferProviderGuardrailsSQL = `SELECT mesh_ops.share_offer_provider_guardrails_v1($1::UUID)::TEXT`

// shareGuardrailFindings are the findings of each side: the acting side's,
// recorded in its own evidence, and, when the consumer acts on a share from
// another Workspace, the provider's, recorded only on the provider's side.
type shareGuardrailFindings struct {
	acting   []guardrail.Finding
	provider []guardrail.Finding
}

// checkShareGuardrails evaluates a share change against the guardrails of
// the acting Workspace, whose verified scope this transaction holds, and,
// when the consumer accepts or activates a share from another Workspace,
// against the provider's. An enforced guardrail of the acting side returns
// *guardrail.ViolationError, one of the provider's
// *guardrail.CounterpartViolationError, and the transaction rolls back;
// audit-mode findings come back for the evidence.
func checkShareGuardrails(ctx context.Context, transaction resourceAuthorityDatabaseTransaction, action string,
	localScope network.Scope, locator resourceSharingScopeLocator) (shareGuardrailFindings, error) {
	if !guardedShareActions[action] {
		return shareGuardrailFindings{}, nil
	}
	edge := guardrail.ShareEdge{Provider: locator.provider.scope, Consumer: locator.consumer.scope}
	var encoded string
	if err := transaction.QueryRow(ctx, activeWorkspaceGuardrailsSQL).Scan(&encoded); err != nil {
		return shareGuardrailFindings{}, resourceSharingDatabaseError(ctx, err)
	}
	guardrails, err := decodeActiveGuardrails(encoded)
	if err != nil {
		return shareGuardrailFindings{}, sharing.ErrUnavailable
	}
	acting, err := guardrail.Check(guardrails, localScope.WorkspaceID(), edge)
	if err != nil {
		return shareGuardrailFindings{}, err
	}
	result := shareGuardrailFindings{acting: acting}
	providerWorkspace := locator.provider.scope.WorkspaceID()
	if localScope != locator.consumer.scope || providerWorkspace == locator.consumer.scope.WorkspaceID() {
		return result, nil
	}
	if !locator.offerID.IsValid() {
		return shareGuardrailFindings{}, sharing.ErrUnavailable
	}
	if err := transaction.QueryRow(ctx, shareOfferProviderGuardrailsSQL, locator.offerID.String()).
		Scan(&encoded); err != nil {
		return shareGuardrailFindings{}, resourceSharingDatabaseError(ctx, err)
	}
	if guardrails, err = decodeActiveGuardrails(encoded); err != nil {
		return shareGuardrailFindings{}, sharing.ErrUnavailable
	}
	result.provider = guardrail.Evaluate(guardrails, providerWorkspace, edge)
	if len(guardrail.Blocking(result.provider)) > 0 {
		return shareGuardrailFindings{}, &guardrail.CounterpartViolationError{}
	}
	return result, nil
}
