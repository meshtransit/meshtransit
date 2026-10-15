package simulation

import (
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/workspace"
)

// GuardrailSide says whose guardrail a finding belongs to.
type GuardrailSide string

// Guardrail sides.
const (
	// GuardrailSideActing is a guardrail of the Workspace publishing.
	GuardrailSideActing GuardrailSide = "acting"
	// GuardrailSideProvider is a guardrail of the Workspace that provides the
	// Imported Resource. It is never named.
	GuardrailSideProvider GuardrailSide = "provider"
)

// GuardrailFinding is one guardrail a proposed path to an Imported Resource
// breaks, exactly as publication would evaluate it. Blocks is true for an
// enforced guardrail on a path the active release does not already open.
// A provider finding exists only when it blocks, the one fact publication
// also reveals, and carries no guardrail identity, name, kind or reason.
type GuardrailFinding struct {
	SourceNodeID       node.ID
	ImportedResourceID sharing.ImportedResourceID
	Side               GuardrailSide
	Mode               guardrail.Mode
	Blocks             bool
	Guardrail          *guardrail.Finding
}

// GuardrailFindings returns, in canonical order, every guardrail finding of
// the proposed paths to Imported Resources.
func (result Result) GuardrailFindings() []GuardrailFinding {
	return slices.Clone(result.guardrailFindings)
}

// guardrailFindings evaluates every proposed path to an Imported Resource
// against the publishing Workspace's guardrails and its provider's, the way
// publication does: enforced guardrails block only new paths.
func guardrailFindings(baseline Baseline, proposed publication.Candidate) ([]GuardrailFinding, error) {
	existing := map[string]bool{}
	for _, destination := range baseline.candidate.ImportedResourceDestinations() {
		existing[importedPath(destination)] = true
	}
	local := baseline.scope.WorkspaceID()
	findings := []GuardrailFinding{}
	for _, destination := range proposed.ImportedResourceDestinations() {
		provider := destination.Resolution().ProviderScope()
		edge := guardrail.ShareEdge{Provider: provider, Consumer: baseline.scope}
		isNew := !existing[importedPath(destination)]
		for _, finding := range guardrail.Evaluate(baseline.guardrails, local, edge) {
			own := finding
			findings = append(findings, GuardrailFinding{
				SourceNodeID: destination.SourceNodeID(), ImportedResourceID: destination.Resolution().ImportedResourceID(),
				Side: GuardrailSideActing, Mode: finding.Mode, Blocks: finding.Mode == guardrail.ModeEnforce && isNew,
				Guardrail: &own,
			})
		}
		if provider.WorkspaceID() == local {
			continue
		}
		// Fail closed as publication does: an unknown provider is never taken
		// to have no guardrail.
		providerGuardrails, known := baseline.providerGuardrails[provider.WorkspaceID()]
		if !known {
			return nil, ErrInvalidBaseline
		}
		for _, finding := range guardrail.Evaluate(providerGuardrails, provider.WorkspaceID(), edge) {
			if finding.Mode != guardrail.ModeEnforce || !isNew {
				continue
			}
			findings = append(findings, GuardrailFinding{
				SourceNodeID: destination.SourceNodeID(), ImportedResourceID: destination.Resolution().ImportedResourceID(),
				Side: GuardrailSideProvider, Mode: finding.Mode, Blocks: finding.Mode == guardrail.ModeEnforce && isNew,
			})
		}
	}
	slices.SortFunc(findings, compareGuardrailFindings)
	return slices.CompactFunc(findings, func(first, second GuardrailFinding) bool {
		return compareGuardrailFindings(first, second) == 0
	}), nil
}

func importedPath(destination publication.ImportedResourceDestination) string {
	return destination.SourceNodeID().String() + ":" + destination.Resolution().ImportedResourceID().String()
}

func guardrailFindingKey(finding GuardrailFinding) string {
	id := ""
	if finding.Guardrail != nil {
		id = finding.Guardrail.GuardrailID.String()
	}
	blocks := "0"
	if finding.Blocks {
		blocks = "1"
	}
	// Blocking findings sort first, so a bounded list never hides one.
	first := "1"
	if finding.Blocks {
		first = "0"
	}
	return strings.Join([]string{first, finding.SourceNodeID.String(), finding.ImportedResourceID.String(),
		string(finding.Side), id, string(finding.Mode), blocks}, "\x00")
}

func compareGuardrailFindings(first, second GuardrailFinding) int {
	return strings.Compare(guardrailFindingKey(first), guardrailFindingKey(second))
}

func validGuardrailFindings(findings []GuardrailFinding) bool {
	var previous *GuardrailFinding
	for _, finding := range findings {
		if !finding.SourceNodeID.IsValid() || !finding.ImportedResourceID.IsValid() ||
			(finding.Mode != guardrail.ModeAudit && finding.Mode != guardrail.ModeEnforce) ||
			(finding.Blocks && finding.Mode != guardrail.ModeEnforce) ||
			(finding.Side == GuardrailSideActing) != (finding.Guardrail != nil) ||
			(finding.Side == GuardrailSideProvider && !finding.Blocks) ||
			(finding.Side != GuardrailSideActing && finding.Side != GuardrailSideProvider) ||
			previous != nil && compareGuardrailFindings(*previous, finding) >= 0 {
			return false
		}
		previous = &finding
	}
	return true
}

// guardrailsEqual compares guardrail sets by identity and version.
func guardrailsEqual(first, second []guardrail.Guardrail) bool {
	return slices.EqualFunc(first, second, func(left, right guardrail.Guardrail) bool {
		return left.ID == right.ID && left.Version == right.Version
	})
}

func providerGuardrailsEqual(first, second map[workspace.ID][]guardrail.Guardrail) bool {
	if len(first) != len(second) {
		return false
	}
	for id, guardrails := range first {
		other, ok := second[id]
		if !ok || !guardrailsEqual(guardrails, other) {
			return false
		}
	}
	return true
}
