package simulation

import (
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

// A bounded list of findings keeps every blocking one: they sort first,
// whatever their path, side or guardrail.
func TestBlockingGuardrailFindingsSortFirst(t *testing.T) {
	t.Parallel()
	early, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	late, _ := node.ParseID("01890f00-0000-7000-8000-000000000399")
	imported, _ := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000825")
	id, _ := publicid.Parse("01890f00-0000-7000-8000-00000000e001")
	own := &guardrail.Finding{GuardrailID: id}
	findings := []GuardrailFinding{
		{SourceNodeID: early, ImportedResourceID: imported, Side: GuardrailSideActing, Mode: guardrail.ModeAudit, Guardrail: own},
		{SourceNodeID: late, ImportedResourceID: imported, Side: GuardrailSideProvider, Mode: guardrail.ModeEnforce, Blocks: true},
		{SourceNodeID: early, ImportedResourceID: imported, Side: GuardrailSideActing, Mode: guardrail.ModeEnforce, Guardrail: own},
		{SourceNodeID: late, ImportedResourceID: imported, Side: GuardrailSideActing, Mode: guardrail.ModeEnforce, Blocks: true, Guardrail: own},
	}
	slices.SortFunc(findings, compareGuardrailFindings)
	if !findings[0].Blocks || !findings[1].Blocks || findings[2].Blocks || findings[3].Blocks {
		t.Fatalf("blocking findings do not come first: %+v", findings)
	}
	if !validGuardrailFindings(findings) {
		t.Fatal("sorted findings are not valid")
	}
}
