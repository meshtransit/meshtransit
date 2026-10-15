package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

// The publishing Workspace sees its own guardrail by name; the provider's
// finding names nothing, even if the domain value carried details.
func TestSimulatedGuardrailFindingsHideTheProvider(t *testing.T) {
	t.Parallel()
	source, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	imported, _ := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000825")
	id, _ := publicid.Parse("01890f00-0000-7000-8000-00000000e001")
	secret := guardrail.Finding{GuardrailID: id, Name: "Provider secret", Kind: guardrail.KindNetworkSharing,
		Mode: guardrail.ModeEnforce, Reason: guardrail.ReasonSharingLocked}
	own := secret
	own.Name = "Our lock"
	encoded := encodeSimulatedGuardrailFindings([]simulation.GuardrailFinding{
		{SourceNodeID: source, ImportedResourceID: imported, Side: simulation.GuardrailSideActing,
			Mode: guardrail.ModeEnforce, Blocks: true, Guardrail: &own},
		{SourceNodeID: source, ImportedResourceID: imported, Side: simulation.GuardrailSideProvider,
			Mode: guardrail.ModeEnforce, Blocks: true, Guardrail: &secret},
	})
	body, err := json.Marshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 2 || encoded[0].Guardrail == nil || encoded[0].Guardrail.Name != "Our lock" ||
		encoded[1].Guardrail != nil || strings.Contains(string(body), "Provider secret") {
		t.Fatalf("encoded findings = %s", body)
	}
}
