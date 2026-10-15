package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/publicid"
)

// The acting Workspace sees which of its guardrails blocked a change; the
// other Workspace's guardrails stay private behind one generic refusal.
func TestGuardrailViolationKeepsTheOtherWorkspacePrivate(t *testing.T) {
	t.Parallel()
	id, err := publicid.Parse("01890f00-0000-7000-8000-00000000e001")
	if err != nil {
		t.Fatal(err)
	}
	own, ok := guardrailViolation(fmt.Errorf("share: %w", &guardrail.ViolationError{Findings: []guardrail.Finding{{
		GuardrailID: id, Name: "Production shares nothing", Kind: guardrail.KindNetworkSharing,
		Reason: guardrail.ReasonSharingLocked,
	}}}))
	if !ok || own.Status != http.StatusConflict || own.Code != "guardrail_violation" ||
		len(own.GuardrailFindings) != 1 || own.GuardrailFindings[0].Name != "Production shares nothing" {
		t.Fatalf("own guardrail = %+v, %t", own, ok)
	}
	other, ok := guardrailViolation(fmt.Errorf("share: %w", &guardrail.CounterpartViolationError{}))
	if !ok || other.Status != http.StatusConflict || other.Code != "counterpart_guardrail_violation" ||
		len(other.GuardrailFindings) != 0 {
		t.Fatalf("other Workspace's guardrail = %+v, %t", other, ok)
	}
	if _, ok := guardrailViolation(errors.New("unrelated")); ok {
		t.Fatal("an unrelated error mapped to a guardrail refusal")
	}
}
