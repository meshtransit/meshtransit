package oidcauth

import (
	"errors"
	"testing"
)

func TestSystemStartDependenciesGenerateCompleteIndependentMaterial(t *testing.T) {
	t.Parallel()
	transactionID, ids, err := (SystemStartIDs{}).NewStartIDs()
	if err != nil || !transactionID.IsValid() || !ids.IsValid() {
		t.Fatal("runtime did not generate complete identities")
	}
	for _, value := range [][16]byte{ids.ChangeID().Bytes(), ids.AuditEventID().Bytes(), ids.OutboxEventID().Bytes()} {
		if value == transactionID.Bytes() {
			t.Fatal("runtime aliased transaction and evidence identity")
		}
	}
	secrets, err := (SystemSecrets{}).NewSecrets()
	if err != nil || !secrets.IsValid() {
		t.Fatal("runtime did not generate independent secrets")
	}
	if (SystemStartClock{}).Now().IsZero() {
		t.Fatal("runtime clock returned zero")
	}
}

func TestStartOutcomeHasClosedLabelsAndClassification(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want StartOutcome
	}{
		{name: "committed", want: StartOutcomeCommitted},
		{name: "invalid", err: ErrInvalidCreated, want: StartOutcomeRejected},
		{name: "expired", err: ErrStartExpired, want: StartOutcomeRejected},
		{name: "unknown", err: ErrCommitOutcomeUnknown, want: StartOutcomeUncertain},
		{name: "cleanup precedes unknown", err: errors.Join(ErrStartRollbackFailed, ErrCommitOutcomeUnknown), want: StartOutcomeCleanupFailed},
		{name: "dependency", err: errors.New("synthetic dependency failure"), want: StartOutcomeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if startOutcome(test.err) != test.want {
				t.Fatal("outcome classification differs")
			}
		})
	}
	if StartOutcome(200).String() != "unknown" || StartOutcomeUnknown.String() != "unknown" {
		t.Fatal("unsupported outcome became unbounded label")
	}
}
