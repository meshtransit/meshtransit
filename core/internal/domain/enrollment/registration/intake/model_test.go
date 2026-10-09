package intake_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestAuthorityAndResolutionRejectIncompleteEvidence(t *testing.T) {
	t.Parallel()

	if _, err := intake.NewAuthority(intake.AuthorityParams{}); !errors.Is(err, intake.ErrInvalidAuthority) {
		t.Fatalf("NewAuthority() error = %v, want invalid authority", err)
	}
	authority := validAuthority(t)
	if _, err := intake.NewExistingResolution(
		authority,
		mustRegistrationID(t, "01890f50-0000-7000-8000-000000000099"),
		registration.RequestHash{},
	); !errors.Is(err, intake.ErrInvalidResolution) {
		t.Fatalf("NewExistingResolution() error = %v, want invalid resolution", err)
	}
	if intake.NewResolution(intake.Authority{}).IsValid() {
		t.Fatal("Resolution accepted empty authority")
	}
}

func TestEvidenceIDsRequireDistinctUUIDs(t *testing.T) {
	t.Parallel()

	ids := validEvidenceIDs(t)
	if !ids.IsValid() || !ids.ChangeID().IsValid() || !ids.AuditEventID().IsValid() ||
		!ids.OutboxEventID().IsValid() {
		t.Fatalf("valid EvidenceIDs rejected: %+v", ids)
	}
	if ids.ChangeID() == ids.AuditEventID() || ids.ChangeID() == ids.OutboxEventID() ||
		ids.AuditEventID() == ids.OutboxEventID() {
		t.Fatal("EvidenceIDs aliased distinct authority evidence")
	}
	if _, err := intake.NewEvidenceIDs(
		ids.ChangeID(),
		ids.ChangeID(),
		publicid.ID{},
	); !errors.Is(err, intake.ErrInvalidEvidenceIDs) {
		t.Fatalf("NewEvidenceIDs() error = %v, want invalid evidence IDs", err)
	}
}

func TestChangeBindsCommandRegistrationHashAndTime(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	authority := validAuthority(t)
	command := commandFromRequest(request, authority, request.RegistrationID)
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	transaction := &fakeTransaction{resolution: intake.NewResolution(authority)}
	service, _ := newService(
		t,
		&transactionQueue{transactions: []*fakeTransaction{transaction}},
		validVerifier{accept: true},
	)
	if _, err := service.Prepare(t.Context(), request); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	change := transaction.changes[0]
	if change.RequestHash() != hash || !change.OccurredAt().Equal(intakeTime) || !change.IsValid() {
		t.Fatal("Change did not preserve command hash and stable decision time")
	}
	if _, err := intake.NewChange(
		command,
		change.Registration(),
		registration.RequestHash{},
		change.EvidenceIDs(),
		intakeTime,
	); !errors.Is(err, intake.ErrInvalidChange) {
		t.Fatalf("NewChange() error = %v, want invalid change", err)
	}
}
