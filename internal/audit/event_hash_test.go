package audit_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestHashEventIsDeterministicAndFieldBound(t *testing.T) {
	t.Parallel()

	material := validEventHashMaterial(t)
	first, err := audit.HashEvent(material)
	if err != nil {
		t.Fatalf("HashEvent() error = %v", err)
	}
	second, err := audit.HashEvent(material)
	if err != nil {
		t.Fatalf("HashEvent() second error = %v", err)
	}
	if first != second || first == ([sha256.Size]byte{}) {
		t.Fatalf("HashEvent() = %x then %x, want one non-zero deterministic hash", first, second)
	}

	changed := material
	changed.Action = "device.resumed"
	different, err := audit.HashEvent(changed)
	if err != nil {
		t.Fatalf("HashEvent(changed) error = %v", err)
	}
	if different == first {
		t.Fatal("HashEvent() did not bind the action field")
	}
}

func TestHashEventDistinguishesFieldBoundaries(t *testing.T) {
	t.Parallel()

	left := validEventHashMaterial(t)
	left.AggregateKind = "device"
	left.Action = "registered"
	right := left
	right.AggregateKind = "device.registered"
	right.Action = "device"

	leftHash, err := audit.HashEvent(left)
	if err != nil {
		t.Fatalf("HashEvent(left) error = %v", err)
	}
	rightHash, err := audit.HashEvent(right)
	if err != nil {
		t.Fatalf("HashEvent(right) error = %v", err)
	}
	if leftHash == rightHash {
		t.Fatal("HashEvent() merged distinct field boundaries")
	}
}

func TestHashEventRejectsInvalidMaterial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*audit.EventHashMaterial)
	}{
		{name: "missing event id", mutate: func(value *audit.EventHashMaterial) { value.EventID = publicid.ID{} }},
		{name: "invalid version", mutate: func(value *audit.EventHashMaterial) { value.AggregateVersion = 0 }},
		{name: "invalid label", mutate: func(value *audit.EventHashMaterial) { value.Action = "Device Registered" }},
		{name: "missing audit payload hash", mutate: func(value *audit.EventHashMaterial) { value.AuditPayloadHash = [sha256.Size]byte{} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			material := validEventHashMaterial(t)
			test.mutate(&material)
			result, err := audit.HashEvent(material)
			if !errors.Is(err, audit.ErrInvalidEventHash) {
				t.Fatalf("HashEvent() error = %v, want ErrInvalidEventHash", err)
			}
			if result != ([sha256.Size]byte{}) {
				t.Fatalf("HashEvent() = %x after invalid input", result)
			}
		})
	}
}

func validEventHashMaterial(t *testing.T) audit.EventHashMaterial {
	t.Helper()

	parseID := func(value string) publicid.ID {
		t.Helper()
		id, err := publicid.Parse(value)
		if err != nil {
			t.Fatalf("parse test public id: %v", err)
		}
		return id
	}
	auditPayloadHash := sha256.Sum256([]byte(`{"disposition":"created"}`))
	outboxPayloadHash := sha256.Sum256([]byte(`{"network_revision":2}`))
	return audit.EventHashMaterial{
		PreviousHash:      sha256.Sum256([]byte("previous")),
		EventID:           parseID("01890f20-0000-7000-8000-000000000001"),
		ChangeID:          parseID("01890f20-0000-7000-8000-000000000002"),
		AggregateKind:     "device",
		AggregateID:       parseID("01890f20-0000-7000-8000-000000000003"),
		AggregateVersion:  1,
		NetworkRevision:   2,
		ActorPrincipalID:  parseID("01890f20-0000-7000-8000-000000000004"),
		Action:            "device.registered",
		Permission:        "device.register",
		CorrelationID:     parseID("01890f20-0000-7000-8000-000000000005"),
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  "network.revision.advanced",
		OutboxPayloadHash: outboxPayloadHash,
	}
}
