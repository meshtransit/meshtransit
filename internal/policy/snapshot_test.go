package policy

import (
	"errors"
	"testing"
)

func TestSnapshotCanonicalizesRulesAndOwnsInput(t *testing.T) {
	t.Parallel()

	source := policyNodeFixture(t, "000000000701")
	destination := policyNodeFixture(t, "000000000702")
	port, err := NewPortRange(443, 443)
	if err != nil {
		t.Fatalf("NewPortRange() error = %v", err)
	}
	second := policyRuleFixture(t, "000000000802", source, destination, ProtocolTCP, []PortRange{port})
	first := policyRuleFixture(t, "000000000801", source, destination, ProtocolUDP, []PortRange{port})
	rules := []Rule{second, first}
	snapshot, err := NewSnapshot(SnapshotParams{
		Scope:    policyScopeFixture(t),
		Revision: 7,
		Rules:    rules,
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	rules[0] = Rule{}

	got := snapshot.Rules()
	if len(got) != 2 || got[0].ID() != first.ID() || got[1].ID() != second.ID() {
		t.Fatalf("Rules() = %+v, want deterministic rule id order", got)
	}
	got[0] = Rule{}
	if !snapshot.IsValid() || snapshot.Rules()[0].ID() != first.ID() {
		t.Fatal("snapshot exposed mutable rule storage")
	}
}

func TestSnapshotRejectsDuplicateAndExcessRules(t *testing.T) {
	t.Parallel()

	source := policyNodeFixture(t, "000000000701")
	destination := policyNodeFixture(t, "000000000702")
	rule := policyRuleFixture(t, "000000000801", source, destination, ProtocolICMP, nil)

	if _, err := NewSnapshot(SnapshotParams{
		Scope:    policyScopeFixture(t),
		Revision: 1,
		Rules:    []Rule{rule, rule},
	}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("duplicate NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
	}

	rules := make([]Rule, MaximumRules+1)
	if _, err := NewSnapshot(SnapshotParams{
		Scope:    policyScopeFixture(t),
		Revision: 1,
		Rules:    rules,
	}); !errors.Is(err, ErrRuleLimit) {
		t.Fatalf("excess NewSnapshot() error = %v, want ErrRuleLimit", err)
	}
}

func TestSnapshotPeerVisibilityRequiresExplicitDirectionalRule(t *testing.T) {
	t.Parallel()

	first := policyNodeFixture(t, "000000000701")
	second := policyNodeFixture(t, "000000000702")
	third := policyNodeFixture(t, "000000000703")
	rule := policyRuleFixture(t, "000000000801", second, first, ProtocolICMP, nil)
	snapshot, err := NewSnapshot(SnapshotParams{
		Scope:    policyScopeFixture(t),
		Revision: 3,
		Rules:    []Rule{rule},
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	if !snapshot.AllowsPeer(first, second) {
		t.Fatal("responder peer was hidden despite explicit reverse-direction rule")
	}
	if snapshot.AllowsPeer(first, third) || snapshot.AllowsPeer(first, first) {
		t.Fatal("snapshot inferred peer visibility without an explicit rule")
	}
}
