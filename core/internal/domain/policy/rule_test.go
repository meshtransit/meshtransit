package policy

import (
	"errors"
	"testing"
)

func TestRuleCanonicalizesPortRangesAndOwnsInput(t *testing.T) {
	t.Parallel()

	source := policyNodeFixture(t, "000000000701")
	destination := policyNodeFixture(t, "000000000702")
	first, err := NewPortRange(443, 443)
	if err != nil {
		t.Fatalf("NewPortRange() error = %v", err)
	}
	second, err := NewPortRange(80, 81)
	if err != nil {
		t.Fatalf("NewPortRange() error = %v", err)
	}
	third, err := NewPortRange(82, 82)
	if err != nil {
		t.Fatalf("NewPortRange() error = %v", err)
	}
	ports := []PortRange{first, third, second}
	rule := policyRuleFixture(t, "000000000801", source, destination, ProtocolTCP, ports)
	ports[0] = PortRange{}

	got := rule.DestinationPortRanges()
	if len(got) != 2 || got[0].First() != 80 || got[0].Last() != 82 ||
		got[1].First() != 443 || got[1].Last() != 443 {
		t.Fatalf("DestinationPortRanges() = %+v, want [80-82, 443]", got)
	}
	got[0] = PortRange{}
	if !rule.IsValid() || rule.DestinationPortRanges()[0].First() != 80 {
		t.Fatal("rule exposed mutable port storage")
	}
}

func TestRuleRejectsUnsafeProtocolPortShapes(t *testing.T) {
	t.Parallel()

	source := policyNodeFixture(t, "000000000701")
	destination := policyNodeFixture(t, "000000000702")
	port, err := NewPortRange(443, 443)
	if err != nil {
		t.Fatalf("NewPortRange() error = %v", err)
	}

	for _, testCase := range []struct {
		name     string
		protocol Protocol
		ports    []PortRange
	}{
		{name: "unknown protocol", protocol: ProtocolUnknown, ports: []PortRange{port}},
		{name: "tcp without ports", protocol: ProtocolTCP},
		{name: "udp without ports", protocol: ProtocolUDP},
		{name: "icmp with ports", protocol: ProtocolICMP, ports: []PortRange{port}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			id, parseErr := ParseRuleID("01890f00-0000-7000-8000-000000000801")
			if parseErr != nil {
				t.Fatalf("ParseRuleID() error = %v", parseErr)
			}
			_, ruleErr := NewRule(RuleParams{
				ID:                    id,
				Scope:                 policyScopeFixture(t),
				SourceNodeID:          source,
				DestinationNodeID:     destination,
				Protocol:              testCase.protocol,
				DestinationPortRanges: testCase.ports,
			})
			if !errors.Is(ruleErr, ErrInvalidRule) {
				t.Fatalf("NewRule() error = %v, want ErrInvalidRule", ruleErr)
			}
		})
	}
}

func TestRuleRejectsExcessTransportPortRangesBeforeNormalization(t *testing.T) {
	t.Parallel()

	source := policyNodeFixture(t, "000000000701")
	destination := policyNodeFixture(t, "000000000702")
	ports := make([]PortRange, MaximumPortRangesPerRule+1)
	for index := range ports {
		port, err := NewPortRange(uint16(index+1), uint16(index+1))
		if err != nil {
			t.Fatalf("NewPortRange(%d) error = %v", index+1, err)
		}
		ports[index] = port
	}
	id, err := ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatalf("ParseRuleID() error = %v", err)
	}
	if _, err := NewRule(RuleParams{
		ID:                    id,
		Scope:                 policyScopeFixture(t),
		SourceNodeID:          source,
		DestinationNodeID:     destination,
		Protocol:              ProtocolUDP,
		DestinationPortRanges: ports,
	}); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("NewRule() error = %v, want ErrInvalidRule", err)
	}
}
