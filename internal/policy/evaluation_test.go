package policy

import "testing"

func TestEvaluateDefaultsToDenyAndMatchesExactPacket(t *testing.T) {
	t.Parallel()

	source := policyNodeFixture(t, "000000000701")
	destination := policyNodeFixture(t, "000000000702")
	port, err := NewPortRange(80, 443)
	if err != nil {
		t.Fatalf("NewPortRange() error = %v", err)
	}
	rule := policyRuleFixture(t, "000000000801", source, destination, ProtocolTCP, []PortRange{port})
	allowedSnapshot, err := NewSnapshot(SnapshotParams{
		Scope:    policyScopeFixture(t),
		Revision: 9,
		Rules:    []Rule{rule},
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	denySnapshot, err := NewSnapshot(SnapshotParams{
		Scope:    policyScopeFixture(t),
		Revision: 9,
		Rules:    nil,
	})
	if err != nil {
		t.Fatalf("NewSnapshot(deny) error = %v", err)
	}
	request, err := NewPacketRequest(PacketRequestParams{
		Scope:             policyScopeFixture(t),
		PolicyRevision:    9,
		SourceNodeID:      source,
		DestinationNodeID: destination,
		Protocol:          ProtocolTCP,
		DestinationPort:   443,
	})
	if err != nil {
		t.Fatalf("NewPacketRequest() error = %v", err)
	}
	if decision := Evaluate(denySnapshot, request); decision.IsAllowed() ||
		decision.Reason() != ReasonNoMatchingRule {
		t.Fatalf("deny decision = %s, want no_matching_rule", decision.Reason())
	}
	decision := Evaluate(allowedSnapshot, request)
	if !decision.IsAllowed() || decision.Reason() != ReasonAllowed ||
		len(decision.RuleIDs()) != 1 || decision.RuleIDs()[0] != rule.ID() {
		t.Fatalf("allow decision = %+v, want matching rule", decision)
	}
}

func TestEvaluateRejectsDirectionProtocolPortScopeAndRevisionWidening(t *testing.T) {
	t.Parallel()

	source := policyNodeFixture(t, "000000000701")
	destination := policyNodeFixture(t, "000000000702")
	port, err := NewPortRange(443, 443)
	if err != nil {
		t.Fatalf("NewPortRange() error = %v", err)
	}
	rule := policyRuleFixture(t, "000000000801", source, destination, ProtocolTCP, []PortRange{port})
	snapshot, err := NewSnapshot(SnapshotParams{
		Scope:    policyScopeFixture(t),
		Revision: 4,
		Rules:    []Rule{rule},
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	testCases := []struct {
		name     string
		params   PacketRequestParams
		expected Reason
	}{
		{
			name: "reverse direction",
			params: PacketRequestParams{Scope: policyScopeFixture(t), PolicyRevision: 4,
				SourceNodeID: destination, DestinationNodeID: source, Protocol: ProtocolTCP, DestinationPort: 443},
			expected: ReasonNoMatchingRule,
		},
		{
			name: "different protocol",
			params: PacketRequestParams{Scope: policyScopeFixture(t), PolicyRevision: 4,
				SourceNodeID: source, DestinationNodeID: destination, Protocol: ProtocolUDP, DestinationPort: 443},
			expected: ReasonNoMatchingRule,
		},
		{
			name: "different port",
			params: PacketRequestParams{Scope: policyScopeFixture(t), PolicyRevision: 4,
				SourceNodeID: source, DestinationNodeID: destination, Protocol: ProtocolTCP, DestinationPort: 80},
			expected: ReasonNoMatchingRule,
		},
		{
			name: "stale revision",
			params: PacketRequestParams{Scope: policyScopeFixture(t), PolicyRevision: 3,
				SourceNodeID: source, DestinationNodeID: destination, Protocol: ProtocolTCP, DestinationPort: 443},
			expected: ReasonStalePolicy,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			request, requestErr := NewPacketRequest(testCase.params)
			if requestErr != nil {
				t.Fatalf("NewPacketRequest() error = %v", requestErr)
			}
			decision := Evaluate(snapshot, request)
			if decision.IsAllowed() || decision.Reason() != testCase.expected {
				t.Fatalf("Evaluate() = %s, want %s", decision.Reason(), testCase.expected)
			}
		})
	}
}
