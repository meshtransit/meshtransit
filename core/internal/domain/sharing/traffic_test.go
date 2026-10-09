package sharing

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
)

func TestNewTrafficSetCanonicalizesAndOwnsInput(t *testing.T) {
	t.Parallel()

	first := mustPortRange(t, 90, 100)
	second := mustPortRange(t, 80, 89)
	constraints := []TrafficConstraint{
		mustTrafficConstraint(t, policy.ProtocolTCP, first),
		mustTrafficConstraint(t, policy.ProtocolTCP, second),
		mustTrafficConstraint(t, policy.ProtocolICMP),
	}

	set, err := NewTrafficSet(constraints)
	if err != nil {
		t.Fatalf("NewTrafficSet() error = %v", err)
	}
	constraints[0] = TrafficConstraint{}

	values := set.Constraints()
	if len(values) != 2 || values[0].Protocol() != policy.ProtocolTCP ||
		values[1].Protocol() != policy.ProtocolICMP {
		t.Fatalf("Constraints() = %#v, want canonical TCP and ICMP", values)
	}
	ranges := values[0].DestinationPortRanges()
	if len(ranges) != 1 || ranges[0].First() != 80 || ranges[0].Last() != 100 {
		t.Fatalf("TCP ranges = %#v, want 80-100", ranges)
	}
	ranges[0] = mustPortRange(t, 443, 443)
	if !set.Allows(policy.ProtocolTCP, 95) || set.Allows(policy.ProtocolTCP, 443) ||
		!set.Allows(policy.ProtocolICMP, 0) || set.Allows(policy.ProtocolICMP, 1) {
		t.Fatal("TrafficSet did not retain canonical owned authority")
	}
}

func TestTrafficConstraintRejectsProtocolPortAmbiguity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol policy.Protocol
		ranges   []policy.PortRange
	}{
		{name: "unknown protocol", protocol: policy.ProtocolUnknown},
		{name: "tcp without ports", protocol: policy.ProtocolTCP},
		{name: "udp without ports", protocol: policy.ProtocolUDP},
		{name: "icmp with ports", protocol: policy.ProtocolICMP, ranges: []policy.PortRange{mustPortRange(t, 1, 1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewTrafficConstraint(TrafficConstraintParams{
				Protocol: test.protocol, DestinationPortRanges: test.ranges,
			}); !errors.Is(err, ErrInvalidTrafficConstraint) {
				t.Fatalf("NewTrafficConstraint() error = %v, want ErrInvalidTrafficConstraint", err)
			}
		})
	}
}

func TestIntersectTrafficReturnsExactProviderConsumerMinimum(t *testing.T) {
	t.Parallel()

	provider := mustTrafficSet(t,
		mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 80, 100)),
		mustTrafficConstraint(t, policy.ProtocolUDP, mustPortRange(t, 53, 53)),
		mustTrafficConstraint(t, policy.ProtocolICMP),
	)
	consumer := mustTrafficSet(t,
		mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 90, 110)),
		mustTrafficConstraint(t, policy.ProtocolICMP),
	)

	intersection, ok := IntersectTraffic(provider, consumer)
	if !ok || !intersection.Allows(policy.ProtocolTCP, 90) ||
		!intersection.Allows(policy.ProtocolTCP, 100) ||
		intersection.Allows(policy.ProtocolTCP, 89) ||
		intersection.Allows(policy.ProtocolTCP, 101) ||
		intersection.Allows(policy.ProtocolUDP, 53) ||
		!intersection.Allows(policy.ProtocolICMP, 0) {
		t.Fatalf("IntersectTraffic() = %#v, %t, want TCP 90-100 and ICMP", intersection, ok)
	}
	if !intersection.IsSubsetOf(provider) || !intersection.IsSubsetOf(consumer) ||
		provider.IsSubsetOf(consumer) {
		t.Fatal("TrafficSet subset relation widened authority")
	}
}

func TestIntersectTrafficFailsClosedOnDisjointSets(t *testing.T) {
	t.Parallel()

	left := mustTrafficSet(t,
		mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 80, 80)),
	)
	right := mustTrafficSet(t,
		mustTrafficConstraint(t, policy.ProtocolTCP, mustPortRange(t, 443, 443)),
	)
	if intersection, ok := IntersectTraffic(left, right); ok || intersection.IsValid() {
		t.Fatalf("IntersectTraffic() = %#v, %t, want empty denial", intersection, ok)
	}
}

func mustPortRange(t *testing.T, first, last uint16) policy.PortRange {
	t.Helper()
	value, err := policy.NewPortRange(first, last)
	if err != nil {
		t.Fatalf("policy.NewPortRange() error = %v", err)
	}
	return value
}

func mustTrafficConstraint(
	t *testing.T,
	protocol policy.Protocol,
	ranges ...policy.PortRange,
) TrafficConstraint {
	t.Helper()
	value, err := NewTrafficConstraint(TrafficConstraintParams{
		Protocol: protocol, DestinationPortRanges: ranges,
	})
	if err != nil {
		t.Fatalf("NewTrafficConstraint() error = %v", err)
	}
	return value
}

func mustTrafficSet(t *testing.T, constraints ...TrafficConstraint) TrafficSet {
	t.Helper()
	value, err := NewTrafficSet(constraints)
	if err != nil {
		t.Fatalf("NewTrafficSet() error = %v", err)
	}
	return value
}
