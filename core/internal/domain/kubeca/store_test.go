package kubeca

import "testing"

func TestReasons(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		reason        Reason
		creates, move bool
	}{
		{ReasonInitial, true, false},
		{ReasonScheduled, true, true},
		{ReasonNameChanged, true, true},
		{ReasonEmergency, true, true},
		{ReasonClusterDeleted, false, true},
		{ReasonExpired, false, true},
		{Reason("recovery"), false, false},
	} {
		if test.reason.CreatesCA() != test.creates || test.reason.MovesCA() != test.move {
			t.Errorf("%s: creates %v, moves %v", test.reason, test.reason.CreatesCA(), test.reason.MovesCA())
		}
	}
}
