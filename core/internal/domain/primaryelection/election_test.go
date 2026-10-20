package primaryelection

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

func device(t *testing.T, last byte) node.ID {
	t.Helper()
	id, err := node.ParseID("01a15307-09d3-76b4-a028-3c21ee7080" + string("0123456789abcdef"[last>>4]) +
		string("0123456789abcdef"[last&0xf]))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestElect(t *testing.T) {
	t.Parallel()
	first, second, third := device(t, 1), device(t, 2), device(t, 3)
	usable := func(id node.ID, usableFor time.Duration) Candidate {
		return Candidate{Device: id, Status: StatusUsable, UsableFor: usableFor}
	}
	with := func(id node.ID, status Status, code string) Candidate {
		return Candidate{Device: id, Status: status, Code: code}
	}
	for name, test := range map[string]struct {
		current    node.ID
		candidates []Candidate
		failback   bool
		want       node.ID
		reason     string
	}{
		"first election takes the preferred router": {
			candidates: []Candidate{usable(first, 0), usable(second, 0)}, want: first, reason: ReasonElected,
		},
		"a usable primary is kept": {
			current: second, candidates: []Candidate{usable(first, time.Hour), usable(second, 0)},
			want: second,
		},
		"failback returns to the preferred router once it is usable long enough": {
			current: second, candidates: []Candidate{usable(first, FailbackAfter), usable(second, 0)}, failback: true,
			want: first, reason: ReasonFailback,
		},
		"failback waits": {
			current: second, candidates: []Candidate{usable(first, FailbackAfter-time.Second), usable(second, 0)},
			failback: true, want: second,
		},
		"a failed primary fails over in priority order": {
			current:    first,
			candidates: []Candidate{with(first, StatusFailed, "forward_blocked"), usable(second, 0), usable(third, 0)},
			want:       second, reason: ReasonFailover,
		},
		"a draining primary fails over": {
			current: first, candidates: []Candidate{with(first, StatusDraining, ""), usable(second, 0)},
			want: second, reason: ReasonFailover,
		},
		"a router in hold-down is not chosen while another can serve": {
			current: second, candidates: []Candidate{with(first, StatusHoldDown, ""), with(second, StatusFailed, "x"), usable(third, 0)},
			want: third, reason: ReasonFailover,
		},
		"with none usable the best of the rest, hold-down first": {
			current: second, candidates: []Candidate{with(first, StatusHoldDown, ""), with(second, StatusFailed, "x")},
			want: first, reason: ReasonDegraded,
		},
		"the current router is kept when it is as good as any": {
			current: second, candidates: []Candidate{with(first, StatusFailed, "x"), with(second, StatusFailed, "y")},
			want: second,
		},
		"a draining router is better than a failed one": {
			current: second, candidates: []Candidate{with(first, StatusDraining, ""), with(second, StatusFailed, "probe_failed")},
			want: first, reason: ReasonDegraded,
		},
		"all probe failures keep the current router": {
			current:    second,
			candidates: []Candidate{with(first, StatusFailed, "probe_failed"), with(second, StatusFailed, "probe_failed")},
			want:       second,
		},
		"an ineligible primary is replaced": {
			current: first, candidates: []Candidate{with(first, StatusIneligible, ""), usable(second, 0)},
			want: second, reason: ReasonElected,
		},
		"no router at the authority level means none": {
			current: first, candidates: []Candidate{with(first, StatusIneligible, ""), with(second, StatusIneligible, "")},
			want: node.ID{}, reason: ReasonNone,
		},
		"no routers at all": {want: node.ID{}, reason: ReasonNone},
	} {
		got, reason := Elect(test.current, test.candidates, test.failback)
		if got != test.want || reason != test.reason {
			t.Errorf("%s: Elect() = %v %q, want %v %q", name, got, reason, test.want, test.reason)
		}
	}
}
