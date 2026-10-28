package main

import (
	"strings"
	"testing"
)

// Changes need an operator and a change record; a status read takes
// neither; retire-ca needs a CA and a reason, and nothing else does.
func TestParseKubernetesCAArguments(t *testing.T) {
	t.Parallel()
	const scope = "--workspace=01890f00-0000-7000-8000-000000000101 --network=01890f00-0000-7000-8000-000000000201"
	const operator = " --actor=alice@example.com --change-ref=CHG-7"
	const ca = " --ca=01890f00-0000-7000-8000-000000000301"
	for _, test := range []struct {
		args string
		ok   bool
	}{
		{"status " + scope, true},
		{"rewrap " + scope + operator, true},
		{"rotate-data-key " + scope + operator, true},
		{"retire-ca " + scope + operator + ca + " --reason=compromise", true},
		{"status " + scope + operator, false},
		{"rewrap " + scope, false},
		{"rewrap " + scope + " --actor=alice@example.com", false},
		{"retire-ca " + scope + operator + " --reason=compromise", false},
		{"retire-ca " + scope + operator + ca, false},
		{"rewrap " + scope + operator + ca, false},
		{"status --workspace=x --network=y", false},
		{"rename " + scope + operator, false},
		{"status " + scope + " extra", false},
		// The restore commands act on the whole installation.
		{"guard", true},
		{"mark-restored" + operator, true},
		{"reconcile-after-restore" + operator + " --roots-checked-since=2026-10-01T00:00:00Z", true},
		// Reconcile needs the time from which root retirements were
		// checked (a3 §14 R-M8), and nothing else takes it.
		{"reconcile-after-restore" + operator, false},
		{"reconcile-after-restore" + operator + " --roots-checked-since=yesterday", false},
		{"reconcile-after-restore" + operator + " --roots-checked-since=2999-01-01T00:00:00Z", false},
		{"mark-restored" + operator + " --roots-checked-since=2026-10-01T00:00:00Z", false},
		{"guard" + operator, false},
		{"mark-restored", false},
		{"reconcile-after-restore " + scope + operator, false},
		{"mark-restored" + operator + ca, false},
		{"mark-restored --actor=meshcore-worker --change-ref=restore-tripwire", false},
	} {
		if _, ok := parseKubernetesCAArguments(strings.Fields(test.args)); ok != test.ok {
			t.Errorf("%q: ok = %v", test.args, ok)
		}
	}
}
