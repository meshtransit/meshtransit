package meshgw

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/kubediscovery"
	"meshtransit.net/client/internal/kubeproxy"
	"meshtransit.net/client/internal/rbaccheck"
)

// A group never checked makes the oldest check 0, first or last (review
// b6a M5).
func TestOldestCheck(t *testing.T) {
	t.Parallel()
	checked := time.Unix(1_800_000_000, 0)
	for name, groups := range map[string][]groupStatus{
		"unchecked first": {{Name: "a"}, {Name: "b", CheckedAt: checked}},
		"unchecked last":  {{Name: "b", CheckedAt: checked}, {Name: "a"}},
		"none":            {},
	} {
		if got := oldestCheck(groups); got != 0 {
			t.Errorf("%s: %d", name, got)
		}
	}
	if got := oldestCheck([]groupStatus{{CheckedAt: checked.Add(time.Hour)}, {CheckedAt: checked}}); got != checked.Unix() {
		t.Fatalf("oldest %d", got)
	}
	if got := labelValue("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Fatalf("escaped %q", got)
	}
}

// With profiles on, the metrics show decisions and discovery; off, none.
func TestProfileMetrics(t *testing.T) {
	t.Parallel()
	var off strings.Builder
	(&kubeRuntime{}).writeProfileMetrics(&off)
	if off.Len() != 0 || (&kubeRuntime{}).profilesStatus() != nil {
		t.Fatal("profile metrics without profiles")
	}
	discovery, err := kubediscovery.New(kubediscovery.Options{
		Server: "https://api.invalid", TokenFile: "token",
		Logger: slog.New(slog.DiscardHandler), Transport: http.DefaultTransport,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &kubeRuntime{discovery: discovery, proxy: &kubeproxy.Server{}}
	var on strings.Builder
	runtime.writeProfileMetrics(&on)
	for _, want := range []string{
		`meshgw_kube_profile_decisions_total{result="denied"} 0`, "meshgw_kube_discovery_fresh 0",
		"meshgw_kube_discovery_confirmed_timestamp_seconds 0", `meshgw_kube_discovery_fetches_total{outcome="failed"} 0`,
	} {
		if !strings.Contains(on.String(), want) {
			t.Errorf("missing %q in\n%s", want, on.String())
		}
	}
	if status := runtime.profilesStatus(); status == nil || status.DiscoveryFresh {
		t.Fatalf("status %+v", status)
	}
}

// The ceiling measurements' metrics, once a measurer runs.
func TestCeilingMetrics(t *testing.T) {
	t.Parallel()
	var off strings.Builder
	(&kubeRuntime{}).writeCeilingMetrics(&off)
	if off.Len() != 0 {
		t.Fatal("ceiling metrics without a measurer")
	}
	ceilings, err := rbaccheck.NewCeilings(rbaccheck.CeilingOptions{
		Groups: []rbaccheck.CeilingGroup{{Name: "view"}}, Reviewer: refusingRules{},
		Tokens: refusingRules{}, Passes: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ceilings.Measure(t.Context())
	var on strings.Builder
	(&kubeRuntime{ceilings: ceilings}).writeCeilingMetrics(&on)
	for _, want := range []string{
		"meshgw_kube_ceiling_measurements_total 1", "meshgw_kube_ceiling_duration_seconds ",
		"meshgw_kube_ceiling_bytes ", `meshgw_kube_ceiling_unmeasured_total{reason="unauthorized"} 1`,
		"meshgw_kube_ceiling_invalid_total 0",
	} {
		if !strings.Contains(on.String(), want) {
			t.Errorf("missing %q in\n%s", want, on.String())
		}
	}
}

// refusingRules refuses every token, and is its own token source.
type refusingRules struct{}

func (refusingRules) Token(context.Context, string) (string, error) { return "t", nil }

func (refusingRules) Forget(string, string) {}

func (refusingRules) RulesReview(context.Context, string, string) (rbaccheck.RulesAnswer, error) {
	return rbaccheck.RulesAnswer{}, rbaccheck.ErrUnauthorized
}
