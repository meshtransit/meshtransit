package meshgw

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/kubediscovery"
	"meshtransit.net/client/internal/kubeproxy"
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
