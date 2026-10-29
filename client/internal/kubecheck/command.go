package kubecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// The pod's own ServiceAccount files and termination message.
const (
	caFile          = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenFile       = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- a path
	terminationFile = "/dev/termination-log"
)

// Main runs `meshgw check [--preflight]`: the JSON report on stdout, its
// summary as the pod's termination message and in an Event on the gateway's
// StatefulSet, exit 1 on a failure and 2 on a bad call or configuration.
func Main(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer,
	audiences func(string) ([]string, error),
) int {
	preflight := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--preflight":
		preflight = true
	default:
		_, _ = fmt.Fprintln(stderr, "usage: meshgw check [--preflight]")
		return 2
	}
	config, err := ParseConfig(getenv("MESHGW_CHECK_CONFIG"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	api, err := NewInCluster(getenv, caFile, tokenFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	checker := Checker{
		Config: config, API: api, Status: FetchStatus,
		Audiences: func() ([]string, error) { return audiences(tokenFile) },
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var report Report
	if preflight {
		report = checker.Preflight(ctx)
	} else {
		report = checker.Run(ctx)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(report)
	summary := report.Summary()
	_ = os.WriteFile(terminationFile, []byte(summary), 0o600)
	if err := checker.recordEvent(ctx, preflight, report, summary); err != nil {
		_, _ = fmt.Fprintln(stderr, "kubecheck: recording the result:", err)
	}
	if report.Failed() {
		return 1
	}
	return 0
}

// recordEvent leaves the result on the gateway's StatefulSet, where
// `kubectl describe` shows it after the hook's Job is gone (review v2 M5).
func (checker Checker) recordEvent(ctx context.Context, preflight bool, report Report, summary string) error {
	reason, kind := "MeshgwCheck", "Normal"
	if preflight {
		reason = "MeshgwPreflight"
	}
	if report.Failed() {
		kind = "Warning"
	}
	if len(summary) > 1000 {
		summary = summary[:1000] + "…"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	event := map[string]any{
		"apiVersion": "v1", "kind": "Event",
		"metadata": map[string]any{"generateName": checker.Config.StatefulSet + "-check-"},
		"involvedObject": map[string]any{
			"apiVersion": "apps/v1", "kind": "StatefulSet",
			"name": checker.Config.StatefulSet, "namespace": checker.Config.Namespace,
		},
		"reason": reason, "type": kind, "message": strings.TrimSpace(summary),
		"source":         map[string]any{"component": "meshgw-check"},
		"firstTimestamp": now, "lastTimestamp": now, "count": 1,
	}
	return checker.API.Post(ctx, checker.path("/api/v1/namespaces/%s/events", checker.Config.Namespace), event)
}
