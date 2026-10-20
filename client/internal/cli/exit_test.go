package cli

import (
	"bytes"
	"strings"
	"testing"

	"meshtransit.net/client/internal/cli/localapi"
)

func TestExitApprove(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"exit", "approve", "d2"}, &stdout, &stderr, testOptions(&fakeClient{})); code != 0 {
		t.Fatalf("exit approve = %d: %s", code, stderr.String())
	}
	if got := stdout.String(); got != "Approved in pool p1: d2.\n" {
		t.Fatalf("output = %q", got)
	}
	stdout.Reset()
	for _, args := range [][]string{{"exit"}, {"exit", "approve"}} {
		if code := Run(t.Context(), args, &stdout, &stderr, testOptions(&fakeClient{})); code != 2 {
			t.Fatalf("%v = %d", args, code)
		}
	}
	status := &localapi.ExitStatus{
		Use: "p1", Pool: "p1", ExitNode: "d1", Via: "primary", IPv6: true, Routing: true,
		Pending: []string{"d2"}, PendingNames: []string{"ams"},
	}
	if got := formatExitStatus(status); !strings.HasSuffix(got, "new exit nodes wait for meshctl exit approve ID: ams (d2)") {
		t.Fatalf("status = %q", got)
	}
}
