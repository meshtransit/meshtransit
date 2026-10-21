package cli

import (
	"bytes"
	"io"
	"slices"
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

// fakeRoutes records what meshctl asks of the host's route settings.
type fakeRoutes struct {
	calls  [][]string
	output string
	code   int
}

func (routes *fakeRoutes) run(args []string, stdout, _ io.Writer) int {
	routes.calls = append(routes.calls, append([]string(nil), args...))
	_, _ = io.WriteString(stdout, routes.output)
	return routes.code
}

func TestExitUseAndServeChangeTheHostSettings(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		args []string
		want []string
	}{
		{[]string{"exit", "use", "World"}, []string{"exit-use", "World"}},
		{[]string{"exit", "use", "auto"}, []string{"exit-use", "auto"}},
		{[]string{"exit", "use", "off"}, []string{"exit-use", "off"}},
		{[]string{"exit", "serve", "on"}, []string{"exit-mode", "on"}},
		{[]string{"exit", "serve", "off"}, []string{"exit-mode", "off"}},
		{[]string{"routes", "accept", "on"}, []string{"accept", "on"}},
		{[]string{"routes", "show"}, []string{"show"}},
	} {
		routes := &fakeRoutes{}
		options := testOptions(&fakeClient{})
		options.Routes = routes.run
		var stdout, stderr bytes.Buffer
		if code := Run(t.Context(), test.args, &stdout, &stderr, options); code != 0 {
			t.Fatalf("%v = %d: %s", test.args, code, stderr.String())
		}
		if len(routes.calls) != 1 || !slices.Equal(routes.calls[0], test.want) {
			t.Fatalf("%v asked %v, want %v", test.args, routes.calls, test.want)
		}
	}
	for _, args := range [][]string{
		{"exit", "use"},
		{"exit", "use", "a", "b"},
		{"exit", "serve"},
		{"exit", "serve", "maybe"},
		{"exit", "nothing"},
		{"routes"},
	} {
		routes := &fakeRoutes{}
		options := testOptions(&fakeClient{})
		options.Routes = routes.run
		var stdout, stderr bytes.Buffer
		if code := Run(t.Context(), args, &stdout, &stderr, options); code != 2 || len(routes.calls) != 0 {
			t.Fatalf("%v = %d after %v", args, code, routes.calls)
		}
	}
	// No JSON: refused rather than answered in text.
	for _, args := range [][]string{{"--json", "routes", "show"}, {"--json", "exit", "use", "World"}, {"--json", "exit", "status"}} {
		routes := &fakeRoutes{}
		options := testOptions(&fakeClient{})
		options.Routes = routes.run
		var stdout, stderr bytes.Buffer
		if code := Run(t.Context(), args, &stdout, &stderr, options); code != 2 || len(routes.calls) != 0 {
			t.Fatalf("%v = %d after %v", args, code, routes.calls)
		}
	}
	// A failed change is the command's failure.
	options := testOptions(&fakeClient{})
	options.Routes = (&fakeRoutes{code: 1}).run
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"exit", "use", "World"}, &stdout, &stderr, options); code != 1 {
		t.Fatalf("failed change = %d", code)
	}
	// Without a way to change them, meshctl says so.
	options.Routes = nil
	stderr.Reset()
	if code := Run(t.Context(), []string{"exit", "use", "World"}, &stdout, &stderr, options); code != 1 ||
		!strings.Contains(stderr.String(), "cannot change") {
		t.Fatalf("no routes = %d: %s", code, stderr.String())
	}
}

func TestExitStatusShowsTheHostChoiceAndTheExitInUse(t *testing.T) {
	t.Parallel()
	routes := &fakeRoutes{output: "accept: on\nrouter-mode: off\nexit-mode: off\nexit-use: World\nexit-allow-lan: off\n"}
	options := testOptions(&fakeClient{})
	options.Routes = routes.run
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"exit", "status"}, &stdout, &stderr, options); code != 0 {
		t.Fatalf("exit status = %d: %s", code, stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "exit-use: World\n") || strings.Contains(got, "accept: on") ||
		!strings.Contains(got, "Exit: ") {
		t.Fatalf("exit status = %q", got)
	}
}

func TestExitStatusStillAsksTheDaemonWhenSettingsCannotBeRead(t *testing.T) {
	t.Parallel()
	options := testOptions(&fakeClient{})
	options.Routes = (&fakeRoutes{code: 1}).run
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"exit", "status"}, &stdout, &stderr, options); code != 0 ||
		!strings.Contains(stdout.String(), "Exit: ") || strings.Contains(stdout.String(), "exit-use") {
		t.Fatalf("exit status = %d: %q", code, stdout.String())
	}
}
