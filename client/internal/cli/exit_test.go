package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

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
	calls     [][]string
	quiet     []bool
	output    string
	code      int
	delegated bool
}

func (routes *fakeRoutes) run(args []string, quiet bool, stdout, _ io.Writer) (int, bool) {
	routes.calls = append(routes.calls, append([]string(nil), args...))
	routes.quiet = append(routes.quiet, quiet)
	_, _ = io.WriteString(stdout, routes.output)
	return routes.code, routes.delegated
}

// statusSequence answers each Status with the next of statuses, the last
// one again once they run out.
type statusSequence struct {
	fakeClient
	statuses []localapi.Status
	asked    int
}

func (client *statusSequence) Status(context.Context) (localapi.Status, error) {
	if client.err != nil {
		return localapi.Status{}, client.err
	}
	status := client.statuses[min(client.asked, len(client.statuses)-1)]
	client.asked++
	return status, nil
}

func TestExitUseWaitsUntilTheChoiceApplies(t *testing.T) {
	t.Parallel()
	serving := localapi.Status{Exit: &localapi.ExitStatus{
		Use: "World", Pool: "p1", PoolName: "World",
		ExitNode: "d1", ExitNodeName: "poc-02", Via: "primary", Routing: true,
	}}
	for _, test := range []struct {
		name      string
		args      []string
		statuses  []localapi.Status
		delegated bool
		err       error
		want      string
		asked     int
	}{
		{
			"applies",
			[]string{"exit", "use", "World"},
			[]localapi.Status{{}, serving},
			false, nil,
			"Exit: via poc-02 in pool World; IPv6 blocked\n", 2,
		},
		{
			"off",
			[]string{"exit", "use", "off"},
			[]localapi.Status{serving, {}},
			false, nil,
			"Exit: off; this machine uses its own network again\n", 2,
		},
		{
			"refused",
			[]string{"exit", "use", "World"},
			[]localapi.Status{{Exit: &localapi.ExitStatus{Use: "World", Refused: "exit_use_off"}}},
			false, nil,
			"Exit: not routed: exit_use_off\n", 1,
		},
		{"run through sudo", []string{"exit", "use", "World"}, []localapi.Status{{}}, true, nil, "", 0},
		{"auto after a pool", []string{"exit", "use", "auto"}, []localapi.Status{
			serving,
			{Exit: &localapi.ExitStatus{Use: "auto", Pool: "p1", PoolName: "World", Routing: true}},
			{Exit: &localapi.ExitStatus{
				Use: "auto", Pool: "p1", PoolName: "World", ExitNode: "d1",
				ExitNodeName: "poc-02", Via: "primary", Routing: true, IPv6: true,
			}},
		}, false, nil, "Exit: via poc-02 in pool World\n", 3},
		{"off under a managed pool", []string{"exit", "use", "off"}, []localapi.Status{
			serving,
			{Exit: &localapi.ExitStatus{
				Use: "managed", Pool: "p1", PoolName: "World", ExitNode: "d1",
				ExitNodeName: "poc-02", Via: "primary", Routing: true, IPv6: true,
			}},
		}, false, nil, "Exit: off here; the administrator's pool applies: via poc-02 in pool World\n", 2},
		{
			"never applies",
			[]string{"exit", "use", "World"},
			[]localapi.Status{{}},
			false, nil,
			"Exit: not applied yet; meshctl exit status shows when it is\n", -1,
		},
		{
			"meshd down",
			[]string{"exit", "use", "World"},
			[]localapi.Status{{}},
			false, errors.New("no socket"),
			"Exit: saved; it applies when meshd runs\n", -1,
		},
	} {
		client := &statusSequence{statuses: test.statuses}
		client.err = test.err
		routes := &fakeRoutes{delegated: test.delegated}
		options := testOptions(client)
		options.Routes = routes.run
		options.ExitWait = 50 * time.Millisecond
		var stdout, stderr bytes.Buffer
		if code := Run(t.Context(), test.args, &stdout, &stderr, options); code != 0 {
			t.Fatalf("%s = %d: %s", test.name, code, stderr.String())
		}
		if got := stdout.String(); got != test.want || len(routes.quiet) != 1 || !routes.quiet[0] ||
			(test.asked >= 0 && client.asked != test.asked) {
			t.Errorf("%s: printed %q, quiet %v, asked %d", test.name, got, routes.quiet, client.asked)
		}
	}
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
