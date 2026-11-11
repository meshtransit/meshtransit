package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/cli/localapi"
)

func TestRun_Down(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		changed bool
		want    string
	}{
		{"disconnects", true, "Disconnected."},
		{"already down", false, "Already disconnected."},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeClient{connection: localapi.Connection{APIVersion: "v1", State: "down", Changed: test.changed}}
			var stdout, stderr bytes.Buffer
			if code := Run(t.Context(), []string{"down"}, &stdout, &stderr, testOptions(client)); code != 0 {
				t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.want) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), test.want)
			}
		})
	}
}

func TestRun_DownRejectsArgumentsAndOddStates(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"down", "now"}, &stdout, &stderr, testOptions(&fakeClient{})); code != 2 {
		t.Fatalf("exit with an argument = %d, want 2", code)
	}
	client := &fakeClient{connection: localapi.Connection{APIVersion: "v1", State: "sideways"}}
	if code := Run(t.Context(), []string{"down"}, &stdout, &stderr, testOptions(client)); code != 1 {
		t.Fatalf("exit for an unknown state = %d, want 1", code)
	}
}

func TestRun_Logout(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		result localapi.Logout
		want   string
	}{
		{"logged out", localapi.Logout{APIVersion: "v1", State: "logged_out"}, "Logged out"},
		{"already removed", localapi.Logout{APIVersion: "v1", State: "logged_out", AlreadyRemoved: true}, "already removed"},
		{"not registered", localapi.Logout{APIVersion: "v1", State: "not_registered"}, "not registered"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			client := &fakeClient{logout: test.result}
			if code := Run(t.Context(), []string{"logout"}, &stdout, &stderr, testOptions(client)); code != 0 {
				t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.want) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), test.want)
			}
		})
	}
	var stdout, stderr bytes.Buffer
	client := &fakeClient{logout: localapi.Logout{APIVersion: "v1", State: "logged_out"}}
	if code := Run(t.Context(), []string{"--json", "logout"}, &stdout, &stderr, testOptions(client)); code != 0 ||
		!strings.Contains(stdout.String(), `"state": "logged_out"`) {
		t.Fatalf("json logout exit = %d stdout=%s", code, stdout.String())
	}
}

// Schema 283: logout signs out and keeps the device; --remove and
// deregister remove it.
func TestRun_LogoutSignsOutUnlessRemoving(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		args      []string
		signedOut bool
		removed   bool
		result    localapi.Logout
		want      string
	}{
		{[]string{"logout"}, true, false, localapi.Logout{APIVersion: "v1", State: "signed_out"}, "Signed out"},
		{[]string{"logout", "--remove"}, false, true, localapi.Logout{APIVersion: "v1", State: "logged_out"}, "Logged out"},
		{[]string{"deregister"}, false, true, localapi.Logout{APIVersion: "v1", State: "logged_out"}, "Logged out"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			client := &fakeClient{logout: test.result}
			if code := Run(t.Context(), test.args, &stdout, &stderr, testOptions(client)); code != 0 {
				t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
			}
			if client.signedOut != test.signedOut || client.removed != test.removed ||
				!strings.Contains(stdout.String(), test.want) {
				t.Fatalf("signed out %t, removed %t, stdout %q", client.signedOut, client.removed, stdout.String())
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"logout", "--now"}, &stdout, &stderr, testOptions(&fakeClient{})); code != 2 {
		t.Fatalf("unknown flag exit = %d, want 2", code)
	}
}

// An older meshd has no /v1/sign-out: say what to do.
func TestRun_LogoutOnAnOlderMeshd(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	client := &fakeClient{err: fmt.Errorf("%w: POST /v1/sign-out", localapi.ErrEndpointMissing)}
	if code := Run(t.Context(), []string{"logout"}, &stdout, &stderr, testOptions(client)); code != 1 ||
		!strings.Contains(stderr.String(), "logout --remove") {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
}

// Design §7: login --new-account has meshd add an account (pinned with the
// same key before it becomes active), then signs in to it.
func TestRun_LoginNewAccount(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	client := &fakeClient{
		added: localapi.AccountAdded{
			APIVersion: "v1",
			Profile:    localapi.Profile{ID: "p2", Name: "Cloud 2"},
			Previous:   localapi.Profile{ID: "p1", Name: "Cloud"},
		},
		login: localapi.Login{APIVersion: "v1", State: "registered"},
	}
	if code := Run(t.Context(), []string{"login", "--new-account", "--name", "Work"}, &stdout, &stderr,
		testOptions(client)); code != 0 {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if strings.Join(client.addedWith, ",") != "Work" || !strings.Contains(stdout.String(), `"Cloud" keeps its device`) ||
		!strings.Contains(stdout.String(), "meshctl profile use p1") {
		t.Fatalf("added with %v, stdout %q", client.addedWith, stdout.String())
	}
	if code := Run(t.Context(), []string{"login", "--name", "Work"}, &stdout, &stderr,
		testOptions(&fakeClient{})); code != 2 {
		t.Fatalf("--name without --new-account exit = %d, want 2", code)
	}
}

// A refusal stops before any sign-in; an older meshd says to update it.
func TestRun_LoginNewAccountFailures(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err  error
		says string
	}{
		{&localapi.APIError{
			StatusCode: http.StatusConflict, Code: "add_account_no_device",
			Message: "the account in use has no device yet: sign in to it first",
		}, "no device yet"},
		{fmt.Errorf("%w: POST /v1/accounts", localapi.ErrEndpointMissing), "update it first"},
		// A new meshd's own 404 (the new profile went away) is its answer,
		// not a sign of an older meshd.
		{
			&localapi.APIError{StatusCode: http.StatusNotFound, Code: "profile_not_found", Message: "profile not found"},
			"profile not found",
		},
	} {
		var stdout, stderr bytes.Buffer
		client := &fakeClient{addErr: test.err, login: localapi.Login{APIVersion: "v1", State: "registered"}}
		if code := Run(t.Context(), []string{"login", "--new-account"}, &stdout, &stderr, testOptions(client)); code == 0 ||
			!strings.Contains(stderr.String(), test.says) || strings.Contains(stdout.String(), "Registered") {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", test.err, code, stdout.String(), stderr.String())
		}
	}
}

// Design §7: profile remove takes an id or a name, with --local before or
// after it, and says what became of the Device.
func TestRun_ProfileRemove(t *testing.T) {
	t.Parallel()
	profiles := localapi.Profiles{APIVersion: "v1", Profiles: []localapi.Profile{
		{ID: "p1", Name: "Cloud", IsActive: true},
		{ID: "p2", Name: "Cloud 2"},
	}}
	for _, test := range []struct {
		args   []string
		device string
		local  bool
		says   string
	}{
		{[]string{"profile", "remove", "p2"}, "removed", false, "and its device from the Network"},
		{[]string{"profile", "remove", "cloud 2"}, "already_removed", false, "had already been removed"},
		{[]string{"profile", "remove", "--local", "Cloud 2"}, "left", true, "an administrator removes it"},
		{[]string{"profile", "remove", "Cloud 2", "--local"}, "left", true, "this machine only"},
		{[]string{"profile", "remove", "p2"}, "none", false, "it had no device"},
		{[]string{"profile", "remove", "p2"}, "pending", false, "do not approve that link"},
		// After "--" nothing is a flag.
		{[]string{"profile", "remove", "--local", "--", "p2"}, "left", true, "this machine only"},
	} {
		var stdout, stderr bytes.Buffer
		client := &fakeClient{profiles: profiles, removal: localapi.ProfileRemoval{
			APIVersion: "v1", Profile: localapi.Profile{ID: "p2", Name: "Cloud 2"}, Device: test.device,
		}}
		if code := Run(t.Context(), test.args, &stdout, &stderr, testOptions(client)); code != 0 ||
			strings.Join(client.removedProfiles, ",") != "p2" || client.removedLocal[0] != test.local ||
			!strings.Contains(stdout.String(), test.says) {
			t.Fatalf("%v: exit %d, removed %v %v, stdout %q, stderr %q", test.args, code, client.removedProfiles,
				client.removedLocal, stdout.String(), stderr.String())
		}
	}
	for _, args := range [][]string{
		{"profile", "remove"},
		{"profile", "remove", "p1", "p2"},
		{"profile", "remove", "--force", "p2"},
		{"profile", "remove", "--", "p2", "--local"},
	} {
		var stdout, stderr bytes.Buffer
		client := &fakeClient{profiles: profiles}
		if code := Run(t.Context(), args, &stdout, &stderr, testOptions(client)); code != 2 ||
			len(client.removedProfiles) != 0 {
			t.Fatalf("%v: exit %d, removed %v", args, code, client.removedProfiles)
		}
	}
	var stdout, stderr bytes.Buffer
	client := &fakeClient{profiles: profiles}
	if code := Run(t.Context(), []string{"profile", "remove", "nope"}, &stdout, &stderr, testOptions(client)); code != 1 ||
		len(client.removedProfiles) != 0 || !strings.Contains(stderr.String(), "no profile") {
		t.Fatalf("unknown profile: exit %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	client = &fakeClient{profiles: profiles, removeErr: &localapi.APIError{
		StatusCode: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "method not allowed",
	}}
	if code := Run(t.Context(), []string{"profile", "remove", "p2"}, &stdout, &stderr, testOptions(client)); code != 1 ||
		!strings.Contains(stderr.String(), "update it first") {
		t.Fatalf("older meshd: exit %d, stderr %q", code, stderr.String())
	}
}

// TD-CLI-102: login waits for the first map and prints the addresses; it
// says why when meshd stays down or is stopped, and never fails the login.
func TestRun_LoginPrintsTheAddressesOnceConnected(t *testing.T) {
	t.Parallel()
	ready := localapi.Status{
		APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "synchronized",
		SelfAddresses: []string{"100.64.1.3/32", "fd07::3/128"},
	}
	for _, test := range []struct {
		name     string
		statuses []localapi.Status
		says     string
	}{
		{"connected after a while", []localapi.Status{
			{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "connecting"}, ready,
		}, "Connected. Addresses: 100.64.1.3/32, fd07::3/128."},
		{
			"down",
			[]localapi.Status{{APIVersion: "v1", ActiveProfileID: "p1", Disconnected: true}},
			"meshctl up connects",
		},
		{
			"down on an older meshd",
			[]localapi.Status{{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "down"}},
			"meshctl up connects",
		},
		{"suspended", []localapi.Status{
			{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "connecting"},
			{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "suspended"},
		}, "Not connected (suspended)"},
		// Blocked before the login, then connected: not a failure.
		{"stale blocked", []localapi.Status{
			{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "blocked"},
			{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "connecting"},
			ready,
		}, "Connected. Addresses:"},
		{
			"blocked throughout",
			[]localapi.Status{{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "blocked"}},
			"Still connecting",
		},
		{
			"never connects",
			[]localapi.Status{{APIVersion: "v1", ActiveProfileID: "p1", ControlSession: "connecting"}},
			"Still connecting",
		},
		// Another profile became active meanwhile: its addresses are not ours.
		{"another profile", []localapi.Status{{
			APIVersion: "v1", ActiveProfileID: "p9", ControlSession: "synchronized",
			SelfAddresses: []string{"100.64.9.9/32"},
		}}, "Still connecting"},
	} {
		var stdout, stderr bytes.Buffer
		client := &fakeClient{statuses: test.statuses, login: localapi.Login{
			APIVersion: "v1", State: "registered",
			ProfileID: "p1",
		}}
		options := testOptions(client)
		options.ConnectWait = 600 * time.Millisecond
		if code := Run(t.Context(), []string{"login"}, &stdout, &stderr, options); code != 0 ||
			!strings.Contains(stdout.String(), "Registered active profile p1.\nConnecting...") ||
			!strings.Contains(stdout.String(), test.says) {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", test.name, code, stdout.String(), stderr.String())
		}
	}
	// The browser path and login complete print the addresses too.
	for _, args := range [][]string{{"login"}, {"login", "complete"}} {
		var stdout, stderr bytes.Buffer
		client := &fakeClient{
			status: ready, login: localapi.Login{
				APIVersion: "v1", State: "authorization_required",
				AuthURL: "https://control.example.com/register/v1/x",
			},
			completedLogin: localapi.Login{APIVersion: "v1", State: "registered", ProfileID: "p1"},
		}
		if args[len(args)-1] == "complete" {
			client.login = client.completedLogin
		}
		options := testOptions(client)
		options.ConnectWait = 600 * time.Millisecond
		if code := Run(t.Context(), args, &stdout, &stderr, options); code != 0 ||
			!strings.Contains(stdout.String(), "Connected. Addresses:") {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, code, stdout.String(), stderr.String())
		}
	}
	// Cancelled while waiting: the login succeeded, nothing more is said.
	ctx, cancel := context.WithCancel(t.Context())
	var stdout, stderr bytes.Buffer
	client := &fakeClient{
		status: localapi.Status{ActiveProfileID: "p1", ControlSession: "connecting"},
		login:  localapi.Login{APIVersion: "v1", State: "registered", ProfileID: "p1"},
	}
	options := testOptions(client)
	options.ConnectWait = 5 * time.Second
	time.AfterFunc(100*time.Millisecond, cancel)
	if code := Run(ctx, []string{"login"}, &stdout, &stderr, options); code != 0 ||
		strings.Contains(stdout.String(), "Still connecting") {
		t.Fatalf("cancelled: exit %d, stdout %q", code, stdout.String())
	}
	// JSON output stays one object.
	stdout.Reset()
	client = &fakeClient{status: ready, login: localapi.Login{APIVersion: "v1", State: "registered", ProfileID: "p1"}}
	options = testOptions(client)
	options.ConnectWait = 600 * time.Millisecond
	if code := Run(t.Context(), []string{"--json", "login"}, &stdout, &stderr, options); code != 0 ||
		strings.Contains(stdout.String(), "Connected.") || strings.Contains(stdout.String(), "Connecting") {
		t.Fatalf("json login: exit %d, stdout %q", code, stdout.String())
	}
}

func TestRun_StatusOfASignedOutMachine(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	client := &fakeClient{status: localapi.Status{
		APIVersion: "v1", Registration: "signed_out",
		DeviceExpiry: "unknown",
	}}
	if code := Run(t.Context(), []string{"status"}, &stdout, &stderr, testOptions(client)); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Self addresses: kept in the Network while signed out") ||
		!strings.Contains(out, "Device expiry: not applicable while signed out") || strings.Contains(out, "Network: ") {
		t.Fatalf("status = %q", out)
	}
}

func TestRun_DownOfASignedOutMachineSaysToSignIn(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	client := &fakeClient{
		connection: localapi.Connection{APIVersion: "v1", State: "down", Changed: true},
		status:     localapi.Status{APIVersion: "v1", Registration: "signed_out"},
	}
	if code := Run(t.Context(), []string{"down"}, &stdout, &stderr, testOptions(client)); code != 0 ||
		!strings.Contains(stdout.String(), "This machine is also signed out: meshctl login") {
		t.Fatalf("exit %d, stdout %q", code, stdout.String())
	}
	stdout.Reset()
	client.status.Registration = "registered"
	if code := Run(t.Context(), []string{"down"}, &stdout, &stderr, testOptions(client)); code != 0 ||
		strings.Contains(stdout.String(), "signed out") {
		t.Fatalf("registered down: exit %d, stdout %q", code, stdout.String())
	}
}
