package cli

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

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
	client := &fakeClient{err: &localapi.APIError{StatusCode: http.StatusNotFound, Code: "not_found"}}
	if code := Run(t.Context(), []string{"logout"}, &stdout, &stderr, testOptions(client)); code != 1 ||
		!strings.Contains(stderr.String(), "logout --remove") {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
}

// Design §7: login --new-account adds a profile for the same server, makes
// it active and pins the same control key before signing in.
func TestRun_LoginNewAccount(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	client := &fakeClient{
		status: localapi.Status{APIVersion: "v1", ActiveProfileID: "p1", ControlFingerprint: "sha256:abc"},
		profiles: localapi.Profiles{APIVersion: "v1", Profiles: []localapi.Profile{
			{ID: "p1", Name: "Cloud", ControlURL: "https://control.example.com", IsActive: true},
			{ID: "p0", Name: "Cloud 2", ControlURL: "https://control.example.com"},
		}},
		created: localapi.Profile{ID: "p2", Name: "Cloud 3"},
		login:   localapi.Login{APIVersion: "v1", State: "registered"},
	}
	if code := Run(t.Context(), []string{"login", "--new-account"}, &stdout, &stderr, testOptions(client)); code != 0 {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if client.createdWith.Name != "Cloud 3" || client.createdWith.ControlURL != "https://control.example.com" ||
		client.activatedID != "p2" || client.trustedWith != "sha256:abc" {
		t.Fatalf("created %+v, activated %q, trusted %q", client.createdWith, client.activatedID, client.trustedWith)
	}
	if code := Run(t.Context(), []string{"login", "--name", "Work"}, &stdout, &stderr,
		testOptions(&fakeClient{})); code != 2 {
		t.Fatalf("--name without --new-account exit = %d, want 2", code)
	}
}

// A failed pin goes back to the previous profile; a profile still without
// a Device is where to sign in.
func TestRun_LoginNewAccountFailures(t *testing.T) {
	t.Parallel()
	listing := func(state string) localapi.Profiles {
		return localapi.Profiles{APIVersion: "v1", Profiles: []localapi.Profile{
			{ID: "p1", Name: "Cloud", ControlURL: "https://control.example.com", IsActive: true, State: state},
		}}
	}
	status := localapi.Status{APIVersion: "v1", ActiveProfileID: "p1", ControlFingerprint: "sha256:abc"}
	var stdout, stderr bytes.Buffer
	client := &fakeClient{status: status, profiles: listing("registered"), created: localapi.Profile{
		ID:   "p2",
		Name: "Cloud 2",
	}, trustErr: errors.New("control unreachable")}
	if code := Run(t.Context(), []string{"login", "--new-account"}, &stdout, &stderr, testOptions(client)); code == 0 ||
		strings.Join(client.activatedIDs, ",") != "p2,p1" || !strings.Contains(stderr.String(), "active again") {
		t.Fatalf("exit %d, activated %v, stderr %q", code, client.activatedIDs, stderr.String())
	}
	stderr.Reset()
	client = &fakeClient{status: status, profiles: listing("unregistered")}
	if code := Run(t.Context(), []string{"login", "--new-account"}, &stdout, &stderr, testOptions(client)); code == 0 ||
		client.createdWith.Name != "" || !strings.Contains(stderr.String(), "no device yet") {
		t.Fatalf("exit %d, created %+v, stderr %q", code, client.createdWith, stderr.String())
	}
}

func TestNextAccountName(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("é", 64)
	for _, test := range []struct {
		current string
		taken   []string
		want    string
	}{
		{"Cloud", []string{"cloud"}, "Cloud 2"},
		{"Cloud 2", []string{"cloud", "cloud 2"}, "Cloud 3"},
		{"Cloud", []string{"cloud", "CLOUD 2"}, "Cloud 3"},
		{long, nil, strings.Repeat("é", 62) + " 2"},
	} {
		taken := map[string]bool{}
		for _, name := range test.taken {
			taken[strings.ToLower(name)] = true
		}
		if got := nextAccountName(test.current, taken); got != test.want {
			t.Errorf("nextAccountName(%q) = %q, want %q", test.current, got, test.want)
		}
	}
}
