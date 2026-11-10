package cli

import (
	"bytes"
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
