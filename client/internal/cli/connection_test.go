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
		strings.Join(client.activatedIDs, ",") != "p2,p1" || !strings.Contains(stderr.String(), "active again") ||
		strings.Join(client.removedProfiles, ",") != "p2" || !client.removedLocal[0] ||
		!strings.Contains(stderr.String(), "nothing was added") {
		t.Fatalf("exit %d, activated %v, removed %v, stderr %q", code, client.activatedIDs, client.removedProfiles,
			stderr.String())
	}
	// The unused profile cannot be dropped either: say how.
	stderr.Reset()
	client = &fakeClient{status: status, profiles: listing("registered"), created: localapi.Profile{
		ID:   "p2",
		Name: "Cloud 2",
	}, trustErr: errors.New("control unreachable"), removeErr: errors.New("busy")}
	if code := Run(t.Context(), []string{"login", "--new-account"}, &stdout, &stderr, testOptions(client)); code == 0 ||
		!strings.Contains(stderr.String(), "meshctl profile remove p2") {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
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
