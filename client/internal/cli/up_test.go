package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/client/internal/cli/localapi"
)

const testCloudFingerprint = "sha256:9af0dbfdffaca2f5e428a33b9dfdd57e46aafd0b41010bfbb08daaf508f18f3a"

// upFakeClient models the daemon state that meshctl up walks through.
type upFakeClient struct {
	profiles     []localapi.Profile
	registration string
	network      string
	pinned       string
	loginState   string
	trustErr     error

	created     []localapi.CreateProfile
	activated   []string
	trustedWith []string
	loginCalls  int
	completed   int
	upCalls     int
	upChanged   bool
}

func (f *upFakeClient) Down(context.Context) (localapi.Connection, error) {
	return localapi.Connection{APIVersion: "v1", State: "down"}, nil
}

func (f *upFakeClient) Up(context.Context) (localapi.Connection, error) {
	f.upCalls++
	return localapi.Connection{APIVersion: "v1", State: "up", Changed: f.upChanged}, nil
}

func (f *upFakeClient) Logout(context.Context) (localapi.Logout, error) {
	return localapi.Logout{APIVersion: "v1", State: "not_registered"}, nil
}

func (f *upFakeClient) Status(context.Context) (localapi.Status, error) {
	status := localapi.Status{APIVersion: "v1", Registration: f.registration, NetworkName: f.network}
	for _, profile := range f.profiles {
		if profile.IsActive {
			status.ActiveProfileID = profile.ID
		}
	}

	return status, nil
}

func (f *upFakeClient) ListProfiles(context.Context) (localapi.Profiles, error) {
	return localapi.Profiles{APIVersion: "v1", Profiles: append([]localapi.Profile(nil), f.profiles...)}, nil
}

func (f *upFakeClient) CreateProfile(_ context.Context, input localapi.CreateProfile) (localapi.Profile, error) {
	f.created = append(f.created, input)
	profile := localapi.Profile{ID: "new-profile", Name: input.Name, ControlURL: input.ControlURL}
	f.profiles = append(f.profiles, profile)

	return profile, nil
}

func (f *upFakeClient) ActivateProfile(_ context.Context, id string) (localapi.Profile, error) {
	f.activated = append(f.activated, id)
	var selected localapi.Profile
	for index := range f.profiles {
		f.profiles[index].IsActive = f.profiles[index].ID == id
		if f.profiles[index].IsActive {
			selected = f.profiles[index]
		}
	}

	return selected, nil
}

func (*upFakeClient) ProbeControl(context.Context) (localapi.ControlProbe, error) {
	return localapi.ControlProbe{}, nil
}

func (f *upFakeClient) TrustControl(_ context.Context, fingerprint string) (localapi.ControlTrust, error) {
	f.trustedWith = append(f.trustedWith, fingerprint)
	if f.trustErr != nil {
		return localapi.ControlTrust{}, f.trustErr
	}
	already := f.pinned == fingerprint
	f.pinned = fingerprint

	return localapi.ControlTrust{Fingerprint: fingerprint, AlreadyPinned: already}, nil
}

func (f *upFakeClient) StartLogin(context.Context, string) (localapi.Login, error) {
	f.loginCalls++

	return localapi.Login{State: f.loginState, AuthURL: "https://control.example.test/register/v1/token"}, nil
}

func (f *upFakeClient) CompleteLogin(context.Context) (localapi.Login, error) {
	f.completed++
	f.registration = "registered"

	return localapi.Login{State: "registered", ProfileID: "new-profile"}, nil
}

func (*upFakeClient) RotateNodeKey(context.Context) (localapi.NodeKeyRotation, error) {
	return localapi.NodeKeyRotation{}, nil
}

func (*upFakeClient) RefreshNAT(context.Context) (localapi.Netcheck, error) {
	return localapi.Netcheck{}, nil
}

func (*upFakeClient) ApproveExitNodes(context.Context, []string) (localapi.ExitApproval, error) {
	return localapi.ExitApproval{}, nil
}

var _ DaemonClient = (*upFakeClient)(nil)

func runUpCommand(t *testing.T, client DaemonClient, args ...string) (int, string, string) {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Run(t.Context(), append([]string{"up"}, args...), stdout, stderr, testOptions(client))

	return code, stdout.String(), stderr.String()
}

func TestUpConnectsANewMachineToMeshTransitCloud(t *testing.T) {
	t.Parallel()
	client := &upFakeClient{registration: "unregistered", loginState: "authorization_required"}

	code, stdout, stderr := runUpCommand(t, client)
	if code != 0 {
		t.Fatalf("up exit = %d, stderr = %s", code, stderr)
	}
	if len(client.created) != 1 || client.created[0].ControlURL != DefaultControlURL ||
		client.created[0].Name != "MeshTransit" {
		t.Fatalf("created profiles = %+v", client.created)
	}
	if len(client.activated) != 1 || client.activated[0] != "new-profile" {
		t.Fatalf("activated = %v", client.activated)
	}
	if len(client.trustedWith) != 1 || client.trustedWith[0] != DefaultControlKeyFingerprint {
		t.Fatalf("trusted with = %v, want the built-in Cloud fingerprint", client.trustedWith)
	}
	if client.loginCalls != 1 || client.completed == 0 {
		t.Fatalf("login calls = %d, completions = %d", client.loginCalls, client.completed)
	}
	for _, want := range []string{"https://control.example.test/register/v1/token", "Connected"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestUpIsIdempotentOnAConnectedMachine(t *testing.T) {
	t.Parallel()
	client := &upFakeClient{
		profiles: []localapi.Profile{
			{ID: "old", Name: "Old", ControlURL: "https://old.example.test"},
			{ID: "cloud", Name: "MeshTransit", ControlURL: "https://control.meshtransit.net/", IsActive: true},
		},
		registration: "registered",
		network:      "consumer-net.mesh",
		pinned:       DefaultControlKeyFingerprint,
	}

	code, stdout, stderr := runUpCommand(t, client)
	if code != 0 {
		t.Fatalf("up exit = %d, stderr = %s", code, stderr)
	}
	if len(client.created) != 0 || len(client.activated) != 0 || client.loginCalls != 0 {
		t.Fatalf("connected machine changed: created=%v activated=%v logins=%d",
			client.created, client.activated, client.loginCalls)
	}
	if !strings.Contains(stdout, "Already connected") || !strings.Contains(stdout, "consumer-net.mesh") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestUpReconnectsAMachineThatWasDown(t *testing.T) {
	t.Parallel()
	client := &upFakeClient{
		profiles: []localapi.Profile{
			{ID: "cloud", Name: "MeshTransit", ControlURL: "https://control.meshtransit.net/", IsActive: true},
		},
		registration: "registered",
		network:      "consumer-net.mesh",
		pinned:       DefaultControlKeyFingerprint,
		upChanged:    true,
	}

	code, stdout, stderr := runUpCommand(t, client)
	if code != 0 {
		t.Fatalf("up exit = %d, stderr = %s", code, stderr)
	}
	if client.upCalls != 1 || client.loginCalls != 0 {
		t.Fatalf("up calls = %d, logins = %d; want the down cleared without a login", client.upCalls, client.loginCalls)
	}
	if !strings.Contains(stdout, "Connected again") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestUpReusesAnInactiveProfileForTheSameServer(t *testing.T) {
	t.Parallel()
	client := &upFakeClient{
		profiles: []localapi.Profile{
			{ID: "other", Name: "Other", ControlURL: "https://other.example.test", IsActive: true},
			{ID: "cloud", Name: "MeshTransit", ControlURL: "https://control.meshtransit.net"},
		},
		registration: "registered",
		pinned:       DefaultControlKeyFingerprint,
		loginState:   "registered",
	}

	code, _, stderr := runUpCommand(t, client)
	if code != 0 {
		t.Fatalf("up exit = %d, stderr = %s", code, stderr)
	}
	if len(client.created) != 0 || len(client.activated) != 1 || client.activated[0] != "cloud" {
		t.Fatalf("created=%v activated=%v", client.created, client.activated)
	}
}

func TestUpRequiresAFingerprintForAnotherServer(t *testing.T) {
	t.Parallel()
	client := &upFakeClient{registration: "unregistered", loginState: "authorization_required"}

	code, _, stderr := runUpCommand(t, client, "--server", "https://mesh.example.test")
	if code != 2 || !strings.Contains(stderr, "--fingerprint") {
		t.Fatalf("up exit = %d, stderr = %s", code, stderr)
	}
	if len(client.created) != 0 {
		t.Fatal("a profile was created without a way to verify the server")
	}

	code, _, stderr = runUpCommand(t, client, "--server", "https://mesh.example.test/", "--fingerprint", testCloudFingerprint,
		"--no-wait")
	if code != 0 {
		t.Fatalf("self-hosted up exit = %d, stderr = %s", code, stderr)
	}
	if client.created[0].ControlURL != "https://mesh.example.test" || client.created[0].Name != "mesh.example.test" {
		t.Fatalf("created = %+v", client.created)
	}
	if client.completed != 0 {
		t.Fatal("--no-wait still waited for approval")
	}
}

func TestUpRejectsUnsafeServers(t *testing.T) {
	t.Parallel()
	for _, server := range []string{
		"http://control.example.test",
		"https://control.example.test/path",
		"https://user@control.example.test",
		"https://control.example.test?x=1",
		"control.example.test",
	} {
		t.Run(server, func(t *testing.T) {
			t.Parallel()
			client := &upFakeClient{}
			code, _, stderr := runUpCommand(t, client, "--server", server, "--fingerprint", testCloudFingerprint)
			if code != 2 || len(client.created) != 0 {
				t.Fatalf("up %s exit = %d, stderr = %s", server, code, stderr)
			}
		})
	}
}

func TestUpStopsWhenTheServerKeyDoesNotMatch(t *testing.T) {
	t.Parallel()
	client := &upFakeClient{
		registration: "unregistered",
		loginState:   "authorization_required",
		trustErr:     errors.New("control key fingerprint mismatch"),
	}

	code, _, stderr := runUpCommand(t, client)
	if code != 1 || !strings.Contains(stderr, "fingerprint mismatch") || client.loginCalls != 0 {
		t.Fatalf("up exit = %d, logins = %d, stderr = %s", code, client.loginCalls, stderr)
	}
}
