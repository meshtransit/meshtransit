package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshctl/internal/localapi"
	"github.com/meshtransit/meshctl/internal/version"
)

func TestRun_Version(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"version"},
		stdout,
		stderr,
		testOptions(&fakeClient{}),
	)
	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
	}
	if got, expected := stdout.String(), "test (commit abc123, built 2026-09-09T00:00:00Z)\n"; got != expected {
		t.Fatalf("version output = %q, want %q", got, expected)
	}
}

func TestRun_Status(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		status: localapi.Status{
			APIVersion:      "v1",
			Daemon:          localapi.VersionInfo{Version: "dev"},
			State:           "offline",
			DataPlane:       "not_implemented",
			DNS:             "not_implemented",
			ProfileCount:    0,
			ControlSession:  "synchronized",
			NetmapRevision:  9,
			NetworkName:     "network.example.mesh",
			SelfAddresses:   []string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128"},
			PeerCount:       2,
			PolicyRuleCount: 3,
			PeerPaths: localapi.PathStatus{
				Available:   true,
				PeerCount:   2,
				DirectCount: 1,
				RelayCount:  1,
			},
			Relay: localapi.RelayStatus{
				Available:        true,
				HomeRegion:       7,
				ActiveRegions:    2,
				ConnectedRegions: 1,
			},
			NetworkChanges: localapi.NetworkChangeStatus{
				Available:         true,
				Observed:          4,
				EndpointRefreshes: 3,
			},
			Runtime: &localapi.RuntimeStatus{
				Goroutines:     11,
				HeapAllocBytes: 12582912,
				SysBytes:       25165824,
				GCCycles:       7,
			},
			CompatibilityNote: "foundation only",
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"status"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
	}
	for _, expected := range []string{
		"State: offline",
		"Data plane: not_implemented",
		"DNS: not_implemented",
		"Network changes: 4 observed (3 endpoint refreshes)",
		"Runtime: 11 goroutines, 12.0 MiB heap allocated, 24.0 MiB system, 7 GC cycles",
		"Active profile: none",
		"Control session: synchronized",
		"Netmap revision: 9",
		"Network: network.example.mesh",
		"Self addresses: 100.64.0.1/32, fd7a:115c:a1e0::1/128",
		"Peers: 2",
		"Peer paths: 2 total (1 direct, 1 relay, 0 pending)",
		"Relay: 1/2 regions connected (home 7)",
		"Policy rules: 3",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("status output %q does not contain %q", stdout.String(), expected)
		}
	}
}

func TestFormatRuntimeStatus_Unavailable(t *testing.T) {
	t.Parallel()

	if got := formatRuntimeStatus(nil); got != "unavailable" {
		t.Fatalf("formatRuntimeStatus(nil) = %q, want unavailable", got)
	}
}

func TestRun_ProfileCommands(t *testing.T) {
	t.Parallel()

	profile := localapi.Profile{
		ID:         "00000000000000000000000000000001",
		Name:       "production",
		ControlURL: "https://transit.example.com",
		IsActive:   true,
	}
	client := &fakeClient{
		profiles: localapi.Profiles{
			APIVersion: "v1",
			Profiles:   []localapi.Profile{profile},
		},
		created:   profile,
		activated: profile,
		trusted: localapi.ControlTrust{
			APIVersion:  "v1",
			ProfileID:   profile.ID,
			Fingerprint: "sha256:" + strings.Repeat("a", 64),
		},
	}

	tests := []struct {
		name     string
		args     []string
		contains string
	}{
		{
			name:     "list",
			args:     []string{"profile", "list"},
			contains: "production",
		},
		{
			name: "create",
			args: []string{
				"profile",
				"create",
				"--name",
				"production",
				"--control-url",
				"https://transit.example.com",
			},
			contains: "Created profile production",
		},
		{
			name:     "use",
			args:     []string{"profile", "use", profile.ID},
			contains: "Active profile: production",
		},
		{
			name: "trust",
			args: []string{
				"profile",
				"trust",
				"--fingerprint",
				"sha256:" + strings.Repeat("a", 64),
			},
			contains: "Pinned control key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			exitCode := Run(
				t.Context(),
				test.args,
				stdout,
				stderr,
				testOptions(client),
			)
			if exitCode != 0 {
				t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.contains) {
				t.Fatalf("output %q does not contain %q", stdout.String(), test.contains)
			}
		})
	}
}

func TestRun_LoginCommands(t *testing.T) {
	t.Parallel()

	profileID := "00000000000000000000000000000001"
	tests := []struct {
		name        string
		args        []string
		stdin       string
		login       localapi.Login
		complete    localapi.Login
		contains    string
		wantAuthKey string
	}{
		{
			name: "browser start",
			args: []string{"login"},
			login: localapi.Login{
				APIVersion: "v1",
				ProfileID:  profileID,
				State:      "authorization_required",
				AuthURL:    "https://control.example.com/register/opaque",
			},
			contains: "meshctl login complete",
		},
		{
			name:        "auth key from stdin",
			args:        []string{"login", "--auth-key-stdin"},
			stdin:       "credential-value\n",
			login:       localapi.Login{APIVersion: "v1", ProfileID: profileID, State: "registered"},
			contains:    "Registered active profile",
			wantAuthKey: "credential-value",
		},
		{
			name:     "browser complete",
			args:     []string{"login", "complete"},
			complete: localapi.Login{APIVersion: "v1", ProfileID: profileID, State: "registered"},
			contains: "Registered active profile",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &fakeClient{login: test.login, completedLogin: test.complete}
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			options := testOptions(client)
			options.Stdin = strings.NewReader(test.stdin)
			exitCode := Run(t.Context(), test.args, stdout, stderr, options)
			if exitCode != 0 {
				t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.contains) {
				t.Fatalf("output %q does not contain %q", stdout.String(), test.contains)
			}
			if client.receivedAuthKey != test.wantAuthKey {
				t.Fatalf("received auth key = %q, want %q", client.receivedAuthKey, test.wantAuthKey)
			}
		})
	}
}

func TestReadAuthKey_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"credential value", "credential\x00value", string([]byte{0xff})} {
		if _, err := readAuthKey(strings.NewReader(input)); err == nil {
			t.Fatalf("readAuthKey(%q) error = nil, want validation error", input)
		}
	}
}

func TestRun_DoctorControl(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		probe: localapi.ControlProbe{
			APIVersion:       "v1",
			ProfileID:        "00000000000000000000000000000001",
			ControlURL:       "https://transit.example.com",
			Protocol:         "ts2021",
			Capability:       142,
			KeyFingerprint:   "sha256:test",
			NoiseEstablished: true,
			NoiseVersion:     142,
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"doctor", "control"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
	}
	for _, expected := range []string{
		"Control: reachable",
		"Capability: 142",
		"Noise: true (version 142)",
		"Key fingerprint: sha256:test",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("doctor output %q does not contain %q", stdout.String(), expected)
		}
	}
}

func TestRun_RuntimeError(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"status"},
		stdout,
		stderr,
		testOptions(&fakeClient{err: errors.New("daemon unavailable")}),
	)
	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "daemon unavailable") {
		t.Fatalf("stderr = %q, want runtime error", stderr.String())
	}
}

func TestRun_UsageError(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"unknown"},
		stdout,
		stderr,
		testOptions(&fakeClient{}),
	)
	if exitCode != 2 {
		t.Fatalf("Run() exit code = %d, want 2", exitCode)
	}
}

type fakeClient struct {
	status          localapi.Status
	profiles        localapi.Profiles
	created         localapi.Profile
	activated       localapi.Profile
	probe           localapi.ControlProbe
	trusted         localapi.ControlTrust
	login           localapi.Login
	completedLogin  localapi.Login
	receivedAuthKey string
	err             error
}

func (f *fakeClient) Status(_ context.Context) (localapi.Status, error) {
	return f.status, f.err
}

func (f *fakeClient) ListProfiles(_ context.Context) (localapi.Profiles, error) {
	return f.profiles, f.err
}

func (f *fakeClient) CreateProfile(
	_ context.Context,
	_ localapi.CreateProfile,
) (localapi.Profile, error) {
	return f.created, f.err
}

func (f *fakeClient) ActivateProfile(_ context.Context, _ string) (localapi.Profile, error) {
	return f.activated, f.err
}

func (f *fakeClient) ProbeControl(_ context.Context) (localapi.ControlProbe, error) {
	return f.probe, f.err
}

func (f *fakeClient) TrustControl(_ context.Context, _ string) (localapi.ControlTrust, error) {
	return f.trusted, f.err
}

func (f *fakeClient) StartLogin(_ context.Context, authKey string) (localapi.Login, error) {
	f.receivedAuthKey = authKey

	return f.login, f.err
}

func (f *fakeClient) CompleteLogin(_ context.Context) (localapi.Login, error) {
	return f.completedLogin, f.err
}

func testOptions(client DaemonClient) Options {
	return Options{
		Build: version.Info{
			Version: "test",
			Commit:  "abc123",
			Date:    "2026-09-09T00:00:00Z",
		},
		Getenv: func(string) string { return "" },
		NewClient: func(string, time.Duration) (DaemonClient, error) {
			return client, nil
		},
	}
}

var _ DaemonClient = (*fakeClient)(nil)
