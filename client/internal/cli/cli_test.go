package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/cli/localapi"
	"meshtransit.net/client/internal/version"
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
			SelfAddresses:   []string{"100.64.0.1/32", "fd07:d4de:9d87::1/128"},
			PeerCount:       2,
			PolicyRuleCount: 3,
			PeerPaths: localapi.PathStatus{
				Available:                 true,
				PeerCount:                 2,
				DirectCount:               1,
				RelayCount:                1,
				RelayBootstrapCount:       2,
				DirectPromotionCount:      2,
				RelayFallbackCount:        1,
				LastDirectPromotionMillis: 3200,
				MaxDirectPromotionMillis:  4700,
			},
			PathProbes: &localapi.PathProbeStatus{
				Available:                true,
				MapActivations:           9,
				ActivationPreserved:      7,
				ActivationRetired:        2,
				AuthorityEndpointChanges: 2,
				PendingInvalidated:       3,
				RoundsStarted:            12,
				RoundsCompleted:          11,
				ProbeAttempts:            24,
				ProbesSent:               22,
				ProbeStartFailures:       1,
				ProbeSendFailures:        1,
				AuthenticatedPongs:       21,
				ProbeCompletions:         20,
				CompletionRejections:     1,
				ObservationsQueued:       20,
				ObservationsAccepted:     19,
				ObservationRejected:      1,
				DirectExpirations:        2,
				DatagramDrops:            4,
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
			RuntimeRecovery: &localapi.RuntimeRecoveryStatus{
				Failures:   4,
				Recoveries: 3,
				Pending:    true,
			},
			Runtime: &localapi.RuntimeStatus{
				Goroutines:     11,
				HeapAllocBytes: 12582912,
				SysBytes:       25165824,
				GCCycles:       7,
			},
			NAT: &localapi.NATStatus{
				State:      "ready",
				Mapping:    "endpoint-independent",
				Filtering:  "unknown",
				Allocation: "port-preserving",
				Difficulty: "easy",
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
		"Runtime recovery: pending (failures: 4, recoveries: 3)",
		"Runtime: 11 goroutines, 12.0 MiB heap allocated, 24.0 MiB system, 7 GC cycles",
		"Active profile: none",
		"Control session: synchronized",
		"Netmap revision: 9",
		"Network: network.example.mesh",
		"Self addresses: 100.64.0.1/32, fd07:d4de:9d87::1/128",
		"Peers: 2",
		"Peer paths: 2 total (1 direct, 1 relay, 0 pending)",
		"Path transitions: relay bootstraps 2, direct promotions 2, relay fallbacks 1, last/max promotion 3200/4700 ms",
		"Path probes: maps 9 (7 preserved, 2 retired; authority peer/node/discovery/endpoint 0/0/0/2; socket changes 0; 3 pending invalidated), rounds 11/12 completed, sends 22/24 attempts (1 start, 1 send failures), completions 20/21 authenticated replies (1 rejected), observations 19/20 accepted (1 rejected, 0 dropped), expirations 2, receive drops 4",
		"Relay: 1/2 regions connected (home 7)",
		"NAT: easy (endpoint-independent mapping, unknown filtering, port-preserving)",
		"Policy rules: 3",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("status output %q does not contain %q", stdout.String(), expected)
		}
	}
}

func TestRun_StatusJSONIncludesRuntimeRecovery(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		status: localapi.Status{
			APIVersion: "v1",
			RuntimeRecovery: &localapi.RuntimeRecoveryStatus{
				Failures:   1,
				Recoveries: 1,
			},
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"--json", "status"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
	}

	status := localapi.Status{}
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if status.RuntimeRecovery == nil || status.RuntimeRecovery.Failures != 1 ||
		status.RuntimeRecovery.Recoveries != 1 || status.RuntimeRecovery.Pending {
		t.Fatalf("JSON runtime recovery = %#v", status.RuntimeRecovery)
	}
}

func TestFormatRuntimeRecoveryStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status *localapi.RuntimeRecoveryStatus
		want   string
	}{
		{
			name: "unavailable from older daemon",
			want: "unavailable",
		},
		{
			name:   "idle",
			status: &localapi.RuntimeRecoveryStatus{},
			want:   "idle (failures: 0, recoveries: 0)",
		},
		{
			name: "pending",
			status: &localapi.RuntimeRecoveryStatus{
				Failures:   4,
				Recoveries: 3,
				Pending:    true,
			},
			want: "pending (failures: 4, recoveries: 3)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := formatRuntimeRecoveryStatus(test.status); got != test.want {
				t.Fatalf("formatRuntimeRecoveryStatus() = %q, want %q", got, test.want)
			}
		})
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
			args: []string{"login", "--no-wait"},
			login: localapi.Login{
				APIVersion: "v1",
				ProfileID:  profileID,
				State:      "authorization_required",
				AuthURL:    "https://control.example.com/register/opaque",
			},
			contains: "https://control.example.com/register/opaque",
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

func TestRun_IdentityRotateNodeKey(t *testing.T) {
	t.Parallel()

	profileID := "00000000000000000000000000000001"
	tests := []struct {
		name     string
		args     []string
		contains string
	}{
		{
			name:     "text",
			args:     []string{"identity", "rotate-node-key"},
			contains: "Rotated Node key for active profile " + profileID,
		},
		{
			name:     "json",
			args:     []string{"--json", "identity", "rotate-node-key"},
			contains: `"state": "rotated"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &fakeClient{rotation: localapi.NodeKeyRotation{
				APIVersion: "v1",
				ProfileID:  profileID,
				State:      "rotated",
			}}
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

func TestRun_IdentityRejectsUnknownRotationState(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"identity", "rotate-node-key"},
		stdout,
		stderr,
		testOptions(&fakeClient{rotation: localapi.NodeKeyRotation{State: "pending"}}),
	)
	if exitCode != 1 || !strings.Contains(stderr.String(), "unsupported Node-key rotation state") {
		t.Fatalf("Run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
}

func TestRun_LoginWaitsForBrowserAuthorization(t *testing.T) {
	t.Parallel()

	const profileID = "00000000000000000000000000000001"
	completeCalls := 0
	client := &fakeClient{
		login: localapi.Login{
			APIVersion: "v1",
			ProfileID:  profileID,
			State:      "authorization_required",
			AuthURL:    "https://control.example.com/register/opaque",
		},
		completeLogin: func(context.Context) (localapi.Login, error) {
			completeCalls++
			if completeCalls == 1 {
				return localapi.Login{}, &localapi.APIError{
					StatusCode: 409,
					Code:       "authorization_pending",
					Message:    "browser authorization is still pending",
				}
			}

			return localapi.Login{
				APIVersion: "v1",
				ProfileID:  profileID,
				State:      "registered",
			}, nil
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"login", "--wait-timeout", "1s"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
	}
	if completeCalls != 2 {
		t.Fatalf("CompleteLogin() calls = %d, want 2", completeCalls)
	}
	if !strings.Contains(stdout.String(), "https://control.example.com/register/opaque") ||
		!strings.Contains(stdout.String(), "Registered active profile") {
		t.Fatalf("login output = %q, want authorization URL and success", stdout.String())
	}
}

func TestRun_LoginWaitTimeout(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		login: localapi.Login{
			APIVersion: "v1",
			ProfileID:  "00000000000000000000000000000001",
			State:      "authorization_required",
			AuthURL:    "https://control.example.com/register/opaque",
		},
		completeLogin: func(ctx context.Context) (localapi.Login, error) {
			<-ctx.Done()

			return localapi.Login{}, ctx.Err()
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"login", "--wait-timeout", "1ms"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "timed out") {
		t.Fatalf("stderr = %q, want bounded timeout", stderr.String())
	}
}

func TestRun_LoginNoWaitDoesNotPoll(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		login: localapi.Login{
			APIVersion: "v1",
			ProfileID:  "00000000000000000000000000000001",
			State:      "authorization_required",
			AuthURL:    "https://control.example.com/register/opaque",
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"login", "--no-wait"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
	}
	if client.completeCalls != 0 {
		t.Fatalf("CompleteLogin() calls = %d, want 0", client.completeCalls)
	}
}

func TestRun_LoginWaitHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	client := &fakeClient{
		login: localapi.Login{
			APIVersion: "v1",
			ProfileID:  "00000000000000000000000000000001",
			State:      "authorization_required",
			AuthURL:    "https://control.example.com/register/opaque",
		},
		completeLogin: func(callCtx context.Context) (localapi.Login, error) {
			cancel()
			<-callCtx.Done()

			return localapi.Login{}, callCtx.Err()
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		ctx,
		[]string{"login", "--wait-timeout", "1s"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("stderr = %q, want cancellation", stderr.String())
	}
}

func TestRun_LoginWaitStopsOnUnexpectedError(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		login: localapi.Login{
			APIVersion: "v1",
			ProfileID:  "00000000000000000000000000000001",
			State:      "authorization_required",
			AuthURL:    "https://control.example.com/register/opaque",
		},
		completeLogin: func(context.Context) (localapi.Login, error) {
			return localapi.Login{}, errors.New("daemon unavailable")
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"login", "--wait-timeout", "1s"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if client.completeCalls != 1 || !strings.Contains(stderr.String(), "daemon unavailable") {
		t.Fatalf(
			"CompleteLogin() calls = %d, stderr = %q, want one terminal error",
			client.completeCalls,
			stderr.String(),
		)
	}
}

func TestRun_LoginRejectsInvalidWaitTimeout(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"login", "--wait-timeout", "0s"},
		stdout,
		stderr,
		testOptions(&fakeClient{}),
	)
	if exitCode != 2 {
		t.Fatalf("Run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "must be positive") {
		t.Fatalf("stderr = %q, want validation error", stderr.String())
	}
}

func TestRun_LoginJSONStreamsPendingThenRegistered(t *testing.T) {
	t.Parallel()

	const profileID = "00000000000000000000000000000001"
	client := &fakeClient{
		login: localapi.Login{
			APIVersion: "v1",
			ProfileID:  profileID,
			State:      "authorization_required",
			AuthURL:    "https://control.example.com/register/opaque",
		},
		completeLogin: func(context.Context) (localapi.Login, error) {
			return localapi.Login{
				APIVersion: "v1",
				ProfileID:  profileID,
				State:      "registered",
			}, nil
		},
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode := Run(
		t.Context(),
		[]string{"--json", "login", "--wait-timeout", "1s"},
		stdout,
		stderr,
		testOptions(client),
	)
	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0; stderr=%s", exitCode, stderr.String())
	}

	decoder := json.NewDecoder(stdout)
	first := localapi.Login{}
	if err := decoder.Decode(&first); err != nil {
		t.Fatalf("decoding pending login: %v", err)
	}
	second := localapi.Login{}
	if err := decoder.Decode(&second); err != nil {
		t.Fatalf("decoding registered login: %v", err)
	}
	if err := decoder.Decode(&localapi.Login{}); !errors.Is(err, io.EOF) {
		t.Fatalf("decoding trailing output error = %v, want EOF", err)
	}
	if first.State != "authorization_required" || first.AuthURL == "" ||
		second.State != "registered" || second.AuthURL != "" {
		t.Fatalf("login stream = %#v then %#v, want pending then registered", first, second)
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
			Protocol:         "mtcp",
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
	rotation        localapi.NodeKeyRotation
	connection      localapi.Connection
	logout          localapi.Logout
	netcheck        localapi.Netcheck
	completeLogin   func(context.Context) (localapi.Login, error)
	receivedAuthKey string
	completeCalls   int
	err             error
}

func (f *fakeClient) RefreshNAT(_ context.Context) (localapi.Netcheck, error) {
	return f.netcheck, f.err
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

func (f *fakeClient) CompleteLogin(ctx context.Context) (localapi.Login, error) {
	f.completeCalls++
	if f.completeLogin != nil {
		return f.completeLogin(ctx)
	}

	return f.completedLogin, f.err
}

func (f *fakeClient) RotateNodeKey(_ context.Context) (localapi.NodeKeyRotation, error) {
	return f.rotation, f.err
}

func (f *fakeClient) Down(_ context.Context) (localapi.Connection, error) {
	return f.connection, f.err
}

func (f *fakeClient) Up(_ context.Context) (localapi.Connection, error) {
	return f.connection, f.err
}

func (f *fakeClient) Logout(_ context.Context) (localapi.Logout, error) {
	return f.logout, f.err
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

func TestFormatPathStatusReportsLazyPeers(t *testing.T) {
	t.Parallel()

	eager := localapi.PathStatus{Available: true, PeerCount: 2, DirectCount: 2}
	if got := formatPathStatus(eager); got != "2 total (2 direct, 0 relay, 0 pending)" {
		t.Fatalf("eager status = %q", got)
	}
	lazy := localapi.PathStatus{
		Available: true, PeerCount: 1500, DirectCount: 3, InactiveCount: 1497,
		LazyActivationCount: 9, LazyEvictionCount: 6, LazyDroppedCount: 1,
	}
	want := "1500 total (3 direct, 0 relay, 0 pending); lazy: 1497 inactive, 9 activations, 6 evictions, 1 dropped"
	if got := formatPathStatus(lazy); got != want {
		t.Fatalf("lazy status = %q, want %q", got, want)
	}
}

func TestFormatSubnetRouterStatusListsUnhealthySites(t *testing.T) {
	t.Parallel()
	status := &localapi.SubnetRouterStatus{
		Sites: 2, Requested: 2, Served: 2, Health: "forward_blocked",
		SiteHealth: []localapi.SubnetRouterSiteHealth{
			{Site: "prod", State: "failed", Code: "forward_blocked"},
			{Site: "uat", State: "ok", Code: "ok"},
		},
	}
	got := formatSubnetRouterStatus(status)
	if !strings.Contains(got, "[forward_blocked]") || !strings.Contains(got, "prod failed forward_blocked") ||
		strings.Contains(got, "uat") {
		t.Fatalf("formatSubnetRouterStatus() = %q", got)
	}
}

func TestFormatExitStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status *localapi.ExitStatus
		want   string
	}{
		{nil, "none"},
		{
			&localapi.ExitStatus{Use: "europe", Routing: true},
			"europe: pool not granted; Internet traffic is dropped",
		},
		{
			&localapi.ExitStatus{Use: "auto", Pool: "p1", PoolName: "Europe", Routing: true},
			"pool Europe: no exit node available; Internet traffic is dropped",
		},
		{
			&localapi.ExitStatus{
				Use: "p1", Pool: "p1", PoolName: "Europe", ExitNode: "d1", ExitNodeName: "fra", Via: "sticky",
				IPv6: true, Routing: true,
			},
			"via fra in pool Europe (kept: Core elected another primary)",
		},
		{
			&localapi.ExitStatus{Use: "p1", Pool: "p1", ExitNode: "d1", Via: "primary", Refused: "exit_use_off"},
			"via d1 in pool p1; IPv6 blocked [helper: exit_use_off]",
		},
	}
	for _, test := range cases {
		if got := formatExitStatus(test.status); got != test.want {
			t.Errorf("formatExitStatus(%+v) = %q, want %q", test.status, got, test.want)
		}
	}
}

func TestFormatExitNodeStatus(t *testing.T) {
	t.Parallel()
	if got := formatExitNodeStatus(nil); got != "none" {
		t.Fatalf("no exit node = %q", got)
	}
	serving := &localapi.ExitNodeStatus{
		Pool: "p-main", Serving: true, ConntrackPerConsumer: 4096, MaxConsumers: 8,
		State: "degraded", Code: "egress_v6_failed", Families: "ipv4",
	}
	if got := formatExitNodeStatus(serving); got !=
		"serving pool p-main, 4096 connections per consumer, 8 consumers [degraded egress_v6_failed]; Internet over ipv4" {
		t.Fatalf("serving = %q", got)
	}
	refused := &localapi.ExitNodeStatus{Pool: "p-main", Refused: "exit_off", State: "failed", Code: "exit_not_offered"}
	if got := formatExitNodeStatus(refused); got != "not serving pool p-main [exit_off] [failed exit_not_offered]" {
		t.Fatalf("refused = %q", got)
	}
}
