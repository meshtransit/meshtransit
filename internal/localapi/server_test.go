package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/compat/ts2021"
	"github.com/meshtransit/meshd/internal/daemon"
	"github.com/meshtransit/meshd/internal/dataplane"
	"github.com/meshtransit/meshd/internal/identity"
	"github.com/meshtransit/meshd/internal/profile"
	"github.com/meshtransit/meshd/internal/relay"
	"github.com/meshtransit/meshd/internal/runtimehealth"
	"github.com/meshtransit/meshd/internal/secretstore"
	"github.com/meshtransit/meshd/internal/version"
)

const testUID = 1000

func TestServer_ProfileLifecycle(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)

	initial := performRequest(t, server, http.MethodGet, "/v1/status", "", nil)
	if initial.Code != http.StatusOK {
		t.Fatalf("initial status code = %d, want %d", initial.Code, http.StatusOK)
	}
	status := decodeResponse[statusResponse](t, initial)
	if status.ProfileCount != 0 || status.ActiveProfileID != "" {
		t.Fatalf("initial status = %#v, want no profiles", status)
	}
	if status.DataPlane != daemon.DataPlanePending {
		t.Fatalf("data plane = %q, want %q", status.DataPlane, daemon.DataPlanePending)
	}
	if status.Runtime.Goroutines == 0 || status.Runtime.HeapAllocBytes == 0 ||
		status.Runtime.HeapObjects == 0 || status.Runtime.SysBytes == 0 {
		t.Fatalf("runtime status = %#v, want populated aggregate counters", status.Runtime)
	}
	if status.DNS != daemon.DNSInactive {
		t.Fatalf("dns = %q, want %q", status.DNS, daemon.DNSInactive)
	}
	if status.ControlSession != daemon.ControlSessionInactive ||
		status.NetmapRevision != 0 || status.NetworkName != "" ||
		len(status.SelfAddresses) != 0 || status.PeerCount != 0 ||
		status.PolicyRuleCount != 0 || status.PeerPaths.Available ||
		status.Relay.Available || status.Relay.ActiveRegions != 0 ||
		status.Relay.ConnectedRegions != 0 || status.NetworkChanges.Available ||
		status.NetworkChanges.Observed != 0 || status.NetworkChanges.EndpointRefreshes != 0 ||
		status.RuntimeRecovery.Failures != 0 ||
		status.RuntimeRecovery.Recoveries != 0 || status.RuntimeRecovery.Pending {
		t.Fatalf("initial control sync = %#v, want inactive empty snapshot", status)
	}

	first := createProfile(t, server, "production", "https://one.example.com")
	if !first.IsActive {
		t.Fatal("first profile is not active")
	}
	second := createProfile(t, server, "staging", "https://two.example.com")
	if second.IsActive {
		t.Fatal("second profile became active implicitly")
	}

	activate := performRequest(
		t,
		server,
		http.MethodPost,
		"/v1/profiles/"+second.ID+"/activate",
		"",
		nil,
	)
	if activate.Code != http.StatusOK {
		t.Fatalf("activate status code = %d, want %d", activate.Code, http.StatusOK)
	}
	activated := decodeResponse[profileResponse](t, activate)
	if !activated.IsActive || activated.ID != second.ID {
		t.Fatalf("activated profile = %#v, want second active", activated)
	}

	list := performRequest(t, server, http.MethodGet, "/v1/profiles", "", nil)
	profiles := decodeResponse[profilesResponse](t, list)
	if len(profiles.Profiles) != 2 {
		t.Fatalf("profile count = %d, want 2", len(profiles.Profiles))
	}
	activeCount := 0
	for _, item := range profiles.Profiles {
		if item.IsActive {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("active profile count = %d, want 1", activeCount)
	}
}

func TestMapRuntimeRecoveryStatus(t *testing.T) {
	t.Parallel()

	status := mapRuntimeRecoveryStatus(daemon.RuntimeRecoveryStatus{
		Failures:   5,
		Recoveries: 4,
		Pending:    true,
	})
	if status.Failures != 5 || status.Recoveries != 4 || !status.Pending {
		t.Fatalf("mapRuntimeRecoveryStatus() = %#v", status)
	}
}

func TestMapNetworkChangeStatus(t *testing.T) {
	t.Parallel()

	status := mapNetworkChangeStatus(daemon.NetworkChangeStatus{
		Available:         true,
		Observed:          3,
		EndpointRefreshes: 2,
	})
	if !status.Available || status.Observed != 3 || status.EndpointRefreshes != 2 {
		t.Fatalf("mapNetworkChangeStatus() = %#v", status)
	}
}

func TestMapRuntimeStatus(t *testing.T) {
	t.Parallel()

	status := mapRuntimeStatus(runtimehealth.Snapshot{
		Goroutines:      11,
		HeapAllocBytes:  12,
		HeapInUseBytes:  13,
		HeapObjects:     14,
		StackInUseBytes: 15,
		SysBytes:        16,
		GCCycles:        17,
	})
	if status.Goroutines != 11 || status.HeapAllocBytes != 12 ||
		status.HeapInUseBytes != 13 || status.HeapObjects != 14 ||
		status.StackInUseBytes != 15 || status.SysBytes != 16 ||
		status.GCCycles != 17 {
		t.Fatalf("mapRuntimeStatus() = %#v", status)
	}
}

func TestStatusTransportMapping(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 10, 12, 0, 0, 123, time.UTC)
	paths := mapPathStatus(dataplane.PeerPathSnapshot{
		Available:    true,
		PeerCount:    3,
		DirectCount:  1,
		RelayCount:   1,
		PendingCount: 1,
	})
	if !paths.Available || paths.PeerCount != 3 || paths.DirectCount != 1 ||
		paths.RelayCount != 1 || paths.PendingCount != 1 {
		t.Fatalf("mapPathStatus() = %#v", paths)
	}
	relayState := mapRelayStatus(relay.HealthSnapshot{
		Available:  true,
		HomeRegion: 9,
		Regions: []relay.RegionHealth{
			{RegionID: 9, Connected: true, LastActivity: now},
			{RegionID: 10, ConsecutiveFailures: 2, LastFailure: now},
		},
	})
	if !relayState.Available || relayState.HomeRegion != 9 ||
		relayState.ActiveRegions != 2 || relayState.ConnectedRegions != 1 ||
		len(relayState.Regions) != 2 ||
		relayState.Regions[0].LastActivity != now.Format(time.RFC3339Nano) ||
		relayState.Regions[1].LastFailure != now.Format(time.RFC3339Nano) {
		t.Fatalf("mapRelayStatus() = %#v", relayState)
	}
}

func TestServer_ControlProbe(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	createProfile(t, server, "production", "https://one.example.com")
	response := performRequest(t, server, http.MethodPost, "/v1/doctor/control", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("control probe status code = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	result := decodeResponse[controlProbeResponse](t, response)
	if got, expected := result.Capability, 142; got != expected {
		t.Fatalf("capability = %d, want %d", got, expected)
	}
	if got, expected := result.KeyFingerprint, "sha256:test-fingerprint"; got != expected {
		t.Fatalf("fingerprint = %q, want %q", got, expected)
	}
	if !result.NoiseEstablished || result.NoiseVersion != 142 {
		t.Fatalf("noise result = %#v, want established version 142", result)
	}
}

func TestServer_ControlTrustAndLogin(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	createProfile(t, server, "production", "https://one.example.com")
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	trustBody, err := json.Marshal(trustControlRequest{Fingerprint: fingerprint})
	if err != nil {
		t.Fatalf("json.Marshal(trust) error = %v", err)
	}
	trust := performRequest(
		t,
		server,
		http.MethodPost,
		"/v1/control/trust",
		"application/json",
		trustBody,
	)
	if trust.Code != http.StatusOK {
		t.Fatalf("trust status = %d, want 200; body=%s", trust.Code, trust.Body.String())
	}
	trusted := decodeResponse[trustControlResponse](t, trust)
	if trusted.Fingerprint != fingerprint || trusted.AlreadyPinned {
		t.Fatalf("trust response = %#v, want newly pinned fingerprint", trusted)
	}

	login := performRequest(
		t,
		server,
		http.MethodPost,
		"/v1/login",
		"application/json",
		[]byte(`{}`),
	)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body=%s", login.Code, login.Body.String())
	}
	pending := decodeResponse[loginResponse](t, login)
	if pending.State != daemon.RegistrationPending || pending.AuthURL == "" {
		t.Fatalf("login response = %#v, want pending browser auth", pending)
	}

	complete := performRequest(
		t,
		server,
		http.MethodPost,
		"/v1/login/complete",
		"",
		nil,
	)
	if complete.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want 200; body=%s", complete.Code, complete.Body.String())
	}
	registered := decodeResponse[loginResponse](t, complete)
	if registered.State != daemon.RegistrationRegistered || registered.AuthURL != "" {
		t.Fatalf("complete response = %#v, want registered", registered)
	}

	statusRecorder := performRequest(t, server, http.MethodGet, "/v1/status", "", nil)
	status := decodeResponse[statusResponse](t, statusRecorder)
	if status.ControlTrust != daemon.ControlTrustPinned ||
		status.Registration != daemon.RegistrationRegistered ||
		status.ControlFingerprint != fingerprint {
		t.Fatalf("status = %#v, want pinned and registered", status)
	}
}

func TestServer_RequestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        []byte
		expected    int
	}{
		{
			name:        "trust unknown json field",
			method:      http.MethodPost,
			path:        "/v1/control/trust",
			contentType: "application/json",
			body:        []byte(`{"fingerprint":"sha256:value","network_id":"forged"}`),
			expected:    http.StatusBadRequest,
		},
		{
			name:     "wrong method",
			method:   http.MethodDelete,
			path:     "/v1/profiles",
			expected: http.StatusMethodNotAllowed,
		},
		{
			name:        "missing json content type",
			method:      http.MethodPost,
			path:        "/v1/profiles",
			contentType: "text/plain",
			body:        []byte(`{"name":"prod","control_url":"https://one.example.com"}`),
			expected:    http.StatusUnsupportedMediaType,
		},
		{
			name:        "unknown json field",
			method:      http.MethodPost,
			path:        "/v1/profiles",
			contentType: "application/json",
			body:        []byte(`{"name":"prod","control_url":"https://one.example.com","network_id":"forged"}`),
			expected:    http.StatusBadRequest,
		},
		{
			name:        "insecure control url",
			method:      http.MethodPost,
			path:        "/v1/profiles",
			contentType: "application/json",
			body:        []byte(`{"name":"prod","control_url":"http://one.example.com"}`),
			expected:    http.StatusBadRequest,
		},
		{
			name:     "invalid action path",
			method:   http.MethodPost,
			path:     "/v1/profiles/not-an-id/delete",
			expected: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newTestServer(t)
			response := performRequest(
				t,
				server,
				test.method,
				test.path,
				test.contentType,
				test.body,
			)
			if response.Code != test.expected {
				t.Fatalf("status code = %d, want %d; body=%s", response.Code, test.expected, response.Body.String())
			}
		})
	}
}

func TestServer_Authorization(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/status", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusForbidden)
	}

	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/status", nil)
	request = request.WithContext(contextWithPeer(request.Context(), peerIdentity{
		uid:        testUID + 1,
		isPresent:  true,
		isVerified: true,
	}))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong uid status code = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestServer_AuthorizesVerifiedSocketPeerWhenEnabled(t *testing.T) {
	t.Parallel()

	server := newTestServerWithOptions(t, Options{
		AllowedUIDs:      []uint32{testUID},
		AllowSocketPeers: true,
	})
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/status", nil)
	request = request.WithContext(contextWithPeer(request.Context(), peerIdentity{
		uid:        testUID + 1,
		isPresent:  true,
		isVerified: true,
	}))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("verified socket peer status code = %d, want %d", response.Code, http.StatusOK)
	}

	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/status", nil)
	request = request.WithContext(contextWithPeer(request.Context(), peerIdentity{
		uid:       testUID + 1,
		isPresent: true,
	}))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unverified socket peer status code = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()

	return newTestServerWithOptions(t, Options{AllowedUIDs: []uint32{testUID}})
}

func newTestServerWithOptions(t *testing.T, options Options) *Server {
	t.Helper()

	stateDir := t.TempDir()
	store, err := profile.Open(stateDir)
	if err != nil {
		t.Fatalf("profile.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	protector, err := secretstore.New(bytes.Repeat([]byte{0x52}, secretstore.KeySize))
	if err != nil {
		t.Fatalf("secretstore.New() error = %v", err)
	}
	identities, err := identity.Open(stateDir, protector)
	if err != nil {
		_ = protector.Close()
		t.Fatalf("identity.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = identities.Close() })
	service, err := daemon.New(
		store,
		identities,
		version.Info{
			Version: "test",
			Commit:  "test-commit",
			Date:    "2026-09-09T00:00:00Z",
		},
		fakeProber{},
		daemon.Options{Hostname: "node-a"},
	)
	if err != nil {
		t.Fatalf("daemon.New() error = %v", err)
	}
	logger := slog.New(slog.DiscardHandler)
	server, err := New(service, logger, options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return server
}

type fakeProber struct{}

func (fakeProber) Probe(_ context.Context, _ string) (ts2021.Result, error) {
	return ts2021.Result{
		Protocol:         "ts2021",
		Capability:       142,
		KeyFingerprint:   "sha256:test-fingerprint",
		NoiseEstablished: true,
		NoiseVersion:     142,
	}, nil
}

func (fakeProber) BootstrapTrust(
	_ context.Context,
	_ string,
	fingerprint string,
) (ts2021.TrustResult, error) {
	return ts2021.TrustResult{
		Fingerprint: fingerprint,
		Material: ts2021.KeyMaterial{
			MachinePrivateKey: []byte("machine-private"),
			NodePrivateKey:    []byte("node-private"),
			ControlPublicKey:  []byte("control-public"),
		},
	}, nil
}

func (fakeProber) VerifyTrust(context.Context, string, ts2021.KeyMaterial, string) error {
	return nil
}

func (fakeProber) Register(
	_ context.Context,
	controlURL string,
	_ ts2021.KeyMaterial,
	options ts2021.RegisterOptions,
) (ts2021.RegistrationResult, error) {
	if options.AuthKey != "" || options.FollowupURL != "" {
		return ts2021.RegistrationResult{
			State:             ts2021.RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, nil
	}

	return ts2021.RegistrationResult{
		State:   ts2021.RegistrationStateAuthorizationRequired,
		AuthURL: controlURL + "/register/opaque",
	}, nil
}

func (fakeProber) StreamNetmap(
	ctx context.Context,
	_ string,
	_ ts2021.KeyMaterial,
	_ ts2021.NetmapOptions,
	_ ts2021.NetmapHandler,
) error {
	<-ctx.Done()

	return ctx.Err()
}

var _ interface {
	Probe(context.Context, string) (ts2021.Result, error)
} = fakeProber{}

func createProfile(t *testing.T, server *Server, name, controlURL string) profileResponse {
	t.Helper()

	body, err := json.Marshal(createProfileRequest{
		Name:       name,
		ControlURL: controlURL,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	response := performRequest(
		t,
		server,
		http.MethodPost,
		"/v1/profiles",
		"application/json",
		body,
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status code = %d, want %d; body=%s", response.Code, http.StatusCreated, response.Body.String())
	}

	return decodeResponse[profileResponse](t, response)
}

func performRequest(
	t *testing.T,
	server *Server,
	method string,
	path string,
	contentType string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	request = request.WithContext(contextWithPeer(request.Context(), peerIdentity{
		uid:        testUID,
		isPresent:  true,
		isVerified: true,
	}))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	return response
}

func decodeResponse[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()

	var decoded T
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	return decoded
}
