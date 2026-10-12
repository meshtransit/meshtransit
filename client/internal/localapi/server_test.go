package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/client/internal/runtimehealth"
	"meshtransit.net/client/internal/secretstore"
	"meshtransit.net/client/internal/version"
	"meshtransit.net/shared/disco"
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
		status.PathProbes.Available ||
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

func TestMapPathProbeStatus(t *testing.T) {
	t.Parallel()

	snapshot := pathdiscovery.ProbeTelemetrySnapshot{
		MapActivations:               1,
		ActivationPreserved:          2,
		ActivationRetired:            3,
		AuthorityPeerChanges:         4,
		AuthorityNodeKeyChanges:      5,
		AuthorityDiscoveryKeyChanges: 6,
		AuthorityEndpointChanges:     7,
		SocketChanges:                8,
		PendingInvalidated:           9,
		RoundsStarted:                10,
		RoundsCompleted:              11,
		ProbeAttempts:                12,
		ProbesStarted:                13,
		ProbesSent:                   14,
		ProbeStartFailures:           15,
		ProbeSendFailures:            16,
		DatagramDrops:                17,
		AuthenticatedPings:           18,
		PingRateLimited:              19,
		PongsSent:                    20,
		PongSendFailures:             21,
		AuthenticatedPongs:           22,
		ProbeCompletions:             23,
		CompletionRejections:         24,
		ObservationsQueued:           25,
		ObservationDrops:             26,
		ObservationsAccepted:         27,
		ObservationRejected:          28,
		DirectExpirations:            29,
	}
	got := mapPathProbeStatus(daemon.PathProbeStatus{
		Available: true,
		Snapshot:  snapshot,
	})
	want := pathProbeStatus{
		Available:                    true,
		MapActivations:               1,
		ActivationPreserved:          2,
		ActivationRetired:            3,
		AuthorityPeerChanges:         4,
		AuthorityNodeKeyChanges:      5,
		AuthorityDiscoveryKeyChanges: 6,
		AuthorityEndpointChanges:     7,
		SocketChanges:                8,
		PendingInvalidated:           9,
		RoundsStarted:                10,
		RoundsCompleted:              11,
		ProbeAttempts:                12,
		ProbesStarted:                13,
		ProbesSent:                   14,
		ProbeStartFailures:           15,
		ProbeSendFailures:            16,
		DatagramDrops:                17,
		AuthenticatedPings:           18,
		PingRateLimited:              19,
		PongsSent:                    20,
		PongSendFailures:             21,
		AuthenticatedPongs:           22,
		ProbeCompletions:             23,
		CompletionRejections:         24,
		ObservationsQueued:           25,
		ObservationDrops:             26,
		ObservationsAccepted:         27,
		ObservationRejected:          28,
		DirectExpirations:            29,
	}
	if got != want {
		t.Fatalf("mapPathProbeStatus() = %#v, want %#v", got, want)
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
		Available:            true,
		PeerCount:            3,
		DirectCount:          1,
		RelayCount:           1,
		PendingCount:         1,
		RelayBootstrapCount:  4,
		DirectPromotionCount: 3,
		RelayFallbackCount:   2,
		LastDirectPromotion:  1500 * time.Millisecond,
		MaxDirectPromotion:   3250 * time.Millisecond,
	})
	if !paths.Available || paths.PeerCount != 3 || paths.DirectCount != 1 ||
		paths.RelayCount != 1 || paths.PendingCount != 1 ||
		paths.RelayBootstrapCount != 4 || paths.DirectPromotionCount != 3 ||
		paths.RelayFallbackCount != 2 || paths.LastDirectPromotionMillis != 1500 ||
		paths.MaxDirectPromotionMillis != 3250 {
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

	rotation := performRequest(
		t,
		server,
		http.MethodPost,
		"/v1/identity/node-key/rotate",
		"",
		nil,
	)
	if rotation.Code != http.StatusOK {
		t.Fatalf("rotation status = %d, want 200; body=%s", rotation.Code, rotation.Body.String())
	}
	rotated := decodeResponse[nodeKeyRotationResponse](t, rotation)
	if rotated.APIVersion != apiVersion || rotated.ProfileID != firstProfileID(t, server) ||
		rotated.State != "rotated" {
		t.Fatalf("rotation response = %#v, want committed rotation", rotated)
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
		{
			name:     "rotation wrong method",
			method:   http.MethodGet,
			path:     "/v1/identity/node-key/rotate",
			expected: http.StatusMethodNotAllowed,
		},
		{
			name:        "rotation rejects body",
			method:      http.MethodPost,
			path:        "/v1/identity/node-key/rotate",
			contentType: "application/json",
			body:        []byte(`{}`),
			expected:    http.StatusBadRequest,
		},
		{
			name:     "down wrong method",
			method:   http.MethodGet,
			path:     "/v1/down",
			expected: http.StatusMethodNotAllowed,
		},
		{
			name:        "down rejects body",
			method:      http.MethodPost,
			path:        "/v1/down",
			contentType: "application/json",
			body:        []byte(`{}`),
			expected:    http.StatusBadRequest,
		},
		{
			name:     "up wrong method",
			method:   http.MethodGet,
			path:     "/v1/up",
			expected: http.StatusMethodNotAllowed,
		},
		{
			name:        "up rejects body",
			method:      http.MethodPost,
			path:        "/v1/up",
			contentType: "application/json",
			body:        []byte(`{}`),
			expected:    http.StatusBadRequest,
		},
		{
			name:     "logout wrong method",
			method:   http.MethodGet,
			path:     "/v1/logout",
			expected: http.StatusMethodNotAllowed,
		},
		{
			name:        "logout rejects body",
			method:      http.MethodPost,
			path:        "/v1/logout",
			contentType: "application/json",
			body:        []byte(`{}`),
			expected:    http.StatusBadRequest,
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

func (fakeProber) Probe(_ context.Context, _ string) (controlplane.Result, error) {
	return controlplane.Result{
		Protocol:         "mtcp",
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
) (controlplane.TrustResult, error) {
	return controlplane.TrustResult{
		Fingerprint: fingerprint,
		Material: controlplane.KeyMaterial{
			MachinePrivateKey: []byte("machine-private"),
			NodePrivateKey:    []byte("node-private"),
			ControlPublicKey:  []byte("control-public"),
		},
	}, nil
}

func (fakeProber) VerifyTrust(context.Context, string, controlplane.KeyMaterial, string) error {
	return nil
}

func (fakeProber) Register(
	_ context.Context,
	controlURL string,
	_ controlplane.KeyMaterial,
	options controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	if options.AuthKey != "" || options.FollowupURL != "" {
		return controlplane.RegistrationResult{
			State:             controlplane.RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, nil
	}

	return controlplane.RegistrationResult{
		State:   controlplane.RegistrationStateAuthorizationRequired,
		AuthURL: controlURL + "/register/opaque",
	}, nil
}

func (fakeProber) RotateNodeKey(
	_ context.Context,
	_ string,
	_ controlplane.KeyMaterial,
	_ []byte,
	_ controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	return controlplane.RegistrationResult{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}, nil
}

func (fakeProber) Logout(context.Context, string, controlplane.KeyMaterial, controlplane.RegisterOptions) error {
	return nil
}

func (fakeProber) StreamNetmap(
	ctx context.Context,
	_ string,
	_ controlplane.KeyMaterial,
	_ controlplane.NetmapOptions,
	_ controlplane.NetmapHandler,
) error {
	<-ctx.Done()

	return ctx.Err()
}

var _ interface {
	Probe(context.Context, string) (controlplane.Result, error)
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

func firstProfileID(t *testing.T, server *Server) string {
	t.Helper()

	response := performRequest(t, server, http.MethodGet, "/v1/profiles", "", nil)
	profiles := decodeResponse[profilesResponse](t, response)
	if len(profiles.Profiles) == 0 {
		t.Fatal("profile list is empty")
	}

	return profiles.Profiles[0].ID
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

func TestServer_Netcheck(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	status := decodeResponse[statusResponse](t, performRequest(t, server, http.MethodGet, "/v1/status", "", nil))
	if status.NAT.State != daemon.NATUnavailable || status.NAT.PublicEndpoint != "" {
		t.Fatalf("nat status without a packet engine = %#v", status.NAT)
	}
	if status.PortMapping.State != daemon.PortMappingOff {
		t.Fatalf("port mapping without a packet engine = %#v", status.PortMapping)
	}
	if got := performRequest(t, server, http.MethodGet, "/v1/netcheck", "", nil); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/netcheck = %d, want 405", got.Code)
	}
	if got := performRequest(t, server, http.MethodPost, "/v1/netcheck", "application/json", []byte("{}")); got.Code != http.StatusBadRequest {
		t.Fatalf("POST with body = %d, want 400", got.Code)
	}
}

func TestMapNATStatus(t *testing.T) {
	t.Parallel()
	observed := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	ready := daemon.NATStatus{
		State:           daemon.NATReady,
		NAT:             disco.NATInfo{Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationSequential},
		Step:            2,
		PublicEndpoint:  netip.MustParseAddrPort("203.0.113.7:41641"),
		ServersAnswered: 3,
		ObservedAt:      observed,
	}
	got := mapNATStatus(ready, true)
	want := natStatus{
		State: "ready", Mapping: "address-and-port-dependent", Filtering: "address-and-port-dependent",
		Allocation: "sequential", SequentialStep: 2, Difficulty: "hard", PublicEndpoint: "203.0.113.7:41641",
		ServersAnswered: 3, ObservedAt: "2026-10-09T08:00:00Z",
	}
	if got != want {
		t.Fatalf("mapNATStatus = %#v, want %#v", got, want)
	}
	if forStatus := mapNATStatus(ready, false); forStatus.PublicEndpoint != "" {
		t.Fatalf("status form exposes the public endpoint: %#v", forStatus)
	}
	failed := mapNATStatus(daemon.NATStatus{State: daemon.NATFailed, Error: "no_response", PublicEndpoint: netip.MustParseAddrPort("203.0.113.7:1")}, true)
	if failed != (natStatus{State: "failed", Error: "no_response"}) {
		t.Fatalf("failed status leaks fields: %#v", failed)
	}
	easy := mapNATStatus(daemon.NATStatus{State: daemon.NATStale, NAT: disco.NATInfo{Mapping: disco.MappingNone}}, false)
	if easy.Difficulty != "easy" || easy.Filtering != "unknown" || easy.Allocation != "unknown" {
		t.Fatalf("stale public host = %#v", easy)
	}
}

func TestMapPortMappingStatus(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 10, 10, 14, 0, 0, 0, time.FixedZone("ICT", 7*3600))
	mapped := daemon.PortMappingStatus{
		State: "mapped", Protocol: "pcp", External: netip.MustParseAddrPort("203.0.113.7:41641"), ExpiresAt: expires,
	}
	status := mapPortMappingStatus(mapped, false)
	if status.External != "" || status.Protocol != "pcp" || status.ExpiresAt != "2026-10-10T07:00:00Z" {
		t.Fatalf("status form = %#v", status)
	}
	if netcheck := mapPortMappingStatus(mapped, true); netcheck.External != "203.0.113.7:41641" {
		t.Fatalf("netcheck form = %#v", netcheck)
	}
	if empty := mapPortMappingStatus(daemon.PortMappingStatus{}, true); empty.State != daemon.PortMappingOff {
		t.Fatalf("empty = %#v", empty)
	}
}

func TestMapCloudStatus(t *testing.T) {
	t.Parallel()
	ready := daemon.CloudStatus{
		State: "ready", Platform: "aws", Addresses: []netip.Addr{netip.MustParseAddr("18.142.253.199")},
		ObservedAt: time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC),
	}
	status := mapCloudStatus(ready, false)
	if status.AddressCount != 1 || len(status.Addresses) != 0 || status.ObservedAt != "2026-10-10T10:00:00Z" {
		t.Fatalf("status form = %#v", status)
	}
	if netcheck := mapCloudStatus(ready, true); len(netcheck.Addresses) != 1 || netcheck.Addresses[0] != "18.142.253.199" {
		t.Fatalf("netcheck form = %#v", netcheck)
	}
	if empty := mapCloudStatus(daemon.CloudStatus{}, true); empty.State != daemon.CloudOff {
		t.Fatalf("empty = %#v", empty)
	}
}

func TestServer_UpAndLogoutWithoutADevice(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	upRecorder := performRequest(t, server, http.MethodPost, "/v1/up", "", nil)
	if upRecorder.Code != http.StatusOK {
		t.Fatalf("up status = %d; body=%s", upRecorder.Code, upRecorder.Body.String())
	}
	up := decodeResponse[connectionResponse](t, upRecorder)
	if up.APIVersion != apiVersion || up.State != daemon.ConnectionUp || up.Changed {
		t.Fatalf("up response = %#v, want an unchanged up", up)
	}

	createProfile(t, server, "test", "https://control.example.com")
	logoutRecorder := performRequest(t, server, http.MethodPost, "/v1/logout", "", nil)
	if logoutRecorder.Code != http.StatusOK {
		t.Fatalf("logout status = %d; body=%s", logoutRecorder.Code, logoutRecorder.Body.String())
	}
	logout := decodeResponse[logoutResponse](t, logoutRecorder)
	if logout.APIVersion != apiVersion || logout.State != daemon.LogoutNotRegistered {
		t.Fatalf("logout response = %#v, want not registered", logout)
	}
}
