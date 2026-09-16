package localapi

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		socketPath string
		timeout    time.Duration
	}{
		{
			name:       "relative socket",
			socketPath: "meshd.sock",
			timeout:    time.Second,
		},
		{
			name:       "zero timeout",
			socketPath: "/tmp/meshd.sock",
			timeout:    0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(test.socketPath, test.timeout)
			if err == nil {
				t.Fatal("New() error = nil, want validation error")
			}
		})
	}
}

func TestClient_Status(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/status" {
			t.Fatalf("request = %s %s, want GET /v1/status", request.Method, request.URL.Path)
		}

		return jsonResponse(http.StatusOK, `{
  "api_version":"v1",
  "daemon":{"version":"dev","commit":"none","date":"unknown"},
  "state":"offline",
  "data_plane":"not_implemented",
	"dns":"not_implemented",
  "active_profile_id":"",
  "profile_count":0,
	"network_name":"network.example.mesh",
	"self_addresses":["100.64.0.1/32"],
	"policy_rule_count":2,
	"paths":{"available":true,"peer_count":2,"direct_count":1,"relay_count":1,"pending_count":0},
	"relay":{"available":true,"home_region":7,"active_regions":2,"connected_regions":1,"regions":[{"region_id":7,"connected":true,"consecutive_failures":0}]},
	"network_changes":{"available":true,"observed":4,"endpoint_refreshes":3},
	"runtime_recovery":{"failures":4,"recoveries":3,"pending":true},
	"runtime":{"goroutines":11,"heap_alloc_bytes":12582912,"heap_in_use_bytes":13631488,"heap_objects":1200,"stack_in_use_bytes":1048576,"sys_bytes":25165824,"gc_cycles":7},
  "compatibility_note":"foundation only"
}`), nil
	})

	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if got, expected := status.DataPlane, "not_implemented"; got != expected {
		t.Fatalf("Status().DataPlane = %q, want %q", got, expected)
	}
	if got, expected := status.DNS, "not_implemented"; got != expected {
		t.Fatalf("Status().DNS = %q, want %q", got, expected)
	}
	if status.NetworkName != "network.example.mesh" ||
		len(status.SelfAddresses) != 1 ||
		status.SelfAddresses[0] != "100.64.0.1/32" ||
		status.PolicyRuleCount != 2 {
		t.Fatalf("Status() diagnostics = %#v", status)
	}
	if !status.PeerPaths.Available || status.PeerPaths.DirectCount != 1 ||
		status.PeerPaths.RelayCount != 1 {
		t.Fatalf("Status().PeerPaths = %#v, want one direct and one relay path", status.PeerPaths)
	}
	if !status.Relay.Available || status.Relay.HomeRegion != 7 ||
		status.Relay.ConnectedRegions != 1 || len(status.Relay.Regions) != 1 {
		t.Fatalf("Status().Relay = %#v, want connected home region 7", status.Relay)
	}
	if !status.NetworkChanges.Available || status.NetworkChanges.Observed != 4 ||
		status.NetworkChanges.EndpointRefreshes != 3 {
		t.Fatalf("Status().NetworkChanges = %#v, want four changes and three refreshes", status.NetworkChanges)
	}
	if status.RuntimeRecovery == nil || status.RuntimeRecovery.Failures != 4 ||
		status.RuntimeRecovery.Recoveries != 3 || !status.RuntimeRecovery.Pending {
		t.Fatalf("Status().RuntimeRecovery = %#v, want one pending recovery", status.RuntimeRecovery)
	}
	if status.Runtime == nil || status.Runtime.Goroutines != 11 ||
		status.Runtime.HeapAllocBytes != 12582912 || status.Runtime.HeapObjects != 1200 ||
		status.Runtime.SysBytes != 25165824 || status.Runtime.GCCycles != 7 {
		t.Fatalf("Status().Runtime = %#v, want aggregate runtime health", status.Runtime)
	}
}

func TestClient_StatusAcceptsOlderDaemonWithoutRuntimeRecovery(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{
  "api_version":"v1",
  "daemon":{"version":"dev","commit":"none","date":"unknown"},
  "state":"offline"
}`), nil
	})

	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.RuntimeRecovery != nil {
		t.Fatalf("Status().RuntimeRecovery = %#v, want unavailable", status.RuntimeRecovery)
	}
}

func TestClient_CreateProfile(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(request *http.Request) (*http.Response, error) {
		encoded, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if strings.Contains(string(encoded), "network_id") {
			t.Fatalf("request body contains forbidden network_id: %s", encoded)
		}
		if got, expected := request.Header.Get("Content-Type"), "application/json"; got != expected {
			t.Fatalf("Content-Type = %q, want %q", got, expected)
		}

		return jsonResponse(http.StatusCreated, `{
  "id":"00000000000000000000000000000001",
  "name":"production",
  "control_url":"https://transit.example.com",
  "created_at":"2026-09-09T00:00:00Z",
  "updated_at":"2026-09-09T00:00:00Z",
  "is_active":true
}`), nil
	})

	created, err := client.CreateProfile(t.Context(), CreateProfile{
		Name:       "production",
		ControlURL: "https://transit.example.com",
	})
	if err != nil {
		t.Fatalf("CreateProfile() error = %v", err)
	}
	if !created.IsActive {
		t.Fatal("CreateProfile().IsActive = false, want true")
	}
}

func TestClient_ActivateProfile(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("transport should not be called")
	})

	_, err := client.ActivateProfile(t.Context(), "../forged")
	if err == nil {
		t.Fatal("ActivateProfile() error = nil, want id validation error")
	}
}

func TestClient_APIError(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(
			http.StatusConflict,
			`{"api_version":"v1","code":"profile_exists","message":"profile name already exists"}`,
		), nil
	})

	_, err := client.CreateProfile(t.Context(), CreateProfile{
		Name:       "production",
		ControlURL: "https://transit.example.com",
	})
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) {
		t.Fatalf("CreateProfile() error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusConflict || apiErr.Code != "profile_exists" {
		t.Fatalf("APIError = %#v, want conflict/profile_exists", apiErr)
	}
}

func TestClient_ProbeControl(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/doctor/control" {
			t.Fatalf("request = %s %s, want POST /v1/doctor/control", request.Method, request.URL.Path)
		}

		return jsonResponse(http.StatusOK, `{
  "api_version":"v1",
  "profile_id":"00000000000000000000000000000001",
  "control_url":"https://transit.example.com",
  "protocol":"ts2021",
  "capability":142,
  "control_key_fingerprint":"sha256:test",
  "noise_established":true,
  "noise_version":142
}`), nil
	})

	result, err := client.ProbeControl(t.Context())
	if err != nil {
		t.Fatalf("ProbeControl() error = %v", err)
	}
	if got, expected := result.Capability, 142; got != expected {
		t.Fatalf("Capability = %d, want %d", got, expected)
	}
	if !result.NoiseEstablished || result.NoiseVersion != 142 {
		t.Fatalf("noise result = %#v, want established version 142", result)
	}
}

func TestClient_TrustControl(t *testing.T) {
	t.Parallel()

	fingerprint := "sha256:" + strings.Repeat("a", 64)
	client := newTestClient(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/control/trust" {
			t.Fatalf("request = %s %s, want POST /v1/control/trust", request.Method, request.URL.Path)
		}
		encoded, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if !strings.Contains(string(encoded), fingerprint) || strings.Contains(string(encoded), "network_id") {
			t.Fatalf("unexpected trust request: %s", encoded)
		}

		return jsonResponse(http.StatusOK, `{
  "api_version":"v1",
  "profile_id":"00000000000000000000000000000001",
  "control_key_fingerprint":"`+fingerprint+`",
  "already_pinned":false
}`), nil
	})

	trusted, err := client.TrustControl(t.Context(), fingerprint)
	if err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	if trusted.Fingerprint != fingerprint || trusted.AlreadyPinned {
		t.Fatalf("TrustControl() = %#v, want new pin", trusted)
	}
}

func TestClient_Login(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/login":
			encoded, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			if !strings.Contains(string(encoded), `"auth_key":"credential"`) {
				t.Fatalf("login request = %s, want in-memory auth key", encoded)
			}

			return jsonResponse(http.StatusOK, `{
  "api_version":"v1",
  "profile_id":"00000000000000000000000000000001",
  "state":"registered"
}`), nil
		case "/v1/login/complete":
			return jsonResponse(http.StatusOK, `{
  "api_version":"v1",
  "profile_id":"00000000000000000000000000000001",
  "state":"registered"
}`), nil
		default:
			t.Fatalf("unexpected login path %q", request.URL.Path)

			return nil, errors.New("unreachable")
		}
	})

	started, err := client.StartLogin(t.Context(), "credential")
	if err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	if started.State != "registered" {
		t.Fatalf("StartLogin().State = %q, want registered", started.State)
	}
	completed, err := client.CompleteLogin(t.Context())
	if err != nil {
		t.Fatalf("CompleteLogin() error = %v", err)
	}
	if completed.State != "registered" {
		t.Fatalf("CompleteLogin().State = %q, want registered", completed.State)
	}
}

func TestClient_RotateNodeKey(t *testing.T) {
	t.Parallel()

	client := newTestClient(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost ||
			request.URL.Path != "/v1/identity/node-key/rotate" {
			t.Fatalf(
				"request = %s %s, want POST /v1/identity/node-key/rotate",
				request.Method,
				request.URL.Path,
			)
		}
		if request.Body != nil || request.ContentLength != 0 ||
			request.Header.Get("Content-Type") != "" {
			t.Fatalf(
				"rotation request carried a body: body=%v length=%d content-type=%q",
				request.Body,
				request.ContentLength,
				request.Header.Get("Content-Type"),
			)
		}

		return jsonResponse(http.StatusOK, `{
  "api_version":"v1",
  "profile_id":"00000000000000000000000000000001",
  "state":"rotated"
}`), nil
	})

	rotated, err := client.RotateNodeKey(t.Context())
	if err != nil {
		t.Fatalf("RotateNodeKey() error = %v", err)
	}
	if rotated.ProfileID != "00000000000000000000000000000001" ||
		rotated.State != "rotated" {
		t.Fatalf("RotateNodeKey() = %#v, want committed rotation", rotated)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newTestClient(roundTrip roundTripFunc) *Client {
	return newWithHTTPClient(&http.Client{
		Transport: roundTrip,
	})
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

var _ http.RoundTripper = roundTripFunc(nil)
