package legacyts2021

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const registrationRequestBody = `{
  "Version":142,
  "NodeKey":"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "OldNodeKey":"nodekey:0000000000000000000000000000000000000000000000000000000000000000",
  "NLKey":"nlpub:0000000000000000000000000000000000000000000000000000000000000000",
  "Auth":{"AuthKey":"mtc1.01890f90-0000-7000-8000-000000000001.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"},
  "Expiry":"0001-01-01T00:00:00Z",
  "Followup":"",
  "Hostinfo":{"Hostname":"node-one.example"},
  "NodeKeySignature":null
}`

func TestCredentialRegistrationHandlerAuthorizesBoundRequest(t *testing.T) {
	t.Parallel()

	service := newRecordingRegistrationService(t)
	ids := &fixedRegistrationIDGenerator{id: parseRegistrationID(t)}
	handler := newCredentialRegistrationHandler(t, service, ids)
	authenticated := authenticatedHandler(t, handler)

	response := serveRegistration(t, authenticated, http.MethodPost, credentialRegistrationPath, registrationRequestBody)
	if response.Code != http.StatusOK || response.Body.String() != "{\"MachineAuthorized\":true}\n" {
		t.Fatalf("registration response = (%d, %q), want authorized", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("registration response headers = %v", response.Header())
	}
	if service.calls.Load() != 1 || ids.calls.Load() != 1 || !service.sawValid.Load() {
		t.Fatal("credential registration did not generate and bind exactly one valid request")
	}
	metrics := gatherControlMetrics(t, handler.telemetry)
	if !strings.Contains(
		metrics,
		`meshtransit_control_registration_requests_total{result="authorized"} 1`,
	) || !strings.Contains(metrics, `meshtransit_control_registrations_active 0`) ||
		!strings.Contains(
			metrics,
			`meshtransit_control_registration_duration_seconds_count{result="authorized"} 1`,
		) {
		t.Fatalf("authorized registration metrics are incomplete: %s", metrics)
	}
}

func TestCredentialRegistrationHandlerRejectsUnrelatedCommittedResult(t *testing.T) {
	t.Parallel()

	service := newRecordingRegistrationService(t)
	otherID, err := enrollment.ParseRegistrationID("01890f90-0000-7000-8000-000000000006")
	if err != nil {
		t.Fatalf("enrollment.ParseRegistrationID() error = %v", err)
	}
	service.result, err = registration.NewResult(
		otherID,
		service.result.Scope(),
		service.result.NodeID(),
		service.result.Hostname(),
		service.result.Disposition(),
		service.result.NetworkRevision(),
	)
	if err != nil {
		t.Fatalf("registration.NewResult() error = %v", err)
	}
	handler := newCredentialRegistrationHandler(
		t,
		service,
		&fixedRegistrationIDGenerator{id: parseRegistrationID(t)},
	)
	response := serveRegistration(
		t,
		authenticatedHandler(t, handler),
		http.MethodPost,
		credentialRegistrationPath,
		registrationRequestBody,
	)
	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), "MachineAuthorized") {
		t.Fatalf("unrelated result response = (%d, %q)", response.Code, response.Body.String())
	}
}

func TestCredentialRegistrationHandlerRejectsInvalidHTTPBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantStatus  int
	}{
		{
			name:        "wrong path",
			method:      http.MethodPost,
			path:        "/machine/map",
			contentType: "application/json",
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "wrong method",
			method:      http.MethodGet,
			path:        credentialRegistrationPath,
			contentType: "application/json",
			wantStatus:  http.StatusMethodNotAllowed,
		},
		{
			name:        "query parameters",
			method:      http.MethodPost,
			path:        credentialRegistrationPath + "?scope=untrusted",
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:       "missing content type",
			method:     http.MethodPost,
			path:       credentialRegistrationPath,
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:        "wrong content type",
			method:      http.MethodPost,
			path:        credentialRegistrationPath,
			contentType: "text/plain",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "invalid body",
			method:      http.MethodPost,
			path:        credentialRegistrationPath,
			contentType: "application/json",
			body:        `{}`,
			wantStatus:  http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			service := newRecordingRegistrationService(t)
			ids := &fixedRegistrationIDGenerator{id: parseRegistrationID(t)}
			handler := newCredentialRegistrationHandler(t, service, ids)
			authenticated := authenticatedHandler(t, handler)
			request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			authenticated.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if service.calls.Load() != 0 {
				t.Fatal("invalid HTTP boundary reached registration service")
			}
		})
	}
}

func TestCredentialRegistrationHandlerMapsServiceFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serviceErr error
		wantStatus int
		wantResult string
	}{
		{
			name:       "invalid binding",
			serviceErr: control.ErrInvalidRegistrationRequest,
			wantStatus: http.StatusBadRequest,
			wantResult: "invalid_request",
		},
		{
			name:       "credential rejected",
			serviceErr: intake.ErrAuthenticationFailed,
			wantStatus: http.StatusUnauthorized,
			wantResult: "authentication_failed",
		},
		{
			name:       "intent conflict",
			serviceErr: registration.ErrIntentConflict,
			wantStatus: http.StatusConflict,
			wantResult: "conflict",
		},
		{
			name:       "request canceled",
			serviceErr: context.Canceled,
			wantStatus: http.StatusServiceUnavailable,
			wantResult: "canceled",
		},
		{
			name:       "request deadline",
			serviceErr: context.DeadlineExceeded,
			wantStatus: http.StatusServiceUnavailable,
			wantResult: "canceled",
		},
		{
			name:       "internal failure",
			serviceErr: errors.New("controlled service failure"),
			wantStatus: http.StatusServiceUnavailable,
			wantResult: "unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			service := newRecordingRegistrationService(t)
			service.err = test.serviceErr
			handler := newCredentialRegistrationHandler(
				t,
				service,
				&fixedRegistrationIDGenerator{id: parseRegistrationID(t)},
			)
			response := serveRegistration(
				t,
				authenticatedHandler(t, handler),
				http.MethodPost,
				credentialRegistrationPath,
				registrationRequestBody,
			)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if strings.Contains(response.Body.String(), test.serviceErr.Error()) {
				t.Fatal("registration response disclosed internal service error")
			}
			metrics := gatherControlMetrics(t, handler.telemetry)
			wantMetric := `meshtransit_control_registration_requests_total{result="` +
				test.wantResult + `"} 1`
			if !strings.Contains(metrics, wantMetric) {
				t.Fatalf("registration metrics missing %q: %s", wantMetric, metrics)
			}
		})
	}
}

func TestCredentialRegistrationHandlerFailsClosed(t *testing.T) {
	t.Parallel()

	service := newRecordingRegistrationService(t)
	ids := &fixedRegistrationIDGenerator{id: parseRegistrationID(t)}
	if _, err := NewCredentialRegistrationHandler(CredentialRegistrationHandlerOptions{}); !errors.Is(
		err,
		ErrInvalidCredentialRegistrationHandler,
	) {
		t.Fatalf("NewCredentialRegistrationHandler(empty) error = %v, want invalid handler", err)
	}
	handler := newCredentialRegistrationHandler(t, service, ids)
	if _, err := handler.Handler(control.AuthenticatedMachine{}); !errors.Is(
		err,
		ErrInvalidCredentialRegistrationHandler,
	) {
		t.Fatalf("Handler(zero machine) error = %v, want invalid handler", err)
	}
	if _, err := (*CredentialRegistrationHandler)(nil).Handler(authenticatedMachine(t)); !errors.Is(
		err,
		ErrInvalidCredentialRegistrationHandler,
	) {
		t.Fatalf("nil Handler() error = %v, want invalid handler", err)
	}

	ids.err = errors.New("controlled id failure")
	response := serveRegistration(
		t,
		authenticatedHandler(t, handler),
		http.MethodPost,
		credentialRegistrationPath,
		registrationRequestBody,
	)
	if response.Code != http.StatusServiceUnavailable || service.calls.Load() != 0 {
		t.Fatalf("id failure response = %d with %d service calls", response.Code, service.calls.Load())
	}

	ids.err = nil
	service.result = registration.Result{}
	response = serveRegistration(
		t,
		authenticatedHandler(t, handler),
		http.MethodPost,
		credentialRegistrationPath,
		registrationRequestBody,
	)
	if response.Code != http.StatusServiceUnavailable || service.calls.Load() != 1 ||
		strings.Contains(response.Body.String(), "MachineAuthorized") {
		t.Fatalf("invalid result response = (%d, %q) with %d service calls", response.Code, response.Body.String(), service.calls.Load())
	}
}

func TestCredentialRegistrationHandlerIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	service := newRecordingRegistrationService(t)
	handler := newCredentialRegistrationHandler(
		t,
		service,
		&fixedRegistrationIDGenerator{id: parseRegistrationID(t)},
	)
	authenticated := authenticatedHandler(t, handler)

	const requestCount = 32
	statuses := make([]int, requestCount)
	var group sync.WaitGroup
	for index := range requestCount {
		group.Go(func() {
			response := serveRegistration(
				t,
				authenticated,
				http.MethodPost,
				credentialRegistrationPath,
				registrationRequestBody,
			)
			statuses[index] = response.Code
		})
	}
	group.Wait()
	for index, status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("concurrent response %d status = %d, want 200", index, status)
		}
	}
	if service.calls.Load() != requestCount {
		t.Fatalf("service calls = %d, want %d", service.calls.Load(), requestCount)
	}
	metrics := gatherControlMetrics(t, handler.telemetry)
	wantMetric := `meshtransit_control_registration_requests_total{result="authorized"} 32`
	if !strings.Contains(metrics, wantMetric) ||
		!strings.Contains(metrics, `meshtransit_control_registrations_active 0`) {
		t.Fatalf("concurrent registration metrics are incomplete: %s", metrics)
	}
}

type recordingRegistrationService struct {
	calls    atomic.Int64
	sawValid atomic.Bool
	result   registration.Result
	err      error
}

func (service *recordingRegistrationService) Register(
	_ context.Context,
	machine control.AuthenticatedMachine,
	request control.RegistrationRequest,
) (registration.Result, error) {
	service.calls.Add(1)
	if machine.IsValid() && request.IsValid() {
		service.sawValid.Store(true)
	}
	return service.result, service.err
}

func newRecordingRegistrationService(t *testing.T) *recordingRegistrationService {
	t.Helper()

	workspaceID, err := workspace.ParseID("01890f90-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f90-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	nodeID, err := node.ParseID("01890f90-0000-7000-8000-000000000005")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	result, err := registration.NewResult(
		parseRegistrationID(t),
		scope,
		nodeID,
		hostname,
		registration.DispositionCreated,
		1,
	)
	if err != nil {
		t.Fatalf("registration.NewResult() error = %v", err)
	}
	return &recordingRegistrationService{result: result}
}

type fixedRegistrationIDGenerator struct {
	id    enrollment.RegistrationID
	err   error
	calls atomic.Int64
}

func (generator *fixedRegistrationIDGenerator) NewRegistrationID() (enrollment.RegistrationID, error) {
	generator.calls.Add(1)
	return generator.id, generator.err
}

func newCredentialRegistrationHandler(
	t *testing.T,
	service RegistrationService,
	ids RegistrationIDGenerator,
) *CredentialRegistrationHandler {
	t.Helper()

	handler, err := NewCredentialRegistrationHandler(CredentialRegistrationHandlerOptions{
		Service:   service,
		IDs:       ids,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Telemetry: controlTelemetryFixture(t),
	})
	if err != nil {
		t.Fatalf("NewCredentialRegistrationHandler() error = %v", err)
	}
	return handler
}

func authenticatedHandler(t *testing.T, handler *CredentialRegistrationHandler) http.Handler {
	t.Helper()

	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("CredentialRegistrationHandler.Handler() error = %v", err)
	}
	return authenticated
}

func authenticatedMachine(t *testing.T) control.AuthenticatedMachine {
	t.Helper()

	machineKey, err := node.NewMachineKey([32]byte{0: 1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("control.NewAuthenticatedMachine() error = %v", err)
	}
	return machine
}

func serveRegistration(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

var (
	_ RegistrationService     = (*recordingRegistrationService)(nil)
	_ RegistrationIDGenerator = (*fixedRegistrationIDGenerator)(nil)
)
