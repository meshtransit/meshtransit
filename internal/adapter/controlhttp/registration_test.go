package controlhttp

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
	"github.com/meshtransit/meshtransit/internal/node"
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

	service := &recordingRegistrationService{}
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

			service := &recordingRegistrationService{}
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
	}{
		{name: "invalid binding", serviceErr: control.ErrInvalidRegistrationRequest, wantStatus: http.StatusBadRequest},
		{name: "credential rejected", serviceErr: intake.ErrAuthenticationFailed, wantStatus: http.StatusUnauthorized},
		{name: "intent conflict", serviceErr: registration.ErrIntentConflict, wantStatus: http.StatusConflict},
		{name: "request canceled", serviceErr: context.Canceled, wantStatus: http.StatusServiceUnavailable},
		{name: "request deadline", serviceErr: context.DeadlineExceeded, wantStatus: http.StatusServiceUnavailable},
		{
			name:       "internal failure",
			serviceErr: errors.New("controlled service failure"),
			wantStatus: http.StatusServiceUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			service := &recordingRegistrationService{err: test.serviceErr}
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
		})
	}
}

func TestCredentialRegistrationHandlerFailsClosed(t *testing.T) {
	t.Parallel()

	service := &recordingRegistrationService{}
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
}

func TestCredentialRegistrationHandlerIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	service := &recordingRegistrationService{}
	handler := newCredentialRegistrationHandler(t, service, intake.PublicRegistrationIDGenerator{})
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
}

type recordingRegistrationService struct {
	calls    atomic.Int64
	sawValid atomic.Bool
	err      error
}

func (service *recordingRegistrationService) Register(
	_ context.Context,
	machine control.AuthenticatedMachine,
	request control.RegistrationRequest,
) (registration.Command, error) {
	service.calls.Add(1)
	if machine.IsValid() && request.IsValid() {
		service.sawValid.Store(true)
	}
	return registration.Command{}, service.err
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
		Service: service,
		IDs:     ids,
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
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

func parseRegistrationID(t testing.TB) enrollment.RegistrationID {
	t.Helper()

	id, err := enrollment.ParseRegistrationID("01890f90-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatalf("enrollment.ParseRegistrationID() error = %v", err)
	}
	return id
}

var (
	_ RegistrationService     = (*recordingRegistrationService)(nil)
	_ RegistrationIDGenerator = (*fixedRegistrationIDGenerator)(nil)
)
