package legacyts2021

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/control"
	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
)

func TestMapSessionHandlerReturnsAuthorizedFullSnapshot(t *testing.T) {
	t.Parallel()

	service := &recordingMapSessionService{snapshot: mapSnapshotFixture(t)}
	handler := newMapSessionHandler(t, service)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	response := serveMap(t, authenticated, mapRequestBody)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != mapResponseContentType ||
		response.Header().Get("Cache-Control") != "no-store" || response.Body.Len() == 0 {
		t.Fatalf("map response = (%d, %v, %d bytes)", response.Code, response.Header(), response.Body.Len())
	}
	if service.calls.Load() != 1 || !service.sawValid.Load() {
		t.Fatal("map handler did not submit exactly one valid bound request")
	}
	if !service.sawDeadline.Load() {
		t.Fatal("map handler did not bound application work with a deadline")
	}
	metrics := gatherControlMetrics(t, handler.telemetry)
	if !strings.Contains(metrics, `meshtransit_control_map_requests_total{result="authorized"} 1`) ||
		!strings.Contains(metrics, `meshtransit_control_map_requests_active 0`) {
		t.Fatalf("authorized map metrics are incomplete: %s", metrics)
	}
}

func TestMapSessionHandlerRejectsInvalidHTTPBoundary(t *testing.T) {
	t.Parallel()

	service := &recordingMapSessionService{snapshot: mapSnapshotFixture(t)}
	handler := newMapSessionHandler(t, service)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	for _, test := range []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "wrong path", method: http.MethodPost, path: credentialRegistrationPath, contentType: "application/json", body: mapRequestBody, wantStatus: http.StatusNotFound},
		{name: "wrong method", method: http.MethodGet, path: mapSessionPath, contentType: "application/json", body: mapRequestBody, wantStatus: http.StatusMethodNotAllowed},
		{name: "query", method: http.MethodPost, path: mapSessionPath + "?network=untrusted", contentType: "application/json", body: mapRequestBody, wantStatus: http.StatusBadRequest},
		{name: "wrong content type", method: http.MethodPost, path: mapSessionPath, contentType: "text/plain", body: mapRequestBody, wantStatus: http.StatusUnsupportedMediaType},
		{name: "invalid body", method: http.MethodPost, path: mapSessionPath, contentType: "application/json", body: `{}`, wantStatus: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			authenticated.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
	if service.calls.Load() != 0 {
		t.Fatalf("invalid boundaries reached service %d times", service.calls.Load())
	}
}

func TestMapSessionHandlerMapsServiceFailures(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantResult string
	}{
		{name: "unauthorized", err: mapsession.ErrUnauthorized, wantStatus: http.StatusUnauthorized, wantResult: "authentication_failed"},
		{name: "canceled", err: context.Canceled, wantStatus: http.StatusServiceUnavailable, wantResult: "canceled"},
		{name: "unavailable", err: errors.New("controlled failure"), wantStatus: http.StatusServiceUnavailable, wantResult: "unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &recordingMapSessionService{snapshot: mapSnapshotFixture(t), err: test.err}
			handler := newMapSessionHandler(t, service)
			authenticated, err := handler.Handler(authenticatedMachine(t))
			if err != nil {
				t.Fatalf("Handler() error = %v", err)
			}
			response := serveMap(t, authenticated, mapRequestBody)
			if response.Code != test.wantStatus || strings.Contains(response.Body.String(), test.err.Error()) {
				t.Fatalf("map failure response = (%d, %q)", response.Code, response.Body.String())
			}
			metrics := gatherControlMetrics(t, handler.telemetry)
			wantMetric := `meshtransit_control_map_requests_total{result="` + test.wantResult + `"} 1`
			if !strings.Contains(metrics, wantMetric) {
				t.Fatalf("map metrics missing %q: %s", wantMetric, metrics)
			}
		})
	}
}

type recordingMapSessionService struct {
	snapshot    mapsession.Snapshot
	err         error
	calls       atomic.Int64
	sawValid    atomic.Bool
	sawDeadline atomic.Bool
}

func (service *recordingMapSessionService) Open(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request mapsession.Request,
) (mapsession.Snapshot, error) {
	service.calls.Add(1)
	service.sawValid.Store(machine.IsValid() && request.IsValid())
	_, hasDeadline := ctx.Deadline()
	service.sawDeadline.Store(hasDeadline)
	return service.snapshot, service.err
}

func newMapSessionHandler(t *testing.T, service MapSessionService) *MapSessionHandler {
	t.Helper()
	return newMapSessionHandlerWithStreams(t, service, unusedMapStreamService{})
}

func newMapSessionHandlerWithStreams(
	t *testing.T,
	service MapSessionService,
	streams MapStreamService,
) *MapSessionHandler {
	t.Helper()
	telemetry, err := NewControlTelemetry(8, 8)
	if err != nil {
		t.Fatalf("NewControlTelemetry() error = %v", err)
	}
	handler, err := NewMapSessionHandler(MapSessionHandlerOptions{
		Service:   service,
		Streams:   streams,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Telemetry: telemetry,
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewMapSessionHandler() error = %v", err)
	}
	return handler
}

type unusedMapStreamService struct{}

func (unusedMapStreamService) Serve(
	context.Context,
	control.AuthenticatedMachine,
	mapsession.Request,
	mapsession.StreamSink,
) error {
	return errors.New("unused stream service called")
}

func serveMap(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		mapSessionPath,
		strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestMapSuspensionIsRetryableAndCounted(t *testing.T) {
	t.Parallel()

	failure := classifyMapFailure(errors.Join(mapsession.ErrSuspended, errors.New("wrapped")))
	if failure.status != http.StatusLocked || failure.result != mapSuspended {
		t.Fatalf("classifyMapFailure(suspended) = %+v, want 423 suspended", failure)
	}
	for _, started := range []bool{false, true} {
		if result := classifyMapStreamResult(mapsession.ErrSuspended, started); result != mapSuspended {
			t.Fatalf("classifyMapStreamResult(suspended, %t) = %v", started, result)
		}
	}
	if classifyMapFailure(mapsession.ErrUnauthorized).status != http.StatusUnauthorized {
		t.Fatal("an identity without authority must still be refused")
	}
	if mapSuspended.label() != "suspended" {
		t.Fatalf("label = %q", mapSuspended.label())
	}
}
