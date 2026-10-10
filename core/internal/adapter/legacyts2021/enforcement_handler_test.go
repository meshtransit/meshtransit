package legacyts2021

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

const enforcementTestNodeKey = "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

type fakeEnforcementService struct {
	err    error
	report mapsession.ClientEnforcement
	calls  int
}

func (service *fakeEnforcementService) ReportEnforcement(_ context.Context, _ control.AuthenticatedMachine,
	report mapsession.ClientEnforcement) error {
	service.calls++
	service.report = report
	return service.err
}

func enforcementBody(fields string) string {
	return `{"version":1,"node_key":"` + enforcementTestNodeKey + `",` +
		`"digest":"sha256:65c3166a6062804e3b2a55acd157d70ce0ebf6fdd91130eecd280654a714251a",` +
		`"grants":5,"applied_at":"2026-10-09T12:00:00Z"` + fields + `}`
}

func TestEnforcementHandlerStoresAndClassifiesReports(t *testing.T) {
	telemetry, err := NewControlTelemetry(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	service := &fakeEnforcementService{}
	handler, err := NewEnforcementHandler(service, slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := control.NewAuthenticatedMachine(node.MachineKey{9})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := handler.Handler(machine)
	if err != nil {
		t.Fatal(err)
	}
	post := func(method, contentType, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(t.Context(), method, enforcementPath, strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		response := httptest.NewRecorder()
		bound.ServeHTTP(response, request)
		return response
	}

	if response := post(http.MethodPost, "application/json", enforcementBody("")); response.Code != http.StatusNoContent {
		t.Fatalf("valid report status = %d", response.Code)
	}
	applied := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	if service.report.Filter.Grants() != 5 || !service.report.AppliedAt.Equal(applied) ||
		!service.report.NodeKey.IsValid() {
		t.Fatalf("report = %+v", service.report)
	}
	for name, body := range map[string]string{
		"unknown field": enforcementBody(`,"extra":1`),
		"duplicate":     enforcementBody(`,"grants":6`),
		"version":       strings.Replace(enforcementBody(""), `"version":1`, `"version":2`, 1),
		"digest":        strings.Replace(enforcementBody(""), "sha256:65", "sha256:XX", 1),
		"node key":      strings.Replace(enforcementBody(""), "nodekey:01", "nodekey:zz", 1),
		"too large":     enforcementBody(`,"pad":"` + strings.Repeat("x", maxEnforcementReportBytes) + `"`),
		"trailing":      enforcementBody("") + "{}",
	} {
		if response := post(http.MethodPost, "application/json", body); response.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d", name, response.Code)
		}
	}
	if response := post(http.MethodGet, "application/json", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", response.Code)
	}
	if response := post(http.MethodPost, "text/plain", enforcementBody("")); response.Code != http.StatusBadRequest {
		t.Fatalf("text body status = %d", response.Code)
	}
	for err, want := range map[error]int{
		mapsession.ErrNoEnforcementStream:      http.StatusConflict,
		mapsession.ErrInvalidEnforcementReport: http.StatusBadRequest,
		mapsession.ErrEnforcementUnavailable:   http.StatusServiceUnavailable,
	} {
		service.err = err
		if response := post(http.MethodPost, "application/json", enforcementBody("")); response.Code != want {
			t.Errorf("%v: status = %d, want %d", err, response.Code, want)
		}
	}
	registry := prometheus.NewRegistry()
	if err := registry.Register(telemetry.enforcementReports); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil || len(families) != 1 {
		t.Fatalf("Gather() = %d families, %v", len(families), err)
	}
	for _, metric := range families[0].GetMetric() {
		if metric.GetLabel()[0].GetValue() == "stored" && metric.GetCounter().GetValue() != 1 {
			t.Fatalf("stored reports metric = %v", metric.GetCounter().GetValue())
		}
	}
	if _, err := NewEnforcementHandler(nil, slog.Default(), telemetry); err == nil {
		t.Fatal("handler without a service was accepted")
	}
}
