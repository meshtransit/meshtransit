package legacyts2021

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/control"
)

func TestAuthenticatedRoutesBindAndDispatchClosedEndpointSet(t *testing.T) {
	t.Parallel()

	registration := &routeFactory{body: "registration"}
	mapSession := &routeFactory{body: "map"}
	routes, err := NewAuthenticatedRoutes(registration, mapSession)
	if err != nil {
		t.Fatalf("NewAuthenticatedRoutes() error = %v", err)
	}
	handler, err := routes.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	for _, test := range []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: credentialRegistrationPath, wantStatus: http.StatusOK, wantBody: "registration"},
		{path: mapSessionPath, wantStatus: http.StatusOK, wantBody: "map"},
		{path: "/machine/unknown", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n"},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.wantStatus || response.Body.String() != test.wantBody {
			t.Fatalf("route %q response = (%d, %q), want (%d, %q)", test.path, response.Code, response.Body.String(), test.wantStatus, test.wantBody)
		}
	}
	if registration.bindCalls != 1 || mapSession.bindCalls != 1 ||
		!registration.sawValidMachine || !mapSession.sawValidMachine {
		t.Fatalf("route bindings = (%+v, %+v), want one authenticated bind each", registration, mapSession)
	}
}

func TestAuthenticatedRoutesFailClosed(t *testing.T) {
	t.Parallel()

	if _, err := NewAuthenticatedRoutes(nil, &routeFactory{}); !errors.Is(err, ErrInvalidAuthenticatedRoutes) {
		t.Fatalf("NewAuthenticatedRoutes(nil) error = %v, want invalid routes", err)
	}
	routes, err := NewAuthenticatedRoutes(&routeFactory{}, &routeFactory{})
	if err != nil {
		t.Fatalf("NewAuthenticatedRoutes() error = %v", err)
	}
	if _, err := routes.Handler(control.AuthenticatedMachine{}); !errors.Is(err, ErrInvalidAuthenticatedRoutes) {
		t.Fatalf("Handler(zero machine) error = %v, want invalid routes", err)
	}
	wantErr := errors.New("controlled binding failure")
	routes, err = NewAuthenticatedRoutes(&routeFactory{err: wantErr}, &routeFactory{})
	if err != nil {
		t.Fatalf("NewAuthenticatedRoutes() error = %v", err)
	}
	if _, err := routes.Handler(authenticatedMachine(t)); !errors.Is(err, wantErr) ||
		!errors.Is(err, ErrInvalidAuthenticatedRoutes) {
		t.Fatalf("Handler() error = %v, want wrapped binding failure", err)
	}
}

type routeFactory struct {
	body            string
	err             error
	bindCalls       int
	sawValidMachine bool
}

func (factory *routeFactory) Handler(machine control.AuthenticatedMachine) (http.Handler, error) {
	factory.bindCalls++
	factory.sawValidMachine = machine.IsValid()
	if factory.err != nil {
		return nil, factory.err
	}
	return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(factory.body))
	}), nil
}
