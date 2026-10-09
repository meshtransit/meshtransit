package legacyts2021

import (
	"errors"
	"net/http"

	"meshtransit.net/core/internal/control"
)

// ErrInvalidAuthenticatedRoutes reports incomplete session endpoint composition.
var ErrInvalidAuthenticatedRoutes = errors.New("legacyts2021: invalid authenticated routes")

// AuthenticatedRoutes dispatches the closed set of endpoints available inside
// one transport-authenticated HTTP/2 session.
type AuthenticatedRoutes struct {
	registration AuthenticatedHandlerFactory
	mapSession   AuthenticatedHandlerFactory
}

// NewAuthenticatedRoutes constructs an immutable authenticated endpoint router.
func NewAuthenticatedRoutes(
	registration AuthenticatedHandlerFactory,
	mapSession AuthenticatedHandlerFactory,
) (*AuthenticatedRoutes, error) {
	if registration == nil || mapSession == nil {
		return nil, ErrInvalidAuthenticatedRoutes
	}
	return &AuthenticatedRoutes{registration: registration, mapSession: mapSession}, nil
}

// Handler binds every route to the same transport-authenticated machine.
func (routes *AuthenticatedRoutes) Handler(
	machine control.AuthenticatedMachine,
) (http.Handler, error) {
	if routes == nil || routes.registration == nil || routes.mapSession == nil || !machine.IsValid() {
		return nil, ErrInvalidAuthenticatedRoutes
	}
	registration, err := routes.registration.Handler(machine)
	if err != nil || registration == nil {
		return nil, errors.Join(ErrInvalidAuthenticatedRoutes, err)
	}
	mapSession, err := routes.mapSession.Handler(machine)
	if err != nil || mapSession == nil {
		return nil, errors.Join(ErrInvalidAuthenticatedRoutes, err)
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request == nil || request.URL == nil {
			http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		switch request.URL.Path {
		case credentialRegistrationPath:
			registration.ServeHTTP(response, request)
		case mapSessionPath:
			mapSession.ServeHTTP(response, request)
		default:
			http.NotFound(response, request)
		}
	}), nil
}

var _ AuthenticatedHandlerFactory = (*AuthenticatedRoutes)(nil)
