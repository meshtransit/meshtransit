package legacyts2021

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

const credentialRegistrationPath = "/machine/register"

// ErrInvalidCredentialRegistrationHandler reports missing dependencies or an
// unauthenticated transport identity.
var ErrInvalidCredentialRegistrationHandler = errors.New("control http: invalid credential registration handler")

// RegistrationService is the authenticated application capability consumed by
// the credential registration endpoint.
type RegistrationService interface {
	Register(
		context.Context,
		control.AuthenticatedMachine,
		control.RegistrationRequest,
	) (registration.Result, error)
}

// RegistrationIDGenerator creates server-owned idempotency identities.
type RegistrationIDGenerator interface {
	NewRegistrationID() (enrollment.RegistrationID, error)
}

// CredentialRegistrationHandlerOptions contains immutable endpoint dependencies.
type CredentialRegistrationHandlerOptions struct {
	Service RegistrationService
	IDs     RegistrationIDGenerator
	Logger  *slog.Logger
}

// CredentialRegistrationHandler handles only the credential-enrollment subset
// of the pinned client profile. It starts no goroutines and retains no request state.
type CredentialRegistrationHandler struct {
	service RegistrationService
	ids     RegistrationIDGenerator
	logger  *slog.Logger
}

// NewCredentialRegistrationHandler validates and constructs the endpoint adapter.
func NewCredentialRegistrationHandler(
	options CredentialRegistrationHandlerOptions,
) (*CredentialRegistrationHandler, error) {
	if options.Service == nil || options.IDs == nil || options.Logger == nil {
		return nil, ErrInvalidCredentialRegistrationHandler
	}
	return &CredentialRegistrationHandler{
		service: options.Service,
		ids:     options.IDs,
		logger:  options.Logger,
	}, nil
}

// Handler binds one transport-authenticated machine to a standard HTTP
// handler. Callers cannot supply identity through headers, query parameters, or
// request context values.
func (handler *CredentialRegistrationHandler) Handler(
	machine control.AuthenticatedMachine,
) (http.Handler, error) {
	if handler == nil || handler.service == nil || handler.ids == nil ||
		handler.logger == nil || !machine.IsValid() {
		return nil, ErrInvalidCredentialRegistrationHandler
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		handler.serveAuthenticated(response, request, machine)
	}), nil
}

func (handler *CredentialRegistrationHandler) serveAuthenticated(
	response http.ResponseWriter,
	request *http.Request,
	machine control.AuthenticatedMachine,
) {
	setResponseHeaders(response)
	if request.URL == nil || request.URL.Path != credentialRegistrationPath {
		http.NotFound(response, request)
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.RawQuery != "" {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(response, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	registrationID, err := handler.ids.NewRegistrationID()
	if err != nil || !registrationID.IsValid() {
		handler.logger.ErrorContext(request.Context(), "registration id generation failed", "error", err)
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	registrationRequest, err := DecodeCredentialRegistration(request.Body, registrationID)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	result, err := handler.service.Register(request.Context(), machine, registrationRequest)
	if err != nil {
		statusCode := registrationFailureStatus(err)
		if statusCode == http.StatusServiceUnavailable && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			handler.logger.ErrorContext(request.Context(), "credential registration failed", "error", err)
		}
		http.Error(response, http.StatusText(statusCode), statusCode)
		return
	}
	if !result.IsValid() || result.RegistrationID() != registrationID {
		handler.logger.ErrorContext(request.Context(), "credential registration returned invalid result")
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	if err := WriteAuthorizedRegistrationResponse(response); err != nil {
		handler.logger.DebugContext(request.Context(), "registration response write failed", "error", err)
	}
}

func registrationFailureStatus(err error) int {
	switch {
	case errors.Is(err, control.ErrInvalidRegistrationRequest):
		return http.StatusBadRequest
	case errors.Is(err, intake.ErrAuthenticationFailed):
		return http.StatusUnauthorized
	case errors.Is(err, registration.ErrIntentConflict):
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}

func setResponseHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}
