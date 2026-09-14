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
	Service   RegistrationService
	IDs       RegistrationIDGenerator
	Logger    *slog.Logger
	Telemetry *ControlTelemetry
}

// CredentialRegistrationHandler handles only the credential-enrollment subset
// of the pinned client profile. It starts no goroutines and retains no request state.
type CredentialRegistrationHandler struct {
	service   RegistrationService
	ids       RegistrationIDGenerator
	logger    *slog.Logger
	telemetry *ControlTelemetry
}

// NewCredentialRegistrationHandler validates and constructs the endpoint adapter.
func NewCredentialRegistrationHandler(
	options CredentialRegistrationHandlerOptions,
) (*CredentialRegistrationHandler, error) {
	if options.Service == nil || options.IDs == nil || options.Logger == nil || options.Telemetry == nil {
		return nil, ErrInvalidCredentialRegistrationHandler
	}
	return &CredentialRegistrationHandler{
		service:   options.Service,
		ids:       options.IDs,
		logger:    options.Logger,
		telemetry: options.Telemetry,
	}, nil
}

// Handler binds one transport-authenticated machine to a standard HTTP
// handler. Callers cannot supply identity through headers, query parameters, or
// request context values.
func (handler *CredentialRegistrationHandler) Handler(
	machine control.AuthenticatedMachine,
) (http.Handler, error) {
	if handler == nil || handler.service == nil || handler.ids == nil ||
		handler.logger == nil || handler.telemetry == nil || !machine.IsValid() {
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
	startedAt := handler.telemetry.registrations.start()
	telemetryResult := registrationInvalidRequest
	defer func() {
		handler.telemetry.registrations.finish(startedAt, telemetryResult)
	}()
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
		telemetryResult = registrationUnavailable
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
		failure := classifyRegistrationFailure(err)
		telemetryResult = failure.result
		if failure.status == http.StatusServiceUnavailable && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			handler.logger.ErrorContext(request.Context(), "credential registration failed", "error", err)
		}
		http.Error(response, http.StatusText(failure.status), failure.status)
		return
	}
	if !result.IsValid() || result.RegistrationID() != registrationID {
		telemetryResult = registrationUnavailable
		handler.logger.ErrorContext(request.Context(), "credential registration returned invalid result")
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	response.Header().Set("Content-Type", "application/json")
	telemetryResult = registrationAuthorized
	response.WriteHeader(http.StatusOK)
	if err := WriteAuthorizedRegistrationResponse(response); err != nil {
		handler.logger.DebugContext(request.Context(), "registration response write failed", "error", err)
	}
}

type registrationFailure struct {
	status int
	result registrationResult
}

func classifyRegistrationFailure(err error) registrationFailure {
	switch {
	case errors.Is(err, control.ErrInvalidRegistrationRequest):
		return registrationFailure{status: http.StatusBadRequest, result: registrationInvalidRequest}
	case errors.Is(err, intake.ErrAuthenticationFailed):
		return registrationFailure{status: http.StatusUnauthorized, result: registrationAuthenticationFailed}
	case errors.Is(err, registration.ErrIntentConflict):
		return registrationFailure{status: http.StatusConflict, result: registrationConflict}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return registrationFailure{status: http.StatusServiceUnavailable, result: registrationCanceled}
	default:
		return registrationFailure{status: http.StatusServiceUnavailable, result: registrationUnavailable}
	}
}

func setResponseHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}
