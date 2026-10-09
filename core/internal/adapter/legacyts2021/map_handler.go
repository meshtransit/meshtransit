package legacyts2021

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/control"
	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
)

const mapSessionPath = "/machine/map"

const (
	minimumMapOperationTimeout = 100 * time.Millisecond
	maximumMapOperationTimeout = time.Minute
)

// ErrInvalidMapSessionHandler reports missing dependencies or transport identity.
var ErrInvalidMapSessionHandler = errors.New("control http: invalid map session handler")

// MapSessionService is the authenticated application capability consumed by the map endpoint.
type MapSessionService interface {
	Open(
		context.Context,
		control.AuthenticatedMachine,
		mapsession.Request,
	) (mapsession.Snapshot, error)
}

// MapStreamService is the caller-owned streaming application capability.
type MapStreamService interface {
	Serve(
		context.Context,
		control.AuthenticatedMachine,
		mapsession.Request,
		mapsession.StreamSink,
	) error
}

// MapSessionHandlerOptions contains immutable endpoint dependencies.
type MapSessionHandlerOptions struct {
	Service   MapSessionService
	Streams   MapStreamService
	Logger    *slog.Logger
	Telemetry *ControlTelemetry
	Timeout   time.Duration
}

// MapSessionHandler serves the one-shot full-map subset of the pinned profile.
// It starts no goroutines and retains no request or snapshot state.
type MapSessionHandler struct {
	service   MapSessionService
	streams   MapStreamService
	logger    *slog.Logger
	telemetry *ControlTelemetry
	timeout   time.Duration
}

// NewMapSessionHandler validates and constructs the map endpoint adapter.
func NewMapSessionHandler(options MapSessionHandlerOptions) (*MapSessionHandler, error) {
	if options.Service == nil || options.Streams == nil || options.Logger == nil ||
		options.Telemetry == nil ||
		options.Timeout < minimumMapOperationTimeout || options.Timeout > maximumMapOperationTimeout {
		return nil, ErrInvalidMapSessionHandler
	}
	return &MapSessionHandler{
		service:   options.Service,
		streams:   options.Streams,
		logger:    options.Logger,
		telemetry: options.Telemetry,
		timeout:   options.Timeout,
	}, nil
}

// Handler binds one transport-authenticated machine to the map endpoint.
func (handler *MapSessionHandler) Handler(
	machine control.AuthenticatedMachine,
) (http.Handler, error) {
	if handler == nil || handler.service == nil || handler.streams == nil || handler.logger == nil ||
		handler.telemetry == nil || handler.timeout < minimumMapOperationTimeout ||
		handler.timeout > maximumMapOperationTimeout || !machine.IsValid() {
		return nil, ErrInvalidMapSessionHandler
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		handler.serveAuthenticated(response, request, machine)
	}), nil
}

func (handler *MapSessionHandler) serveAuthenticated(
	response http.ResponseWriter,
	request *http.Request,
	machine control.AuthenticatedMachine,
) {
	setResponseHeaders(response)
	if request.URL == nil || request.URL.Path != mapSessionPath {
		http.NotFound(response, request)
		return
	}
	startedAt := handler.telemetry.maps.start()
	telemetryResult := mapInvalidRequest
	defer func() { handler.telemetry.maps.finish(startedAt, telemetryResult) }()
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
	mapRequest, streaming, compression, err := decodeMapRequest(request.Body)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if streaming {
		handler.telemetry.maps.streamOpened()
		defer handler.telemetry.maps.streamClosed()
		telemetryResult = handler.serveStream(
			response,
			request,
			machine,
			mapRequest,
			compression,
		)
		return
	}
	operationCtx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	snapshot, err := handler.service.Open(operationCtx, machine, mapRequest)
	if err != nil {
		failure := classifyMapFailure(err)
		telemetryResult = failure.result
		if failure.status == http.StatusServiceUnavailable && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			handler.logger.ErrorContext(request.Context(), "map snapshot failed", "error", err)
		}
		http.Error(response, http.StatusText(failure.status), failure.status)
		return
	}
	encoded, err := encodeFullMapResponse(
		snapshot,
		mapRequest.CapabilityVersion(),
		compression,
	)
	if err != nil {
		telemetryResult = mapUnavailable
		handler.logger.ErrorContext(request.Context(), "map response encoding failed", "error", err)
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer clear(encoded)
	response.Header().Set("Content-Type", mapResponseContentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.WriteHeader(http.StatusOK)
	written, err := response.Write(encoded)
	if err != nil || written != len(encoded) {
		telemetryResult = mapUnavailable
		if err == nil {
			err = io.ErrShortWrite
		}
		handler.logger.DebugContext(request.Context(), "map response write failed", "error", err)
		return
	}
	telemetryResult = mapAuthorized
}

func (handler *MapSessionHandler) serveStream(
	response http.ResponseWriter,
	request *http.Request,
	machine control.AuthenticatedMachine,
	mapRequest mapsession.Request,
	compression mapResponseCompression,
) mapResult {
	sink := newMapStreamSink(
		response,
		mapRequest.CapabilityVersion(),
		compression,
	)
	err := handler.streams.Serve(request.Context(), machine, mapRequest, sink)
	result := classifyMapStreamResult(err, sink.started())
	if !sink.started() {
		failure := classifyMapFailure(err)
		http.Error(response, http.StatusText(failure.status), failure.status)
		return result
	}
	if result == mapStreamClosed {
		return result
	}
	if result == mapSuspended {
		// The client keeps its identity and retries until the Device resumes.
		handler.logger.InfoContext(request.Context(), "map stream paused for a suspended Device")
		return result
	}
	if result == mapAuthorityChanged {
		// The client was told its authority ended (withdrawal or expiry); record
		// why, since it stays offline until it reconnects.
		handler.logger.WarnContext(request.Context(), "map stream ended authority", "error", err)
		return result
	}
	if err == nil {
		err = mapsession.ErrStreamUnavailable
	}
	handler.logger.ErrorContext(request.Context(), "map stream terminated", "error", err)
	return result
}

type mapFailure struct {
	status int
	result mapResult
}

func classifyMapFailure(err error) mapFailure {
	switch {
	case errors.Is(err, mapsession.ErrSuspended):
		// 423 tells the client its identity stands and it should retry later.
		return mapFailure{status: http.StatusLocked, result: mapSuspended}
	case errors.Is(err, mapsession.ErrUnauthorized), errors.Is(err, control.ErrInvalidAuthenticatedNode):
		return mapFailure{status: http.StatusUnauthorized, result: mapAuthenticationFailed}
	case errors.Is(err, mapsession.ErrInvalidRequest):
		return mapFailure{status: http.StatusBadRequest, result: mapInvalidRequest}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return mapFailure{status: http.StatusServiceUnavailable, result: mapCanceled}
	default:
		return mapFailure{status: http.StatusServiceUnavailable, result: mapUnavailable}
	}
}

func classifyMapStreamResult(err error, started bool) mapResult {
	switch {
	case errors.Is(err, mapsession.ErrSuspended):
		return mapSuspended
	case started && errors.Is(err, mapsession.ErrUnauthorized):
		return mapAuthorityChanged
	case errors.Is(err, mapsession.ErrUnauthorized),
		errors.Is(err, control.ErrInvalidAuthenticatedNode):
		return mapAuthenticationFailed
	case errors.Is(err, mapsession.ErrInvalidRequest):
		return mapInvalidRequest
	case errors.Is(err, mapsession.ErrPresenceConflict),
		errors.Is(err, mapsession.ErrPresenceLost),
		errors.Is(err, mapsession.ErrStreamUnavailable):
		return mapCoordinationLost
	case errors.Is(err, mapsession.ErrAuthorizationExpired),
		errors.Is(err, mapsession.ErrStreamDiscontinuity):
		return mapAuthorityChanged
	case started && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		return mapStreamClosed
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return mapCanceled
	default:
		return mapUnavailable
	}
}
