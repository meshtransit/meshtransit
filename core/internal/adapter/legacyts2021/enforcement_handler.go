package legacyts2021

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/shared/policydigest"
)

// enforcementPath is the MeshTransit extension where meshd reports the
// digest of the packet filter it enforces (R1-69). It lives inside the
// Noise-authenticated session, next to the map endpoint.
const enforcementPath = "/machine/meshtransit/enforcement"

const (
	maxEnforcementReportBytes = 1 << 10
	enforcementReportVersion  = 1
	enforcementTimeout        = 5 * time.Second
)

// ErrInvalidEnforcementHandler reports missing dependencies.
var ErrInvalidEnforcementHandler = errors.New("legacyts2021: invalid enforcement handler")

type enforcementResult string

const (
	enforcementStored      enforcementResult = "stored"
	enforcementInvalid     enforcementResult = "invalid"
	enforcementNoStream    enforcementResult = "no_session"
	enforcementUnavailable enforcementResult = "unavailable"
)

func allEnforcementResults() [4]enforcementResult {
	return [4]enforcementResult{enforcementStored, enforcementInvalid, enforcementNoStream,
		enforcementUnavailable}
}

// EnforcementService stores what a node reports it enforces.
type EnforcementService interface {
	ReportEnforcement(context.Context, control.AuthenticatedMachine, mapsession.ClientEnforcement) error
}

// EnforcementHandler serves enforcement reports for one composed service.
type EnforcementHandler struct {
	service   EnforcementService
	logger    *slog.Logger
	telemetry *ControlTelemetry
}

// NewEnforcementHandler validates and constructs the report endpoint.
func NewEnforcementHandler(service EnforcementService, logger *slog.Logger,
	telemetry *ControlTelemetry) (*EnforcementHandler, error) {
	if service == nil || logger == nil || telemetry == nil || telemetry.enforcementReports == nil {
		return nil, ErrInvalidEnforcementHandler
	}
	return &EnforcementHandler{service: service, logger: logger, telemetry: telemetry}, nil
}

// enforcementReportWire is version 1 of the report body.
type enforcementReportWire struct {
	Version   int                 `json:"version"`
	NodeKey   string              `json:"node_key"`
	Digest    policydigest.Digest `json:"digest"`
	Grants    int                 `json:"grants"`
	AppliedAt time.Time           `json:"applied_at"`
}

// Handler binds one transport-authenticated machine to the endpoint.
func (handler *EnforcementHandler) Handler(machine control.AuthenticatedMachine) (http.Handler, error) {
	if handler == nil || handler.service == nil || !machine.IsValid() {
		return nil, ErrInvalidEnforcementHandler
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		result := handler.serve(response, request, machine)
		handler.telemetry.enforcementReports.WithLabelValues(string(result)).Inc()
	}), nil
}

func (handler *EnforcementHandler) serve(response http.ResponseWriter, request *http.Request,
	machine control.AuthenticatedMachine) enforcementResult {
	setResponseHeaders(response)
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return enforcementInvalid
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || request.URL.RawQuery != "" {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return enforcementInvalid
	}
	report, err := decodeEnforcementReport(request.Body)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return enforcementInvalid
	}
	operationCtx, cancel := context.WithTimeout(request.Context(), enforcementTimeout)
	defer cancel()
	err = handler.service.ReportEnforcement(operationCtx, machine, report)
	status, result := classifyEnforcementFailure(err)
	if result == enforcementUnavailable {
		handler.logger.WarnContext(request.Context(), "enforcement report not stored", "error", err)
	}
	if status == http.StatusNoContent {
		response.WriteHeader(status)
		return result
	}
	http.Error(response, http.StatusText(status), status)
	return result
}

func decodeEnforcementReport(body io.Reader) (mapsession.ClientEnforcement, error) {
	if body == nil {
		return mapsession.ClientEnforcement{}, ErrInvalidMapRequest
	}
	encoded, err := io.ReadAll(io.LimitReader(body, maxEnforcementReportBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxEnforcementReportBytes ||
		validateUniqueJSONNames(encoded) != nil {
		return mapsession.ClientEnforcement{}, ErrInvalidMapRequest
	}
	var wire enforcementReportWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		wire.Version != enforcementReportVersion || wire.AppliedAt.IsZero() {
		return mapsession.ClientEnforcement{}, ErrInvalidMapRequest
	}
	nodeKey, err := parseNodeKey(wire.NodeKey)
	if err != nil {
		return mapsession.ClientEnforcement{}, ErrInvalidMapRequest
	}
	filter, err := mapsession.NewFilterDigest(wire.Digest, wire.Grants)
	if err != nil {
		return mapsession.ClientEnforcement{}, ErrInvalidMapRequest
	}
	return mapsession.ClientEnforcement{NodeKey: nodeKey, Filter: filter, AppliedAt: wire.AppliedAt}, nil
}

func classifyEnforcementFailure(err error) (int, enforcementResult) {
	switch {
	case err == nil:
		return http.StatusNoContent, enforcementStored
	case errors.Is(err, mapsession.ErrInvalidEnforcementReport):
		return http.StatusBadRequest, enforcementInvalid
	case errors.Is(err, mapsession.ErrNoEnforcementStream):
		return http.StatusConflict, enforcementNoStream
	default:
		return http.StatusServiceUnavailable, enforcementUnavailable
	}
}
