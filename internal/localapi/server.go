// Package localapi exposes the versioned daemon API over a local Unix socket.
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/meshtransit/meshd/internal/compat/ts2021"
	"github.com/meshtransit/meshd/internal/daemon"
	"github.com/meshtransit/meshd/internal/dataplane"
	"github.com/meshtransit/meshd/internal/profile"
	"github.com/meshtransit/meshd/internal/relay"
	"github.com/meshtransit/meshd/internal/runtimehealth"
)

const (
	maxRequestBodyBytes = 64 << 10
	shutdownTimeout     = 5 * time.Second
	profilePathPrefix   = "/v1/profiles/"
)

type service interface {
	Status(context.Context) (daemon.Status, error)
	ListProfiles(context.Context) (profile.Snapshot, error)
	CreateProfile(context.Context, profile.CreateInput) (profile.Profile, error)
	ActivateProfile(context.Context, string) (profile.Profile, error)
	ProbeControl(context.Context) (daemon.ControlProbe, error)
	TrustControl(context.Context, string) (daemon.ControlTrust, error)
	StartLogin(context.Context, string) (daemon.Login, error)
	CompleteLogin(context.Context) (daemon.Login, error)
	RotateNodeKey(context.Context) (daemon.NodeKeyRotation, error)
}

// Server serves the local control API with bounded HTTP resources.
type Server struct {
	service          service
	logger           *slog.Logger
	handler          http.Handler
	allowedUIDs      map[uint32]struct{}
	allowSocketPeers bool
}

// Options configures local authorization. AllowedUIDs is copied during
// construction so later caller mutation cannot change access policy.
type Options struct {
	AllowedUIDs []uint32
	// AllowSocketPeers authorizes any kernel-verified peer that passed the
	// filesystem permissions on the daemon-owned Unix socket. It must only be
	// enabled when the socket group is the intended operator boundary.
	AllowSocketPeers bool
}

// New creates a local API server using explicit service and logger dependencies.
func New(service service, logger *slog.Logger, options Options) (*Server, error) {
	if service == nil {
		return nil, errors.New("localapi: service is required")
	}
	if logger == nil {
		return nil, errors.New("localapi: logger is required")
	}

	allowedUIDs := make(map[uint32]struct{}, len(options.AllowedUIDs))
	for _, uid := range options.AllowedUIDs {
		allowedUIDs[uid] = struct{}{}
	}
	server := &Server{
		service:          service,
		logger:           logger,
		allowedUIDs:      allowedUIDs,
		allowSocketPeers: options.AllowSocketPeers,
	}
	server.handler = server.routes()

	return server, nil
}

// Handler returns the HTTP handler for contract and unit testing.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Serve runs until the listener fails or ctx is cancelled. The listener must be
// a Unix-domain listener so the API cannot be exposed accidentally over TCP.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("localapi: listener is required")
	}
	if listener.Addr().Network() != "unix" {
		return fmt.Errorf("localapi: unsupported listener network %q", listener.Addr().Network())
	}

	httpServer := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			peer, err := peerFromConn(connection)
			if err != nil {
				s.logger.Debug("local peer credentials unavailable", "error", err)
			}

			return contextWithPeer(ctx, peer)
		},
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpServer.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("serving local api: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()

		shutdownErr := httpServer.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			closeErr := httpServer.Close()
			shutdownErr = errors.Join(shutdownErr, closeErr)
		}
		serverErr := <-serveErr
		if errors.Is(serverErr, http.ErrServerClosed) {
			serverErr = nil
		}

		return errors.Join(shutdownErr, serverErr)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/profiles", s.handleProfiles)
	mux.HandleFunc(profilePathPrefix, s.handleProfileAction)
	mux.HandleFunc("/v1/doctor/control", s.handleControlProbe)
	mux.HandleFunc("/v1/control/trust", s.handleControlTrust)
	mux.HandleFunc("/v1/login", s.handleLogin)
	mux.HandleFunc("/v1/login/complete", s.handleLoginComplete)
	mux.HandleFunc("/v1/identity/node-key/rotate", s.handleNodeKeyRotation)

	bounded := http.MaxBytesHandler(mux, maxRequestBodyBytes)

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.isAuthorized(request.Context()) {
			s.writeError(writer, http.StatusForbidden, "forbidden", "local peer is not authorized")

			return
		}
		bounded.ServeHTTP(writer, request)
	})
}

func (s *Server) handleControlTrust(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}

	input := trustControlRequest{}
	if !s.decodeJSONRequest(writer, request, &input) {
		return
	}
	trusted, err := s.service.TrustControl(request.Context(), input.Fingerprint)
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	s.writeJSON(writer, http.StatusOK, trustControlResponse{
		APIVersion:    apiVersion,
		ProfileID:     trusted.ProfileID,
		Fingerprint:   trusted.Fingerprint,
		AlreadyPinned: trusted.AlreadyTrusted,
	})
}

func (s *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}

	input := loginRequest{}
	if !s.decodeJSONRequest(writer, request, &input) {
		return
	}
	login, err := s.service.StartLogin(request.Context(), input.AuthKey)
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	s.writeLogin(writer, login)
}

func (s *Server) handleLoginComplete(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}
	if request.ContentLength > 0 {
		s.writeError(writer, http.StatusBadRequest, "unexpected_body", "request body must be empty")

		return
	}

	login, err := s.service.CompleteLogin(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	s.writeLogin(writer, login)
}

func (s *Server) handleNodeKeyRotation(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}
	if request.ContentLength > 0 {
		s.writeError(writer, http.StatusBadRequest, "unexpected_body", "request body must be empty")

		return
	}

	rotated, err := s.service.RotateNodeKey(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	s.writeJSON(writer, http.StatusOK, nodeKeyRotationResponse{
		APIVersion: apiVersion,
		ProfileID:  rotated.ProfileID,
		State:      rotated.State,
	})
}

func (s *Server) writeLogin(writer http.ResponseWriter, login daemon.Login) {
	s.writeJSON(writer, http.StatusOK, loginResponse{
		APIVersion: apiVersion,
		ProfileID:  login.ProfileID,
		State:      login.State,
		AuthURL:    login.AuthURL,
	})
}

func (s *Server) isAuthorized(ctx context.Context) bool {
	peer, exists := peerFromContext(ctx)
	if !exists || !peer.isPresent || !peer.isVerified {
		return false
	}
	_, explicitlyAllowed := s.allowedUIDs[peer.uid]

	return explicitlyAllowed || s.allowSocketPeers
}

func (s *Server) handleControlProbe(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}

	result, err := s.service.ProbeControl(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	s.writeJSON(writer, http.StatusOK, controlProbeResponse{
		APIVersion:       apiVersion,
		ProfileID:        result.ProfileID,
		ControlURL:       result.ControlURL,
		Protocol:         result.Protocol,
		Capability:       result.Capability,
		KeyFingerprint:   result.KeyFingerprint,
		NoiseEstablished: result.NoiseEstablished,
		NoiseVersion:     result.NoiseVersion,
	})
}

func (s *Server) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		s.writeMethodNotAllowed(writer, http.MethodGet)

		return
	}

	s.writeJSON(writer, http.StatusOK, healthResponse{
		Status:     "ok",
		APIVersion: apiVersion,
	})
}

func (s *Server) handleStatus(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		s.writeMethodNotAllowed(writer, http.MethodGet)

		return
	}

	status, err := s.service.Status(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	s.writeJSON(writer, http.StatusOK, statusResponse{
		APIVersion:         apiVersion,
		Daemon:             status.Build,
		State:              status.State,
		DataPlane:          status.DataPlane,
		DNS:                status.DNS,
		ActiveProfileID:    status.ActiveProfileID,
		ProfileCount:       status.ProfileCount,
		ControlTrust:       status.ControlTrust,
		Registration:       status.Registration,
		ControlFingerprint: status.ControlFingerprint,
		ControlSession:     status.ControlSession,
		NetmapRevision:     status.NetmapRevision,
		NetworkName:        status.NetworkName,
		SelfAddresses:      status.SelfAddresses,
		PeerCount:          status.PeerCount,
		PolicyRuleCount:    status.PolicyRuleCount,
		PeerPaths:          mapPathStatus(status.PeerPaths),
		Relay:              mapRelayStatus(status.Relay),
		NetworkChanges:     mapNetworkChangeStatus(status.NetworkChanges),
		RuntimeRecovery:    mapRuntimeRecoveryStatus(status.RuntimeRecovery),
		Runtime:            mapRuntimeStatus(status.Runtime),
		CompatibilityNote:  status.CompatibilityNote,
	})
}

func mapNetworkChangeStatus(status daemon.NetworkChangeStatus) networkChangeStatus {
	return networkChangeStatus{
		Available:         status.Available,
		Observed:          status.Observed,
		EndpointRefreshes: status.EndpointRefreshes,
	}
}

func mapRuntimeRecoveryStatus(status daemon.RuntimeRecoveryStatus) runtimeRecoveryStatus {
	return runtimeRecoveryStatus{
		Failures:   status.Failures,
		Recoveries: status.Recoveries,
		Pending:    status.Pending,
	}
}

func mapRuntimeStatus(status runtimehealth.Snapshot) runtimeStatus {
	return runtimeStatus{
		Goroutines:      status.Goroutines,
		HeapAllocBytes:  status.HeapAllocBytes,
		HeapInUseBytes:  status.HeapInUseBytes,
		HeapObjects:     status.HeapObjects,
		StackInUseBytes: status.StackInUseBytes,
		SysBytes:        status.SysBytes,
		GCCycles:        status.GCCycles,
	}
}

func mapPathStatus(snapshot dataplane.PeerPathSnapshot) pathStatus {
	return pathStatus{
		Available:    snapshot.Available,
		PeerCount:    snapshot.PeerCount,
		DirectCount:  snapshot.DirectCount,
		RelayCount:   snapshot.RelayCount,
		PendingCount: snapshot.PendingCount,
	}
}

func mapRelayStatus(snapshot relay.HealthSnapshot) relayStatus {
	regions := make([]relayRegionStatus, 0, len(snapshot.Regions))
	connected := 0
	for _, region := range snapshot.Regions {
		if region.Connected {
			connected++
		}
		regions = append(regions, relayRegionStatus{
			RegionID:            region.RegionID,
			Connected:           region.Connected,
			ConsecutiveFailures: region.ConsecutiveFailures,
			LastConnected:       formatStatusTime(region.LastConnected),
			LastActivity:        formatStatusTime(region.LastActivity),
			LastSend:            formatStatusTime(region.LastSend),
			LastFailure:         formatStatusTime(region.LastFailure),
		})
	}

	return relayStatus{
		Available:        snapshot.Available,
		HomeRegion:       snapshot.HomeRegion,
		ActiveRegions:    len(snapshot.Regions),
		ConnectedRegions: connected,
		Regions:          regions,
	}
}

func formatStatusTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}

	return value.UTC().Format(time.RFC3339Nano)
}

func (s *Server) handleProfiles(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		s.handleListProfiles(writer, request)
	case http.MethodPost:
		s.handleCreateProfile(writer, request)
	default:
		s.writeMethodNotAllowed(writer, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleListProfiles(writer http.ResponseWriter, request *http.Request) {
	snapshot, err := s.service.ListProfiles(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	profiles := make([]profileResponse, 0, len(snapshot.Profiles))
	for _, item := range snapshot.Profiles {
		profiles = append(profiles, mapProfile(item, snapshot.ActiveProfileID))
	}

	s.writeJSON(writer, http.StatusOK, profilesResponse{
		APIVersion: apiVersion,
		Profiles:   profiles,
	})
}

func (s *Server) handleCreateProfile(writer http.ResponseWriter, request *http.Request) {
	input := createProfileRequest{}
	if !s.decodeJSONRequest(writer, request, &input) {
		return
	}

	created, err := s.service.CreateProfile(request.Context(), profile.CreateInput{
		Name:       input.Name,
		ControlURL: input.ControlURL,
	})
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	snapshot, err := s.service.ListProfiles(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	s.writeJSON(writer, http.StatusCreated, mapProfile(created, snapshot.ActiveProfileID))
}

func (s *Server) handleProfileAction(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}

	remainder := strings.TrimPrefix(request.URL.Path, profilePathPrefix)
	profileID, found := strings.CutSuffix(remainder, "/activate")
	invalidPath := !found || profileID == "" || strings.Contains(profileID, "/")
	if invalidPath {
		s.writeError(writer, http.StatusNotFound, "not_found", "endpoint not found")

		return
	}

	selected, err := s.service.ActivateProfile(request.Context(), profileID)
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}

	s.writeJSON(writer, http.StatusOK, mapProfile(selected, selected.ID))
}

func (s *Server) writeServiceError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, profile.ErrNotFound):
		s.writeError(writer, http.StatusNotFound, "profile_not_found", "profile not found")
	case errors.Is(err, profile.ErrDuplicate):
		s.writeError(writer, http.StatusConflict, "profile_exists", "profile name already exists")
	case errors.Is(err, profile.ErrInvalid):
		message := strings.TrimPrefix(err.Error(), profile.ErrInvalid.Error()+": ")
		s.writeError(writer, http.StatusBadRequest, "invalid_profile", message)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.writeError(writer, http.StatusRequestTimeout, "request_cancelled", "request was cancelled")
	case errors.Is(err, ts2021.ErrInvalidFingerprint):
		s.writeError(writer, http.StatusBadRequest, "invalid_control_key_fingerprint", "control key fingerprint is invalid")
	case errors.Is(err, ts2021.ErrFingerprintMismatch):
		s.writeError(writer, http.StatusConflict, "control_key_mismatch", "control key fingerprint does not match")
	case errors.Is(err, ts2021.ErrControlKeyChanged):
		s.logger.Error("pinned control key changed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "control_key_changed", "pinned control key no longer matches the control server")
	case errors.Is(err, daemon.ErrControlNotTrusted):
		s.writeError(writer, http.StatusConflict, "control_not_trusted", "pin the active profile control key before login")
	case errors.Is(err, daemon.ErrAuthorizationPending):
		s.writeError(writer, http.StatusConflict, "authorization_pending", "browser authorization is still pending")
	case errors.Is(err, daemon.ErrNoPendingAuthorization):
		s.writeError(writer, http.StatusConflict, "no_pending_authorization", "no browser authorization is pending")
	case errors.Is(err, ts2021.ErrNodeKeyExpired):
		s.writeError(writer, http.StatusConflict, "node_key_expired", "node key rotation is required")
	case errors.Is(err, daemon.ErrNodeKeyRotation) &&
		errors.Is(err, ts2021.ErrRegistrationTemporary):
		s.logger.Warn("node key rotation is temporarily unavailable", "error", err)
		s.writeError(writer, http.StatusServiceUnavailable, "node_key_rotation_unavailable", "node key rotation is temporarily unavailable")
	case errors.Is(err, daemon.ErrNodeKeyRotation):
		s.logger.Warn("node key rotation failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "node_key_rotation_failed", "node key rotation failed")
	case errors.Is(err, daemon.ErrControlProbe):
		s.logger.Warn("control compatibility probe failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "control_probe_failed", "control compatibility probe failed")
	case errors.Is(err, daemon.ErrControlTrust):
		s.logger.Warn("control trust operation failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "control_trust_failed", "control trust operation failed")
	case errors.Is(err, daemon.ErrRegistration):
		s.logger.Warn("node registration failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "registration_failed", "node registration failed")
	default:
		s.logger.Error("local api request failed", "error", err)
		s.writeError(writer, http.StatusInternalServerError, "internal_error", "internal daemon error")
	}
}

func (s *Server) decodeJSONRequest(
	writer http.ResponseWriter,
	request *http.Request,
	target any,
) bool {
	if !isJSON(request.Header.Get("Content-Type")) {
		s.writeError(
			writer,
			http.StatusUnsupportedMediaType,
			"unsupported_media_type",
			"content-type must be application/json",
		)

		return false
	}

	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		s.writeError(writer, http.StatusBadRequest, "invalid_json", "request body is not valid json")

		return false
	}
	if err := ensureRequestEOF(decoder); err != nil {
		s.writeError(writer, http.StatusBadRequest, "invalid_json", "request body must contain one json value")

		return false
	}

	return true
}

func (s *Server) writeMethodNotAllowed(writer http.ResponseWriter, methods ...string) {
	writer.Header().Set("Allow", strings.Join(methods, ", "))
	s.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func (s *Server) writeError(writer http.ResponseWriter, status int, code, message string) {
	s.writeJSON(writer, status, errorResponse{
		APIVersion: apiVersion,
		Code:       code,
		Message:    message,
	})
}

func (s *Server) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)

	if err := json.NewEncoder(writer).Encode(value); err != nil {
		s.logger.Warn("writing local api response failed", "error", err)
	}
}

func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	return mediaType == "application/json"
}

func ensureRequestEOF(decoder *json.Decoder) error {
	var extra struct{}
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple json values")
	}

	return err
}
