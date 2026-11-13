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

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/flowreport"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/runtimehealth"
	"meshtransit.net/shared/disco"
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
	RemoveProfile(context.Context, string, bool) (daemon.ProfileRemoval, error)
	AddAccount(context.Context, string) (profile.Profile, profile.Profile, error)
	ProfileDisplay(string) (daemon.Display, bool)
	CanCancelAddAccount(context.Context, string) bool
	CancelAddAccount(context.Context, string) (daemon.ProfileRemoval, profile.Profile, error)
	StopSignIn(context.Context, string) error
	ProbeControl(context.Context) (daemon.ControlProbe, error)
	TrustControl(context.Context, string) (daemon.ControlTrust, error)
	StartLogin(context.Context, string) (daemon.Login, error)
	CompleteLogin(context.Context) (daemon.Login, error)
	RotateNodeKey(context.Context) (daemon.NodeKeyRotation, error)
	Down(context.Context) (daemon.ConnectionChange, error)
	Up(context.Context) (daemon.ConnectionChange, error)
	Logout(context.Context) (daemon.LogoutResult, error)
	SignOut(context.Context) (daemon.LogoutResult, error)
	ProfileStates(context.Context, []profile.Profile) (map[string]string, error)
	RefreshNAT(context.Context) (daemon.NATStatus, error)
	ApproveExitNodes(context.Context, []string) (daemon.ExitApproval, error)
	CheckCaptiveWindow()
	Peers(context.Context) ([]daemon.PeerView, error)
	PingPeer(context.Context, string) (daemon.PeerPing, error)
	QueryDNS(context.Context, string, string) (dnsconfig.QueryReport, error)
	RouteChoices(context.Context, bool) (daemon.RouteChoices, error)
	ChangeRouteChoices(context.Context, routesettings.ChoiceChange, bool) (daemon.RouteChoices, error)
}

// Server serves the local control API with bounded HTTP resources.
type Server struct {
	service          service
	logger           *slog.Logger
	handler          http.Handler
	allowedUIDs      map[uint32]struct{}
	allowSocketPeers bool
	operatorsSID     string
	// routeChoiceLimits bound each caller's route choice reads and changes:
	// each opens the settings file, which an administrator's change replaces.
	routeChoiceLimits *callerLimits
}

// Options configures local authorization. AllowedUIDs is copied during
// construction so later caller mutation cannot change access policy.
type Options struct {
	AllowedUIDs []uint32
	// AllowSocketPeers authorizes any kernel-verified peer that passed the
	// filesystem permissions on the daemon-owned Unix socket. It must only be
	// enabled when the socket group is the intended operator boundary.
	AllowSocketPeers bool
	// OperatorsSID is the Windows operators group (MeshTransit Users), or ""
	// when it does not exist; its enabled members may use the API.
	OperatorsSID string
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
		service:           service,
		logger:            logger,
		allowedUIDs:       allowedUIDs,
		allowSocketPeers:  options.AllowSocketPeers,
		operatorsSID:      options.OperatorsSID,
		routeChoiceLimits: newCallerLimits(routeChoiceRate, routeChoiceBurst),
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
	if network := listener.Addr().Network(); network != "unix" && network != "pipe" {
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
			peer, err := peerFromConn(connection, s.operatorsSID)
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
	mux.HandleFunc("/v1/accounts", s.handleAddAccount)
	mux.HandleFunc("/v1/accounts/{id}", s.handleCancelAccount)
	mux.HandleFunc("/v1/login/stop", s.handleStopSignIn)
	mux.HandleFunc("/v1/doctor/control", s.handleControlProbe)
	mux.HandleFunc("/v1/control/trust", s.handleControlTrust)
	mux.HandleFunc("/v1/login", s.handleLogin)
	mux.HandleFunc("/v1/login/complete", s.handleLoginComplete)
	mux.HandleFunc("/v1/identity/node-key/rotate", s.handleNodeKeyRotation)
	mux.HandleFunc("/v1/down", s.handleDown)
	mux.HandleFunc("/v1/up", s.handleUp)
	mux.HandleFunc("/v1/logout", s.handleLogout)
	mux.HandleFunc("/v1/sign-out", s.handleSignOut)
	mux.HandleFunc("/v1/netcheck", s.handleNetcheck)
	mux.HandleFunc("/v1/exit/approve", s.handleExitApprove)
	mux.HandleFunc("/v1/exit/captive/check", s.handleCaptiveCheck)
	mux.HandleFunc("/v1/route-choices", s.handleRouteChoices)
	mux.HandleFunc("/v1/peers", s.handlePeers)
	mux.HandleFunc("/v1/peers/{id}/ping", s.handlePeerPing)
	mux.HandleFunc("/v1/dns/query", s.handleDNSQuery)

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

// handleDown takes meshd off the network until /v1/up (meshctl down).
func (s *Server) handleDown(writer http.ResponseWriter, request *http.Request) {
	s.handleConnectionChange(writer, request, s.service.Down)
}

// handleUp clears a down (meshctl up).
func (s *Server) handleUp(writer http.ResponseWriter, request *http.Request) {
	s.handleConnectionChange(writer, request, s.service.Up)
}

// handleExitApprove lets the pool in use carry traffic through the exit
// nodes Core added to it (meshctl exit approve).
func (s *Server) handleExitApprove(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)
		return
	}
	// Approving an exit node lets it see the host's Internet traffic: as
	// the root-owned settings that choose the pool, it is root's to do.
	if peer, found := peerFromContext(request.Context()); !found || !peer.administrator {
		s.writeError(writer, http.StatusForbidden, "exit_approval_needs_root",
			"approving exit nodes needs root (sudo) or an elevated administrator")
		return
	}
	input := exitApprovalRequest{}
	if !s.decodeJSONRequest(writer, request, &input) {
		return
	}
	if len(input.IDs) == 0 || len(input.IDs) > 16 {
		s.writeError(writer, http.StatusBadRequest, "invalid_exit_approval", "name 1 to 16 exit nodes or pools")
		return
	}
	result, err := s.service.ApproveExitNodes(request.Context(), input.IDs)
	if err != nil {
		s.writeServiceError(writer, err)
		return
	}
	approved := result.Approved
	if approved == nil {
		approved = []string{}
	}
	s.writeJSON(writer, http.StatusOK, exitApprovalResponse{APIVersion: apiVersion, Pool: result.Pool, Approved: approved})
}

func (s *Server) handleConnectionChange(
	writer http.ResponseWriter,
	request *http.Request,
	change func(context.Context) (daemon.ConnectionChange, error),
) {
	if !s.acceptEmptyPost(writer, request) {
		return
	}
	result, err := change(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	s.writeJSON(writer, http.StatusOK, connectionResponse{
		APIVersion: apiVersion,
		State:      result.State,
		Changed:    result.Changed,
	})
}

// handleLogout ends the active profile's Device in Core (meshctl logout).
func (s *Server) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if !s.acceptEmptyPost(writer, request) {
		return
	}
	result, err := s.service.Logout(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	s.writeJSON(writer, http.StatusOK, logoutResponse{
		APIVersion:     apiVersion,
		ProfileID:      result.ProfileID,
		State:          result.State,
		AlreadyRemoved: result.AlreadyRemoved,
	})
}

// handleSignOut signs the Device out and keeps it (meshctl logout): the
// profile keeps its keys and meshctl login signs the same Device back in.
// /v1/logout still removes it (meshctl logout --remove).
func (s *Server) handleSignOut(writer http.ResponseWriter, request *http.Request) {
	if !s.acceptEmptyPost(writer, request) {
		return
	}
	result, err := s.service.SignOut(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	s.writeJSON(writer, http.StatusOK, logoutResponse{
		APIVersion:     apiVersion,
		ProfileID:      result.ProfileID,
		State:          result.State,
		AlreadyRemoved: result.AlreadyRemoved,
	})
}

// acceptEmptyPost answers anything but a body-less POST and reports whether
// the request may proceed.
func (s *Server) acceptEmptyPost(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return false
	}
	if request.ContentLength > 0 {
		s.writeError(writer, http.StatusBadRequest, "unexpected_body", "request body must be empty")

		return false
	}

	return true
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

func (s *Server) handleNetcheck(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}
	if request.ContentLength > 0 {
		s.writeError(writer, http.StatusBadRequest, "unexpected_body", "request body must be empty")

		return
	}

	status, err := s.service.RefreshNAT(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	response := netcheckResponse{APIVersion: apiVersion, NAT: mapNATStatus(status, true)}
	if daemonStatus, err := s.service.Status(request.Context()); err == nil {
		response.PortMapping = mapPortMappingStatus(daemonStatus.PortMapping, true)
		response.Cloud = mapCloudStatus(daemonStatus.Cloud, true)
	}
	s.writeJSON(writer, http.StatusOK, response)
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
	if peer.operator {
		return true
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
		DNSError:           status.DNSError,
		ActiveProfileID:    status.ActiveProfileID,
		ProfileCount:       status.ProfileCount,
		ControlTrust:       status.ControlTrust,
		Registration:       status.Registration,
		Disconnected:       status.Disconnected,
		ControlFingerprint: status.ControlFingerprint,
		ControlSession:     status.ControlSession,
		NetmapRevision:     status.NetmapRevision,
		NetworkName:        status.NetworkName,
		SelfAddresses:      status.SelfAddresses,
		DeviceExpiresAt:    deviceExpiresAt(status),
		DeviceExpiry:       status.DeviceExpiry,
		PeerCount:          status.PeerCount,
		PolicyRuleCount:    status.PolicyRuleCount,
		PeerPaths:          mapPathStatus(status.PeerPaths),
		SubnetRoutes:       withRouteSites(mapSubnetRouteStatus(status.SubnetRoutes), status.RouteSites),
		SubnetRouter:       mapSubnetRouterStatus(status.SubnetRouter),
		ExitNode:           mapExitNodeStatus(status.ExitNode),
		Exit:               mapExitStatus(status.Exit, status.ExitRoute),
		KubernetesClusters: mapKubernetesClusters(status.KubernetesClusters),
		Captive:            mapCaptiveStatus(status.Captive),
		ConnectionLogs:     mapConnectionLogs(status.ConnectionLogs),
		PathProbes:         mapPathProbeStatus(status.PathProbes),
		Relay:              mapRelayStatus(status.Relay),
		NetworkChanges:     mapNetworkChangeStatus(status.NetworkChanges),
		RuntimeRecovery:    mapRuntimeRecoveryStatus(status.RuntimeRecovery),
		Runtime:            mapRuntimeStatus(status.Runtime),
		NAT:                mapNATStatus(status.NAT, false),
		PortMapping:        mapPortMappingStatus(status.PortMapping, false),
		Cloud:              mapCloudStatus(status.Cloud, false),
		CompatibilityNote:  status.CompatibilityNote,
	})
}

func mapPathProbeStatus(status daemon.PathProbeStatus) pathProbeStatus {
	snapshot := status.Snapshot

	return pathProbeStatus{
		Available:                    status.Available,
		MapActivations:               snapshot.MapActivations,
		ActivationPreserved:          snapshot.ActivationPreserved,
		ActivationRetired:            snapshot.ActivationRetired,
		AuthorityPeerChanges:         snapshot.AuthorityPeerChanges,
		AuthorityNodeKeyChanges:      snapshot.AuthorityNodeKeyChanges,
		AuthorityDiscoveryKeyChanges: snapshot.AuthorityDiscoveryKeyChanges,
		AuthorityEndpointChanges:     snapshot.AuthorityEndpointChanges,
		SocketChanges:                snapshot.SocketChanges,
		PendingInvalidated:           snapshot.PendingInvalidated,
		RoundsStarted:                snapshot.RoundsStarted,
		RoundsCompleted:              snapshot.RoundsCompleted,
		ProbeAttempts:                snapshot.ProbeAttempts,
		ProbesStarted:                snapshot.ProbesStarted,
		ProbesSent:                   snapshot.ProbesSent,
		ProbeStartFailures:           snapshot.ProbeStartFailures,
		ProbeSendFailures:            snapshot.ProbeSendFailures,
		DatagramDrops:                snapshot.DatagramDrops,
		AuthenticatedPings:           snapshot.AuthenticatedPings,
		PingRateLimited:              snapshot.PingRateLimited,
		PongsSent:                    snapshot.PongsSent,
		PongSendFailures:             snapshot.PongSendFailures,
		AuthenticatedPongs:           snapshot.AuthenticatedPongs,
		ProbeCompletions:             snapshot.ProbeCompletions,
		CompletionRejections:         snapshot.CompletionRejections,
		ObservationsQueued:           snapshot.ObservationsQueued,
		ObservationDrops:             snapshot.ObservationDrops,
		ObservationsAccepted:         snapshot.ObservationsAccepted,
		ObservationRejected:          snapshot.ObservationRejected,
		DirectExpirations:            snapshot.DirectExpirations,
		CallMeMaybeSent:              snapshot.CallMeMaybeSent,
		CallMeMaybeAccepted:          snapshot.CallMeMaybeAccepted,
		PeerReflexiveLearned:         snapshot.PeerReflexiveLearned,
	}
}

// mapCloudStatus converts the cloud addresses to their wire form. The
// addresses are included only for an explicit netcheck request.
func mapCloudStatus(status daemon.CloudStatus, withAddresses bool) cloudStatus {
	out := cloudStatus{
		State: status.State, Platform: status.Platform, AddressCount: len(status.Addresses), Error: status.Error,
	}
	if out.State == "" {
		out.State = daemon.CloudOff
	}
	if !status.ObservedAt.IsZero() {
		out.ObservedAt = status.ObservedAt.UTC().Format(time.RFC3339)
	}
	if withAddresses {
		for _, addr := range status.Addresses {
			out.Addresses = append(out.Addresses, addr.String())
		}
	}

	return out
}

// mapPortMappingStatus converts the port mapping to its wire form. The
// external endpoint is included only for an explicit netcheck request.
func mapPortMappingStatus(status daemon.PortMappingStatus, withEndpoint bool) portMappingStatus {
	out := portMappingStatus{State: status.State, Protocol: status.Protocol, Error: status.Error}
	if out.State == "" {
		out.State = daemon.PortMappingOff
	}
	if !status.ExpiresAt.IsZero() {
		out.ExpiresAt = status.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if withEndpoint && status.External.IsValid() {
		out.External = status.External.String()
	}

	return out
}

// mapNATStatus converts the classification to its wire form. The public
// endpoint is included only for an explicit netcheck request; /v1/status
// never exposes endpoint addresses.
func mapNATStatus(status daemon.NATStatus, withEndpoint bool) natStatus {
	out := natStatus{State: status.State, Error: status.Error}
	if status.State != daemon.NATReady && status.State != daemon.NATStale {
		return out
	}
	out.Mapping = natMappingName(status.NAT.Mapping)
	out.Filtering = natFilteringName(status.NAT.Filtering)
	out.Allocation = natAllocationName(status.NAT.Allocation)
	out.SequentialStep = status.Step
	switch {
	case status.NAT.Mapping.Easy():
		out.Difficulty = "easy"
	case status.NAT.Mapping.Hard():
		out.Difficulty = "hard"
	default:
		out.Difficulty = "unknown"
	}
	if withEndpoint && status.PublicEndpoint.IsValid() {
		out.PublicEndpoint = status.PublicEndpoint.String()
	}
	out.ServersAnswered = status.ServersAnswered
	if !status.ObservedAt.IsZero() {
		out.ObservedAt = status.ObservedAt.UTC().Format(time.RFC3339)
	}

	return out
}

func natMappingName(m disco.Mapping) string {
	switch m {
	case disco.MappingNone:
		return "none"
	case disco.MappingEndpointIndependent:
		return "endpoint-independent"
	case disco.MappingAddressDependent:
		return "address-dependent"
	case disco.MappingAddressAndPortDependent:
		return "address-and-port-dependent"
	default:
		return "unknown"
	}
}

func natFilteringName(f disco.Filtering) string {
	switch f {
	case disco.FilteringEndpointIndependent:
		return "endpoint-independent"
	case disco.FilteringAddressDependent:
		return "address-dependent"
	case disco.FilteringAddressAndPortDependent:
		return "address-and-port-dependent"
	default:
		return "unknown"
	}
}

func natAllocationName(a disco.Allocation) string {
	switch a {
	case disco.AllocationPreserving:
		return "port-preserving"
	case disco.AllocationSequential:
		return "sequential"
	case disco.AllocationRandom:
		return "random"
	default:
		return "unknown"
	}
}

func withRouteSites(mapped subnetRouteStatus, sites []daemon.RouteSiteView) subnetRouteStatus {
	for _, site := range sites {
		prefixes := make([]string, 0, len(site.Prefixes))
		for _, prefix := range site.Prefixes {
			prefixes = append(prefixes, prefix.String())
		}
		mapped.Sites = append(mapped.Sites, subnetRouteSite{
			Site: site.Ref, Name: site.Name, Prefixes: prefixes, Router: site.Router, RouterName: site.RouterName,
			Via: site.Via,
		})
	}
	return mapped
}

func mapSubnetRouteStatus(status dataplane.SubnetRouteStatus) subnetRouteStatus {
	mapped := subnetRouteStatus{
		Requested: status.Requested, Installed: status.Installed, RefusedTotal: status.RefusedTotal,
		Health: "ok", Error: status.Error,
		UnreachableAnswered: status.UnreachableAnswered, UnreachableLimited: status.UnreachableLimited,
	}
	switch {
	case status.Error != "":
		mapped.Health = "route_install_failed"
	case status.LocalConflict:
		mapped.Health = "route_conflict_local"
	}
	for _, refusal := range status.Refused {
		mapped.Refused = append(mapped.Refused, subnetRouteRefusal{Prefix: refusal.Prefix.String(), Reason: refusal.Reason})
	}
	return mapped
}

func mapExitStatus(view *daemon.ExitView, route dataplane.ExitRouteStatus) *exitStatus {
	if view == nil {
		return nil
	}
	return &exitStatus{
		Use: view.Use, Pool: view.Pool, PoolName: view.PoolName, ExitNode: view.ExitNode,
		ExitNodeName: view.ExitNodeName, Via: view.Via, IPv6: route.IPv6, Routing: route.Routing,
		Refused: route.Refused, Error: route.Error, Tampered: route.Tampered, Pending: view.Pending,
		PendingNames: view.PendingNames, PendingPool: view.PendingPool, CaptiveOff: route.CaptiveOff,
	}
}

func mapExitNodeStatus(status dataplane.ExitNodeStatus) exitNodeStatus {
	mapped := exitNodeStatus{
		Pool: status.Pool, Serving: status.Serving, Refused: status.Refused,
		ConntrackPerConsumer: status.ConntrackPerConsumer, SMTPAllowed: status.SMTP,
		MaxConsumers: status.MaxConsumers, Error: status.Error,
	}
	if health := status.Health; health != nil {
		mapped.State, mapped.Code = health.State, health.Code
		switch {
		case health.IPv4 && health.IPv6:
			mapped.Families = "both"
		case health.IPv4:
			mapped.Families = "ipv4"
		case health.IPv6:
			mapped.Families = "ipv6"
		}
	}
	return mapped
}

func mapSubnetRouterStatus(status dataplane.SubnetRouterStatus) subnetRouterStatus {
	mapped := subnetRouterStatus{
		Sites: status.Sites, Requested: status.Requested, Served: status.Served, RefusedTotal: status.RefusedTotal,
		Health: "ok", Error: status.Error,
	}
	// The router's health is its worst Site's: a failed one, else a
	// degraded one.
	worst := ""
	for _, site := range status.Health {
		mapped.SiteHealth = append(mapped.SiteHealth, subnetRouterSiteHealth{Site: site.Ref, State: site.State, Code: site.Code})
		if site.State == dataplane.SiteHealthFailed && (worst == "" || worst == dataplane.SiteCodeConntrackHigh) {
			worst = site.Code
		} else if site.State == dataplane.SiteHealthDegraded && worst == "" {
			worst = site.Code
		}
	}
	switch {
	case status.Error != "":
		mapped.Health = "route_forwarding_failed"
	case status.NotAdvertised:
		mapped.Health = "prefix_not_advertised"
	case worst != "":
		mapped.Health = worst
	}
	for _, refusal := range status.Refused {
		mapped.Refused = append(mapped.Refused, subnetRouteRefusal{Prefix: refusal.Prefix.String(), Reason: refusal.Reason})
	}
	return mapped
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
		Available:                 snapshot.Available,
		PeerCount:                 snapshot.PeerCount,
		DirectCount:               snapshot.DirectCount,
		RelayCount:                snapshot.RelayCount,
		PendingCount:              snapshot.PendingCount,
		RelayBootstrapCount:       snapshot.RelayBootstrapCount,
		DirectPromotionCount:      snapshot.DirectPromotionCount,
		RelayFallbackCount:        snapshot.RelayFallbackCount,
		LastDirectPromotionMillis: snapshot.LastDirectPromotion.Milliseconds(),
		MaxDirectPromotionMillis:  snapshot.MaxDirectPromotion.Milliseconds(),
		InactiveCount:             snapshot.InactiveCount,
		LazyActivationCount:       snapshot.LazyActivationCount,
		LazyEvictionCount:         snapshot.LazyEvictionCount,
		LazyDroppedCount:          snapshot.LazyDroppedCount,
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

	states, err := s.service.ProfileStates(request.Context(), snapshot.Profiles)
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	profiles := make([]profileResponse, 0, len(snapshot.Profiles))
	for _, item := range snapshot.Profiles {
		mapped := mapProfile(item, snapshot.ActiveProfileID)
		mapped.State = states[item.ID]
		display, found := s.service.ProfileDisplay(item.ID)
		canCancel := mapped.State == daemon.RegistrationPending && s.service.CanCancelAddAccount(request.Context(), item.ID)
		profiles = append(profiles, mapped.withDisplay(display, found, canCancel))
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

// handleAddAccount adds an account on the active profile's server (meshctl
// login --new-account, the apps' Add account): a profile pinned with the
// same key before it becomes active. POST /v1/accounts with a JSON body,
// {} or {"name": "..."}; the name defaults to "<active name> N".
func (s *Server) handleAddAccount(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}
	input := addAccountRequest{}
	if !s.decodeJSONRequest(writer, request, &input) {
		return
	}
	created, previous, err := s.service.AddAccount(request.Context(), input.Name)
	if err != nil {
		s.writeAddAccountError(writer, err)

		return
	}
	added := mapProfile(created, created.ID)
	before := mapProfile(previous, created.ID)
	// States are best effort here: the account was added either way.
	if states, err := s.service.ProfileStates(request.Context(), []profile.Profile{created, previous}); err == nil {
		added.State = states[created.ID]
		before.State = states[previous.ID]
	}
	s.writeJSON(writer, http.StatusCreated, addAccountResponse{APIVersion: apiVersion, Profile: added, Previous: before})
}

// handleCancelAccount undoes an Add account still waiting for its first
// approval (S4b §4.3): DELETE /v1/accounts/{id}.
func (s *Server) handleCancelAccount(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodDelete {
		s.writeMethodNotAllowed(writer, http.MethodDelete)

		return
	}
	id := request.PathValue("id")
	if !isProfilePathID(id) {
		s.writeError(writer, http.StatusBadRequest, "invalid_profile_id", "profile id is invalid")

		return
	}
	removal, active, err := s.service.CancelAddAccount(request.Context(), id)
	if errors.Is(err, daemon.ErrNotCancelable) {
		s.writeError(writer, http.StatusConflict, "account_not_cancelable",
			"only an added account that never held a device can be cancelled; stop signing in instead")

		return
	}
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	s.writeJSON(writer, http.StatusOK, cancelAccountResponse{
		APIVersion: apiVersion, Profile: mapProfile(removal.Profile, active.ID), Device: removal.Device,
		Active: mapProfile(active, active.ID),
	})
}

// handleStopSignIn drops a profile's pending browser approval and keeps
// its keys (S4b §4.3): POST /v1/login/stop {"profile_id": "..."}, the
// profile the person saw waiting, so a switch in between never stops
// another one's.
func (s *Server) handleStopSignIn(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)

		return
	}
	input := stopSignInRequest{}
	if !s.decodeJSONRequest(writer, request, &input) {
		return
	}
	if !isProfilePathID(input.ProfileID) {
		s.writeError(writer, http.StatusBadRequest, "invalid_profile_id", "profile id is invalid")

		return
	}
	if err := s.service.StopSignIn(request.Context(), input.ProfileID); err != nil {
		s.writeServiceError(writer, err)

		return
	}
	s.writeJSON(writer, http.StatusOK, stopSignInResponse{APIVersion: apiVersion, ProfileID: input.ProfileID})
}

// writeAddAccountError maps AddAccount's errors before the shared mapping:
// a failed setup wraps causes (a profile gone, a key no longer offered, a
// drop that failed) that mean something else on other routes.
func (s *Server) writeAddAccountError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, daemon.ErrGatewayProfiles):
		s.writeError(writer, http.StatusConflict, "gateway_profile",
			"a Kubernetes gateway keeps its one profile and does not add accounts")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.writeError(writer, http.StatusRequestTimeout, "request_cancelled", "request was cancelled")
	case errors.Is(err, daemon.ErrAddAccount) &&
		(errors.Is(err, controlplane.ErrFingerprintMismatch) || errors.Is(err, controlplane.ErrControlKeyChanged)):
		s.logger.Warn("adding an account failed: control key", "error", err)
		s.writeError(writer, http.StatusBadGateway, "add_account_failed",
			"the server no longer offers the pinned key, so no account was added; the account in use is unchanged")
	case errors.Is(err, daemon.ErrAddAccount):
		s.logger.Warn("adding an account failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "add_account_failed",
			"the new account could not be set up; the account in use is unchanged")
	default:
		s.writeServiceError(writer, err)
	}
}

func (s *Server) handleProfileAction(writer http.ResponseWriter, request *http.Request) {
	remainder := strings.TrimPrefix(request.URL.Path, profilePathPrefix)
	if request.Method == http.MethodDelete && isProfilePathID(remainder) {
		s.handleProfileRemove(writer, request, remainder)

		return
	}
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost, http.MethodDelete)

		return
	}

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

// handleProfileRemove deletes an inactive profile (meshctl profile remove):
// DELETE /v1/profiles/{id}, with ?local=true to drop its keys without Core.
func (s *Server) handleProfileRemove(writer http.ResponseWriter, request *http.Request, profileID string) {
	if request.ContentLength > 0 {
		s.writeError(writer, http.StatusBadRequest, "unexpected_body", "request body must be empty")

		return
	}
	query := request.URL.Query()
	local := false
	for key, values := range query {
		if key != "local" || len(values) != 1 || (values[0] != "true" && values[0] != "false") {
			s.writeError(writer, http.StatusBadRequest, "invalid_query", "the only query parameter is local=true|false")

			return
		}
		local = values[0] == "true"
	}
	removal, err := s.service.RemoveProfile(request.Context(), profileID, local)
	if err != nil {
		s.writeServiceError(writer, err)

		return
	}
	s.writeJSON(writer, http.StatusOK, profileRemovalResponse{
		APIVersion: apiVersion,
		Profile:    mapProfile(removal.Profile, ""),
		Device:     removal.Device,
	})
}

// isProfilePathID reports a single path segment, the profile id.
func isProfilePathID(segment string) bool {
	return segment != "" && !strings.Contains(segment, "/")
}

func (s *Server) writeServiceError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, profile.ErrNotFound):
		s.writeError(writer, http.StatusNotFound, "profile_not_found", "profile not found")
	case errors.Is(err, profile.ErrActive):
		s.writeError(writer, http.StatusConflict, "profile_active",
			"the active profile cannot be removed; switch to another with meshctl profile use first")
	case errors.Is(err, profile.ErrDuplicate):
		s.writeError(writer, http.StatusConflict, "profile_exists", "profile name already exists")
	case errors.Is(err, profile.ErrInvalid):
		message := strings.TrimPrefix(err.Error(), profile.ErrInvalid.Error()+": ")
		s.writeError(writer, http.StatusBadRequest, "invalid_profile", message)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.writeError(writer, http.StatusRequestTimeout, "request_cancelled", "request was cancelled")
	case errors.Is(err, controlplane.ErrInvalidFingerprint):
		s.writeError(writer, http.StatusBadRequest, "invalid_control_key_fingerprint", "control key fingerprint is invalid")
	case errors.Is(err, controlplane.ErrFingerprintMismatch):
		s.writeError(writer, http.StatusConflict, "control_key_mismatch", "control key fingerprint does not match")
	case errors.Is(err, controlplane.ErrControlKeyChanged):
		s.logger.Error("pinned control key changed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "control_key_changed", "pinned control key no longer matches the control server")
	case errors.Is(err, daemon.ErrAddAccountUntrusted):
		s.writeError(writer, http.StatusConflict, "add_account_untrusted",
			"the server in use is not trusted yet: sign in to it first")
	case errors.Is(err, daemon.ErrAddAccountNoDevice):
		s.writeError(writer, http.StatusConflict, "add_account_no_device",
			"the account in use has no device yet: sign in to it first")
	case errors.Is(err, daemon.ErrProfileRemoving):
		s.writeError(writer, http.StatusConflict, "profile_removing", "the profile is being removed; try again")
	case errors.Is(err, daemon.ErrGatewayLogout), errors.Is(err, daemon.ErrGatewayProfiles):
		s.writeError(writer, http.StatusConflict, "gateway_profile",
			"a Kubernetes gateway does not log out or remove its profile; uninstall the gateway instead")
	case errors.Is(err, daemon.ErrProfileActivated):
		s.logger.Warn("profile became active during removal", "error", err)
		s.writeError(writer, http.StatusConflict, "profile_activated",
			"the profile became active while it was being removed; its keys are deleted, so sign in to it again "+
				"with meshctl login")
	case errors.Is(err, daemon.ErrProfileRemoval) &&
		errors.Is(err, controlplane.ErrDeviceNotAuthorized):
		s.writeError(writer, http.StatusConflict, "profile_remove_refused",
			"Core did not accept this profile's keys, so nothing was removed; run meshctl profile remove --local "+
				"to drop them here, and ask an administrator to remove the device")
	case errors.Is(err, daemon.ErrProfileRemoval) &&
		errors.Is(err, controlplane.ErrRegistrationTemporary):
		s.logger.Warn("profile removal is temporarily unavailable", "error", err)
		s.writeError(writer, http.StatusServiceUnavailable, "profile_remove_unavailable",
			"Core could not remove the device right now; try again, or use --local")
	case errors.Is(err, daemon.ErrProfileRemoval):
		s.logger.Warn("profile removal failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "profile_remove_failed",
			"the profile was not removed; if Core is unreachable for good, use meshctl profile remove --local")
	case errors.Is(err, daemon.ErrControlNotTrusted):
		s.writeError(writer, http.StatusConflict, "control_not_trusted", "pin the active profile control key before login")
	case errors.Is(err, daemon.ErrAuthorizationPending):
		s.writeError(writer, http.StatusConflict, "authorization_pending", "browser authorization is still pending")
	case errors.Is(err, daemon.ErrStopSignInUnavailable):
		s.writeError(writer, http.StatusServiceUnavailable, "stop_sign_in_unavailable",
			"the stopped sign-in could not be recorded, so it is still pending; try again")
	case errors.Is(err, daemon.ErrNoPendingAuthorization):
		s.writeError(writer, http.StatusConflict, "no_pending_authorization", "no browser authorization is pending")
	case errors.Is(err, controlplane.ErrNodeKeyExpired):
		s.writeError(writer, http.StatusConflict, "node_key_expired", "node key rotation is required")
	case errors.Is(err, daemon.ErrNodeKeyRotation) &&
		errors.Is(err, controlplane.ErrRegistrationTemporary):
		s.logger.Warn("node key rotation is temporarily unavailable", "error", err)
		s.writeError(writer, http.StatusServiceUnavailable, "node_key_rotation_unavailable", "node key rotation is temporarily unavailable")
	case errors.Is(err, daemon.ErrNodeKeyRotation):
		s.logger.Warn("node key rotation failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "node_key_rotation_failed", "node key rotation failed")
	case errors.Is(err, daemon.ErrNothingToApprove):
		s.writeError(writer, http.StatusConflict, "nothing_to_approve", "none of these exit nodes or pools waits for approval")
	case errors.Is(err, daemon.ErrControlSessionBusy):
		s.writeError(writer, http.StatusServiceUnavailable, "control_session_busy", "meshd is still stopping its control session; try again")
	case errors.Is(err, daemon.ErrLogout) &&
		errors.Is(err, controlplane.ErrRegistrationTemporary):
		s.logger.Warn("logout is temporarily unavailable", "error", err)
		s.writeError(writer, http.StatusServiceUnavailable, "logout_unavailable", "logout is temporarily unavailable; try again")
	case errors.Is(err, daemon.ErrSignedOutNeedsSignIn):
		s.writeError(writer, http.StatusConflict, "signed_out",
			"this device is signed out: run meshctl login without a key to sign back in, "+
				"or meshctl logout --remove to remove it")
	case errors.Is(err, daemon.ErrSignOutUnsupported):
		s.writeError(writer, http.StatusConflict, "sign_out_unsupported",
			"this server removes the device when it signs out; run meshctl logout --remove to remove it")
	case errors.Is(err, daemon.ErrSignOutNotPermitted):
		s.writeError(writer, http.StatusConflict, "sign_out_not_permitted",
			"this device belongs to the Workspace and cannot sign out; remove it with meshctl logout --remove, "+
				"or ask an administrator")
	case errors.Is(err, daemon.ErrLogout) &&
		errors.Is(err, controlplane.ErrDeviceNotAuthorized):
		// The keys stay (TD-CLI-100): say so, and what to do.
		s.writeError(writer, http.StatusConflict, "logout_refused",
			"Core did not accept this device's keys, so they were kept; sign in again with meshctl login, "+
				"or ask an administrator to remove the device")
	case errors.Is(err, daemon.ErrLogout):
		s.logger.Warn("logout failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "logout_failed", "logout failed")
	case errors.Is(err, daemon.ErrNATInactive):
		s.writeError(writer, http.StatusConflict, "nat_classification_inactive", "no connected session to classify the network from")
	case errors.Is(err, daemon.ErrControlProbe):
		s.logger.Warn("control compatibility probe failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "control_probe_failed", "control compatibility probe failed")
	case errors.Is(err, daemon.ErrControlTrust):
		s.logger.Warn("control trust operation failed", "error", err)
		s.writeError(writer, http.StatusBadGateway, "control_trust_failed", "control trust operation failed")
	case errors.Is(err, daemon.ErrRegistration):
		// Core refused: its reason, in its own words, tells the person what to
		// do (sign in to another Network, start again); a retry would not help.
		if rejected, ok := errors.AsType[*controlplane.RejectedError](err); ok && isRejectionCode(rejected.Code) {
			s.logger.Warn("node registration refused", "code", rejected.Code)
			s.writeError(writer, http.StatusConflict, "registration_"+rejected.Code, rejected.Message)
			return
		}
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

// deviceExpiresAt is the wire form of the Device's expiry; empty while it is
// unknown or the Device never expires.
func deviceExpiresAt(status daemon.Status) string {
	if status.DeviceExpiresAt.IsZero() || status.DeviceExpiry == daemon.DeviceExpiryNever {
		return ""
	}
	return status.DeviceExpiresAt.UTC().Format(time.RFC3339)
}

func mapCaptiveStatus(view daemon.CaptiveView) *captiveStatus {
	if view.State == "" || view.State == "none" {
		return nil
	}
	status := &captiveStatus{State: view.State, URL: view.URL, Interface: view.Interface}
	if !view.Since.IsZero() {
		status.Since = view.Since.UTC().Format(time.RFC3339)
	}
	if !view.Until.IsZero() {
		status.Until = view.Until.UTC().Format(time.RFC3339)
	}
	return status
}

// handleCaptiveCheck has meshd ask the helper about a captive portal window
// at once, after root opened or closed one (meshctl exit captive). It
// changes nothing, so any local user may ask.
func (s *Server) handleCaptiveCheck(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		s.writeMethodNotAllowed(writer, http.MethodPost)
		return
	}
	s.service.CheckCaptiveWindow()
	s.writeJSON(writer, http.StatusOK, captiveCheckResponse{APIVersion: apiVersion})
}

// mapConnectionLogs is connection logging's wire form; nil while off.
func mapConnectionLogs(status flowreport.Status) *connectionLogStatus {
	if !status.On {
		return nil
	}
	wire := &connectionLogStatus{On: true, Pending: status.Pending, LastError: status.LastError}
	if !status.LastSent.IsZero() {
		wire.LastSent = status.LastSent.UTC().Format(time.RFC3339)
	}
	return wire
}

// mapKubernetesClusters is the wire form of the node's clusters; nil when
// it takes none.
func mapKubernetesClusters(clusters []daemon.KubernetesClusterView) []kubernetesClusterStatus {
	if len(clusters) == 0 {
		return nil
	}
	mapped := make([]kubernetesClusterStatus, 0, len(clusters))
	for _, cluster := range clusters {
		mapped = append(mapped, kubernetesClusterStatus{
			ID: cluster.ID, Name: cluster.Name, DNSName: cluster.DNSName, TLSServerName: cluster.TLSServerName,
			State: cluster.State, Roots: cluster.RootFingerprints, RootsExcluded: cluster.RootsExcluded,
			HeldUntil: formatStatusTime(cluster.HeldUntil), CAFile: cluster.CAFile, CAFileState: cluster.CAFileState,
			CAFileReason: cluster.CAFileReason,
		})
	}
	return mapped
}

// isRejectionCode reports a Core rejection code fit for an API error code:
// short lowercase words with underscores, as mtcp-v1 names them.
func isRejectionCode(code string) bool {
	if code == "" || len(code) > 32 {
		return false
	}
	for _, character := range code {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return true
}
