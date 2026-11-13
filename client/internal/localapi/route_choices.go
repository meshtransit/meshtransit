package localapi

import (
	"errors"
	"net/http"

	"golang.org/x/time/rate"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/routesettings"
)

// maxRouteChoicesBody bounds a change: three short fields.
const maxRouteChoicesBody = 4 << 10

// The route choices' rate: an app reads them when a page opens and after
// a change, a person changes them by hand.
const (
	routeChoiceRate  = rate.Limit(5)
	routeChoiceBurst = 10
)

// routeChoicesResponse is the host's own route choices (exit node design
// §11), whether root lets the operators change them, and whether this
// caller may.
type routeChoicesResponse struct {
	APIVersion   string `json:"api_version"`
	AcceptRoutes bool   `json:"accept_routes"`
	ExitUse      string `json:"exit_use"`
	ExitAllowLAN bool   `json:"exit_allow_lan"`
	Operators    bool   `json:"operators"`
	// CanChange: this caller may change them through this resource.
	CanChange bool `json:"can_change"`
}

// routeChoicesChange names the choices to change; a missing field stays.
type routeChoicesChange struct {
	ExitUse      *string `json:"exit_use,omitempty"`
	AcceptRoutes *bool   `json:"accept_routes,omitempty"`
	ExitAllowLAN *bool   `json:"exit_allow_lan,omitempty"`
}

// handleRouteChoices reads (GET) or changes (PATCH) the host's own route
// choices. Only an administrator, or an operator while root lets them,
// changes them, and only where meshd writes the route settings (Windows).
func (s *Server) handleRouteChoices(writer http.ResponseWriter, request *http.Request) {
	peer, _ := peerFromContext(request.Context())
	if request.Method != http.MethodGet && request.Method != http.MethodPatch {
		s.writeMethodNotAllowed(writer, http.MethodGet, http.MethodPatch)
		return
	}
	if !s.routeChoiceLimits.allow(peer) {
		s.writeError(writer, http.StatusTooManyRequests, "too_many_requests", "too many requests; try again")
		return
	}
	switch request.Method {
	case http.MethodGet:
		choices, err := s.service.RouteChoices(request.Context(), peer.administrator)
		if err != nil {
			s.writeRouteChoicesError(writer, err)
			return
		}
		s.writeJSON(writer, http.StatusOK, routeChoicesResponseOf(choices))
	case http.MethodPatch:
		request.Body = http.MaxBytesReader(writer, request.Body, maxRouteChoicesBody)
		input := routeChoicesChange{}
		if !s.decodeJSONRequest(writer, request, &input) {
			return
		}
		change := routesettings.ChoiceChange{
			ExitUse: input.ExitUse, AcceptRoutes: input.AcceptRoutes, ExitAllowLAN: input.ExitAllowLAN,
		}
		if input.ExitUse != nil && *input.ExitUse == "" {
			s.writeError(writer, http.StatusBadRequest, "invalid_route_choice",
				"exit_use takes a pool, auto or off")
			return
		}
		if change.Empty() {
			s.writeError(writer, http.StatusBadRequest, "invalid_route_choice",
				"name exit_use, accept_routes or exit_allow_lan")
			return
		}
		choices, err := s.service.ChangeRouteChoices(request.Context(), change, peer.administrator)
		if err != nil {
			s.writeRouteChoicesError(writer, err)
			return
		}
		s.logRouteChoiceChange(peer, change)
		s.writeJSON(writer, http.StatusOK, routeChoicesResponseOf(choices))
	}
}

// logRouteChoiceChange records who changed which choice: the caller's SID
// (Windows) or uid, never a name, and the kind of Exit Pool, never its name.
func (s *Server) logRouteChoiceChange(peer peerIdentity, change routesettings.ChoiceChange) {
	attributes := []any{"administrator", peer.administrator}
	if peer.userSID != "" {
		attributes = append(attributes, "user_sid", peer.userSID)
	} else {
		attributes = append(attributes, "uid", peer.uid)
	}
	if change.ExitUse != nil {
		kind := "pool"
		switch *change.ExitUse {
		case routesettings.ExitUseOff:
			kind = "off"
		case routesettings.ExitUseAuto:
			kind = "auto"
		}
		attributes = append(attributes, "exit_use", kind)
	}
	if change.AcceptRoutes != nil {
		attributes = append(attributes, "accept", *change.AcceptRoutes)
	}
	if change.ExitAllowLAN != nil {
		attributes = append(attributes, "exit_allow_lan", *change.ExitAllowLAN)
	}
	s.logger.Info("route choices changed", attributes...)
}

func routeChoicesResponseOf(choices daemon.RouteChoices) routeChoicesResponse {
	return routeChoicesResponse{
		APIVersion: apiVersion, AcceptRoutes: choices.AcceptRoutes, ExitUse: choices.ExitUse,
		ExitAllowLAN: choices.ExitAllowLAN, Operators: choices.Operators, CanChange: choices.CanChange,
	}
}

func (s *Server) writeRouteChoicesError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, daemon.ErrRouteChoicesReadOnly):
		writer.Header().Set("Allow", http.MethodGet)
		s.writeError(writer, http.StatusMethodNotAllowed, "route_choices_read_only",
			"meshd does not change the route settings here: use meshctl routes")
	case errors.Is(err, daemon.ErrOperatorsOff):
		s.writeError(writer, http.StatusForbidden, "operators_off",
			"an administrator keeps these settings: meshctl routes operators on lets the operators change them")
	case errors.Is(err, routesettings.ErrRootSetting):
		s.writeError(writer, http.StatusConflict, "root_setting",
			"accept-public is on: an administrator turns accept on with meshctl routes accept on")
	case errors.Is(err, routesettings.ErrInvalid):
		s.writeError(writer, http.StatusBadRequest, "invalid_route_choice", "the value is not accepted")
	case errors.Is(err, daemon.ErrRouteChoicesUnavailable):
		s.writeError(writer, http.StatusServiceUnavailable, "route_settings_unavailable",
			"the route settings cannot be used: an administrator checks them with meshctl routes show")
	default:
		s.writeServiceError(writer, err)
	}
}
