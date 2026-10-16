package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/key"
)

const (
	interchangeListOperation    = "interchange_list"
	interchangeCreateOperation  = "interchange_create"
	interchangeUpdateOperation  = "interchange_update"
	interchangeDeleteOperation  = "interchange_delete"
	maximumInterchangeBodyBytes = 32 << 10
)

// InterchangeManager lists and changes a Workspace's Private Interchange
// relays.
type InterchangeManager interface {
	List(context.Context, accountsession.Session, workspace.ID) (interchange.Listing, error)
	Create(context.Context, accountsession.Session, workspace.ID, interchange.Spec, publicid.ID) (interchange.Result, error)
	Update(context.Context, accountsession.Session, workspace.ID, publicid.ID, int64, interchange.Spec,
		publicid.ID) (interchange.Result, error)
	Delete(context.Context, accountsession.Session, workspace.ID, publicid.ID, int64, publicid.ID) (interchange.Result, error)
}

// InterchangeRelayTrust is what a Private Interchange relay needs to reach
// Core, shown with the command that starts it: the control URL and Core's
// relay signing keys. Both are public.
type InterchangeRelayTrust struct {
	CoreURL     string
	SigningKeys []key.SigningPublic
}

type interchangePath struct {
	workspaceID   workspace.ID
	interchangeID publicid.ID
	// methods are the methods the path accepts; action is what the request's
	// method does there: "" to list, "create", "update" or "delete", and ""
	// when the path does not accept the method.
	methods restMethods
	action  string
}

// parseInterchangePath matches, under /api/v1/workspaces/{ws}:
//
//	GET|POST     interchanges       list, create
//	PATCH|DELETE interchanges/{id}  update, delete
//
// A path matched with a method it does not accept carries no action, for a 405.
func parseInterchangePath(request *http.Request) (interchangePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return interchangePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "interchanges" {
		return interchangePath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return interchangePath{}, false
	}
	path := interchangePath{workspaceID: workspaceID}
	var actions map[string]string
	switch len(segments) {
	case 5:
		path.methods, actions = collectionMethods, map[string]string{http.MethodPost: "create"}
	case 6:
		id, err := publicid.Parse(segments[5])
		if err != nil || id.String() != segments[5] {
			return interchangePath{}, false
		}
		path.interchangeID, path.methods = id, itemMethods
		actions = map[string]string{http.MethodPatch: "update", http.MethodDelete: "delete"}
	default:
		return interchangePath{}, false
	}
	if path.methods.allows(request.Method) {
		path.action = actions[request.Method]
	}
	return path, true
}

func (path interchangePath) allowedMethod(method string) string {
	return path.methods.allowedMethod(method)
}

func (path interchangePath) operation(string) string {
	switch path.action {
	case "update":
		return interchangeUpdateOperation
	case "delete":
		return interchangeDeleteOperation
	case "create":
		return interchangeCreateOperation
	default:
		return interchangeListOperation
	}
}

// isInterchangeOperation admits only the methods each path accepts.
func isInterchangeOperation(request *http.Request) bool {
	path, ok := parseInterchangePath(request)
	return ok && path.methods.allows(request.Method)
}

// isInterchangeRead admits the exact, query-free list.
func isInterchangeRead(request *http.Request) bool {
	path, ok := parseInterchangePath(request)
	return ok && request.Method == http.MethodGet && path.methods.allows(http.MethodGet)
}

type interchangeBody struct {
	InterchangeID string    `json:"interchange_id"`
	Name          string    `json:"name"`
	RegionID      uint16    `json:"region_id"`
	RegionCode    string    `json:"region_code"`
	HostName      string    `json:"host_name"`
	IPv4          *string   `json:"ipv4"`
	IPv6          *string   `json:"ipv6"`
	RelayKey      string    `json:"relay_key"`
	UDPPort       uint16    `json:"udp_port"`
	TLSPort       uint16    `json:"tls_port"`
	STUNPort      uint16    `json:"stun_port"`
	NetworkIDs    []string  `json:"network_ids"`
	Version       int64     `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func newInterchangeBody(item interchange.Interchange) interchangeBody {
	optional := func(addr netip.Addr) *string {
		if !addr.IsValid() {
			return nil
		}
		text := addr.String()
		return &text
	}
	body := interchangeBody{InterchangeID: item.ID.String(), Name: item.Spec.Name, RegionID: item.RegionID,
		RegionCode: item.Spec.RegionCode, HostName: item.Spec.HostName, IPv4: optional(item.Spec.IPv4),
		IPv6: optional(item.Spec.IPv6), RelayKey: item.Spec.RelayKey.String(), UDPPort: item.Spec.UDPPort,
		TLSPort: item.Spec.TLSPort, STUNPort: item.Spec.STUNPort, NetworkIDs: make([]string, len(item.Spec.Networks)),
		Version: item.Version, CreatedAt: item.CreatedAt.UTC(), UpdatedAt: item.UpdatedAt.UTC()}
	for index, id := range item.Spec.Networks {
		body.NetworkIDs[index] = id.String()
	}
	return body
}

// parseInterchangeSpec accepts exactly the relay fields; the domain
// validates the values.
func parseInterchangeSpec(response http.ResponseWriter, request *http.Request) (interchange.Spec, bool) {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return interchange.Spec{}, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumInterchangeBodyBytes))
	if err != nil {
		return interchange.Spec{}, false
	}
	var body struct {
		Name       string   `json:"name"`
		RegionCode string   `json:"region_code"`
		HostName   string   `json:"host_name"`
		IPv4       *string  `json:"ipv4"`
		IPv6       *string  `json:"ipv6"`
		RelayKey   string   `json:"relay_key"`
		UDPPort    uint16   `json:"udp_port"`
		TLSPort    uint16   `json:"tls_port"`
		STUNPort   uint16   `json:"stun_port"`
		NetworkIDs []string `json:"network_ids"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil || body.NetworkIDs == nil ||
		len(body.NetworkIDs) > interchange.MaxNetworks {
		return interchange.Spec{}, false
	}
	relayKey, err := key.ParseRelayPublic(body.RelayKey)
	if err != nil {
		return interchange.Spec{}, false
	}
	spec := interchange.Spec{Name: body.Name, RegionCode: body.RegionCode, HostName: body.HostName,
		RelayKey: relayKey, UDPPort: body.UDPPort, TLSPort: body.TLSPort, STUNPort: body.STUNPort}
	for _, address := range []struct {
		text   *string
		target *netip.Addr
	}{{body.IPv4, &spec.IPv4}, {body.IPv6, &spec.IPv6}} {
		if address.text == nil {
			continue
		}
		parsed, err := netip.ParseAddr(*address.text)
		if err != nil || parsed.String() != *address.text {
			return interchange.Spec{}, false
		}
		*address.target = parsed
	}
	networks := make([]network.ID, 0, len(body.NetworkIDs))
	for _, text := range body.NetworkIDs {
		id, err := network.ParseID(text)
		if err != nil || id.String() != text {
			return interchange.Spec{}, false
		}
		networks = append(networks, id)
	}
	spec.Networks = interchange.SortNetworks(networks)
	if len(spec.Networks) != len(networks) {
		return interchange.Spec{}, false // duplicates
	}
	return spec, spec.IsValid()
}

func (handler *ManagementHandler) handleInterchanges(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path interchangePath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if nilContinuationDependency(handler.interchanges) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Private Interchange is temporarily unavailable", Retryable: true})
	}
	if path.action == "" {
		listing, err := handler.interchanges.List(ctx, session, path.workspaceID)
		if err != nil {
			return fail(classifyInterchangeError(err))
		}
		var output struct {
			Data struct {
				Interchanges []interchangeBody `json:"interchanges"`
				CanManage    bool              `json:"can_manage"`
				CoreURL      *string           `json:"core_url"`
				SigningKeys  []string          `json:"relay_signing_keys"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Interchanges = make([]interchangeBody, 0, len(listing.Interchanges))
		for _, item := range listing.Interchanges {
			output.Data.Interchanges = append(output.Data.Interchanges, newInterchangeBody(item))
		}
		output.Data.CanManage, output.CorrelationID = listing.CanManage, correlationID.String()
		output.Data.SigningKeys = []string{}
		if trust := handler.interchangeTrust; trust.CoreURL != "" {
			coreURL := trust.CoreURL
			output.Data.CoreURL = &coreURL
			for _, signing := range trust.SigningKeys {
				output.Data.SigningKeys = append(output.Data.SigningKeys, signing.String())
			}
		}
		response.Header().Set("Cache-Control", "no-store")
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	}

	var result interchange.Result
	var err error
	switch path.action {
	case "create":
		spec, valid := parseInterchangeSpec(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.interchanges.Create(ctx, session, path.workspaceID, spec, correlationID)
	default:
		expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		if path.action == "update" {
			spec, valid := parseInterchangeSpec(response, request)
			if !valid {
				return fail(*invalidManagementRequest())
			}
			result, err = handler.interchanges.Update(ctx, session, path.workspaceID, path.interchangeID,
				expectedVersion, spec, correlationID)
		} else {
			result, err = handler.interchanges.Delete(ctx, session, path.workspaceID, path.interchangeID,
				expectedVersion, correlationID)
		}
	}
	if err != nil {
		return fail(classifyInterchangeError(err))
	}
	var output struct {
		Data struct {
			Interchange interchangeBody `json:"interchange"`
			Deleted     bool            `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Interchange, output.Data.Deleted = newInterchangeBody(result.Interchange), result.Deleted
	output.CorrelationID = correlationID.String()
	status := http.StatusOK
	if path.action == "create" {
		status = http.StatusCreated
	}
	response.Header().Set("ETag", strongVersionETag(result.Interchange.Version))
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func classifyInterchangeError(err error) managementError {
	switch {
	case errors.Is(err, interchange.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change Private Interchange relays in this Workspace"}
	case errors.Is(err, interchange.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "interchange_not_found",
			Message: "The relay no longer exists"}
	case errors.Is(err, interchange.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The relay changed. Reload and review it again."}
	case errors.Is(err, interchange.ErrUnknownNetwork):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "interchange_network_unknown",
			Message: "A chosen Network is not in this Workspace"}
	case errors.Is(err, interchange.ErrConflict):
		return managementError{Status: http.StatusConflict, Code: "interchange_conflict",
			Message: "Another relay already uses this relay key or region code"}
	case errors.Is(err, interchange.ErrLimit):
		return managementError{Status: http.StatusConflict, Code: "interchange_limit",
			Message: "This Workspace already has the maximum number of relays"}
	case errors.Is(err, interchange.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload the relays before trying again.", Retryable: true}
	}
}
