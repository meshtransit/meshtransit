package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/meshtransit/meshtransit/internal/guardrail"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	guardrailListOperation    = "guardrail_list"
	guardrailCreateOperation  = "guardrail_create"
	guardrailUpdateOperation  = "guardrail_update"
	guardrailDeleteOperation  = "guardrail_delete"
	maximumGuardrailBodyBytes = 16 << 10
)

// GuardrailManager lists and changes Workspace guardrails.
type GuardrailManager interface {
	List(context.Context, accountsession.Session, workspace.ID) (guardrail.Listing, error)
	Create(context.Context, accountsession.Session, workspace.ID, guardrail.Spec, publicid.ID) (guardrail.Result, error)
	Update(context.Context, accountsession.Session, workspace.ID, publicid.ID, int64, guardrail.Spec,
		publicid.ID) (guardrail.Result, error)
	Delete(context.Context, accountsession.Session, workspace.ID, publicid.ID, int64, publicid.ID) (guardrail.Result, error)
}

type guardrailPath struct {
	workspaceID workspace.ID
	guardrailID publicid.ID
	action      string // "" to list, "create", "update" or "delete"
}

// parseGuardrailPath matches
// GET /api/v1/workspaces/{ws}/guardrails,
// POST /api/v1/workspaces/{ws}/guardrails/actions/create and
// POST /api/v1/workspaces/{ws}/guardrails/{id}/actions/{update|delete}.
func parseGuardrailPath(request *http.Request) (guardrailPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return guardrailPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "guardrails" {
		return guardrailPath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return guardrailPath{}, false
	}
	switch len(segments) {
	case 5:
		return guardrailPath{workspaceID: workspaceID}, true
	case 7:
		if segments[5] != "actions" || segments[6] != "create" {
			return guardrailPath{}, false
		}
		return guardrailPath{workspaceID: workspaceID, action: "create"}, true
	case 8:
		id, err := publicid.Parse(segments[5])
		if err != nil || id.String() != segments[5] || segments[6] != "actions" ||
			(segments[7] != "update" && segments[7] != "delete") {
			return guardrailPath{}, false
		}
		return guardrailPath{workspaceID: workspaceID, guardrailID: id, action: segments[7]}, true
	default:
		return guardrailPath{}, false
	}
}

func (path guardrailPath) allowedMethod(string) string {
	if path.action == "" {
		return http.MethodGet
	}
	return http.MethodPost
}

func (path guardrailPath) operation(string) string {
	switch path.action {
	case "update":
		return guardrailUpdateOperation
	case "delete":
		return guardrailDeleteOperation
	case "create":
		return guardrailCreateOperation
	default:
		return guardrailListOperation
	}
}

// isGuardrailOperation admits only the method each path allows.
func isGuardrailOperation(request *http.Request) bool {
	path, ok := parseGuardrailPath(request)
	return ok && request.Method == path.allowedMethod(request.Method)
}

// isGuardrailRead admits the exact, query-free list.
func isGuardrailRead(request *http.Request) bool {
	path, ok := parseGuardrailPath(request)
	return ok && path.action == "" && request.Method == http.MethodGet
}

type guardrailBody struct {
	GuardrailID string          `json:"guardrail_id"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Mode        string          `json:"mode"`
	Params      json.RawMessage `json:"params"`
	Version     int64           `json:"version"`
}

func newGuardrailBody(item guardrail.Guardrail) (guardrailBody, error) {
	params, err := item.ParamsDocument()
	if err != nil {
		return guardrailBody{}, err
	}
	return guardrailBody{
		GuardrailID: item.ID.String(), Kind: string(item.Kind), Name: item.Name, Description: item.Description,
		Mode: string(item.Mode), Params: params, Version: item.Version,
	}, nil
}

var guardrailParamKeys = map[guardrail.Kind][]string{
	guardrail.KindNetworkIsolation: {"from_networks", "to_networks", "both_directions"},
	guardrail.KindNetworkSharing:   {"networks", "direction"},
	guardrail.KindExternalSharing:  {"direction", "networks", "allowed_workspaces"},
}

// parseGuardrailSpec accepts exactly kind, name, description, mode and the
// kind's params, each params key once; the domain validates the values.
func parseGuardrailSpec(response http.ResponseWriter, request *http.Request) (guardrail.Spec, bool) {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return guardrail.Spec{}, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumGuardrailBodyBytes))
	if err != nil {
		return guardrail.Spec{}, false
	}
	var body struct {
		Kind        string          `json:"kind"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Mode        string          `json:"mode"`
		Params      json.RawMessage `json:"params"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil {
		return guardrail.Spec{}, false
	}
	allowed, known := guardrailParamKeys[guardrail.Kind(body.Kind)]
	var params map[string]json.RawMessage
	if !known || json.Unmarshal(body.Params, &params) != nil || params == nil || len(params) != len(allowed) {
		return guardrail.Spec{}, false
	}
	for _, key := range allowed {
		if _, present := params[key]; !present {
			return guardrail.Spec{}, false
		}
	}
	spec := guardrail.Spec{Name: body.Name, Description: body.Description, Mode: guardrail.Mode(body.Mode)}
	if guardrail.ParseParams(guardrail.Kind(body.Kind), body.Params, &spec) != nil {
		return guardrail.Spec{}, false
	}
	return spec, spec.IsValid()
}

func (handler *ManagementHandler) handleGuardrails(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path guardrailPath, session accountsession.Session) string {
	if nilContinuationDependency(handler.guardrails) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Guardrails are temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if path.action == "" {
		listing, err := handler.guardrails.List(ctx, session, path.workspaceID)
		if err != nil {
			return fail(classifyGuardrailError(err))
		}
		bodies := make([]guardrailBody, 0, len(listing.Guardrails))
		for _, item := range listing.Guardrails {
			body, err := newGuardrailBody(item)
			if err != nil {
				return fail(internalManagementError())
			}
			bodies = append(bodies, body)
		}
		var output struct {
			Data struct {
				Guardrails []guardrailBody `json:"guardrails"`
				CanManage  bool            `json:"can_manage"`
				CanWeaken  bool            `json:"can_weaken"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Guardrails, output.CorrelationID = bodies, correlationID.String()
		output.Data.CanManage, output.Data.CanWeaken = listing.CanManage, listing.CanWeaken
		response.Header().Set("Cache-Control", "no-store")
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	}

	var result guardrail.Result
	var err error
	switch path.action {
	case "create":
		spec, valid := parseGuardrailSpec(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.guardrails.Create(ctx, session, path.workspaceID, spec, correlationID)
	default:
		expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		if path.action == "update" {
			spec, valid := parseGuardrailSpec(response, request)
			if !valid {
				return fail(*invalidManagementRequest())
			}
			result, err = handler.guardrails.Update(ctx, session, path.workspaceID, path.guardrailID,
				expectedVersion, spec, correlationID)
		} else {
			result, err = handler.guardrails.Delete(ctx, session, path.workspaceID, path.guardrailID,
				expectedVersion, correlationID)
		}
	}
	if err != nil {
		return fail(classifyGuardrailError(err))
	}
	body, err := newGuardrailBody(result.Guardrail)
	if err != nil {
		return fail(internalManagementError())
	}
	var output struct {
		Data struct {
			Guardrail guardrailBody `json:"guardrail"`
			Deleted   bool          `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Guardrail, output.Data.Deleted, output.CorrelationID = body, result.Deleted, correlationID.String()
	status := http.StatusOK
	if path.action == "create" {
		status = http.StatusCreated
	}
	response.Header().Set("ETag", strongVersionETag(result.Guardrail.Version))
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func classifyGuardrailError(err error) managementError {
	switch {
	case errors.Is(err, guardrail.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change guardrails in this Workspace"}
	case errors.Is(err, guardrail.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "guardrail_not_found",
			Message: "The guardrail no longer exists"}
	case errors.Is(err, guardrail.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The guardrail changed. Reload and review it again."}
	case errors.Is(err, guardrail.ErrUnknownNetwork):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "guardrail_network_unknown",
			Message: "A chosen Network is not in this Workspace"}
	case errors.Is(err, guardrail.ErrLimit):
		return managementError{Status: http.StatusConflict, Code: "guardrail_limit",
			Message: "This Workspace already has the maximum number of guardrails"}
	case errors.Is(err, guardrail.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload guardrails before trying again.", Retryable: true}
	}
}
