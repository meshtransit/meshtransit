package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	guardrailListOperation    = "guardrail_list"
	guardrailCreateOperation  = "guardrail_create"
	guardrailUpdateOperation  = "guardrail_update"
	guardrailDeleteOperation  = "guardrail_delete"
	guardrailPreviewOperation = "guardrail_preview"
	maximumGuardrailBodyBytes = 16 << 10
)

// GuardrailManager lists and changes Workspace guardrails.
type GuardrailManager interface {
	List(context.Context, accountsession.Session, workspace.ID) (guardrail.Listing, error)
	Preview(context.Context, accountsession.Session, workspace.ID, guardrail.Candidate) (guardrail.Impact, error)
	Create(context.Context, accountsession.Session, workspace.ID, guardrail.Spec, guardrail.ImpactHash,
		publicid.ID) (guardrail.Result, error)
	Update(context.Context, accountsession.Session, workspace.ID, publicid.ID, int64, guardrail.Spec,
		guardrail.ImpactHash, publicid.ID) (guardrail.Result, error)
	Delete(context.Context, accountsession.Session, workspace.ID, publicid.ID, int64, publicid.ID) (guardrail.Result, error)
}

type guardrailPath struct {
	workspaceID workspace.ID
	guardrailID publicid.ID
	// methods are the methods the path accepts; action is what the request's
	// method does there: "" to list, "create", "preview", "update" or
	// "delete", and "" when the path does not accept the method.
	methods restMethods
	action  string
}

// parseGuardrailPath matches, under /api/v1/workspaces/{ws}:
//
//	GET|POST     guardrails                  list, create
//	POST         guardrails/actions/preview  preview a candidate
//	PATCH|DELETE guardrails/{id}             update, delete
//
// A path matched with a method it does not accept carries no action, for a 405.
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
	path := guardrailPath{workspaceID: workspaceID}
	var actions map[string]string
	switch {
	case len(segments) == 5:
		path.methods, actions = collectionMethods, map[string]string{http.MethodPost: "create"}
	case len(segments) == 7 && segments[5] == "actions" && segments[6] == "preview":
		path.methods, actions = restMethods{http.MethodPost}, map[string]string{http.MethodPost: "preview"}
	case len(segments) == 6:
		id, err := publicid.Parse(segments[5])
		if err != nil || id.String() != segments[5] {
			return guardrailPath{}, false
		}
		path.guardrailID, path.methods = id, itemMethods
		actions = map[string]string{http.MethodPatch: "update", http.MethodDelete: "delete"}
	default:
		return guardrailPath{}, false
	}
	if path.methods.allows(request.Method) {
		path.action = actions[request.Method]
	}
	return path, true
}

func (path guardrailPath) allowedMethod(method string) string {
	return path.methods.allowedMethod(method)
}

func (path guardrailPath) operation(string) string {
	switch path.action {
	case "update":
		return guardrailUpdateOperation
	case "delete":
		return guardrailDeleteOperation
	case "create":
		return guardrailCreateOperation
	case "preview":
		return guardrailPreviewOperation
	default:
		return guardrailListOperation
	}
}

// isGuardrailOperation admits only the methods each path accepts.
func isGuardrailOperation(request *http.Request) bool {
	path, ok := parseGuardrailPath(request)
	return ok && path.methods.allows(request.Method)
}

// isGuardrailRead admits the exact, query-free list.
func isGuardrailRead(request *http.Request) bool {
	path, ok := parseGuardrailPath(request)
	return ok && request.Method == http.MethodGet && path.methods.allows(http.MethodGet)
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

// guardrailRequest is a create, update or preview body: the spec, the
// impact hash a save echoes, and for a preview of an update the guardrail
// and its expected version.
type guardrailRequest struct {
	spec            guardrail.Spec
	impact          guardrail.ImpactHash
	guardrailID     publicid.ID
	expectedVersion int64
}

type guardrailRequestBody struct {
	Kind            string          `json:"kind"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Mode            string          `json:"mode"`
	Params          json.RawMessage `json:"params"`
	ImpactHash      *string         `json:"impact_hash"`
	GuardrailID     *string         `json:"guardrail_id"`
	ExpectedVersion *int64          `json:"expected_version"`
}

// parseGuardrailRequest accepts exactly kind, name, description, mode and
// the kind's params, each params key once, plus impact_hash on a save or
// guardrail_id with expected_version (both or neither) on a preview; the
// domain validates the values.
func parseGuardrailRequest(response http.ResponseWriter, request *http.Request, preview bool) (guardrailRequest, bool) {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return guardrailRequest{}, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumGuardrailBodyBytes))
	if err != nil {
		return guardrailRequest{}, false
	}
	var body guardrailRequestBody
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil {
		return guardrailRequest{}, false
	}
	if preview && body.ImpactHash != nil || !preview && (body.GuardrailID != nil || body.ExpectedVersion != nil) ||
		(body.GuardrailID == nil) != (body.ExpectedVersion == nil) {
		return guardrailRequest{}, false
	}
	spec, valid := parseGuardrailSpec(body)
	if !valid {
		return guardrailRequest{}, false
	}
	parsed := guardrailRequest{spec: spec}
	if body.ImpactHash != nil {
		if parsed.impact, err = guardrail.ParseImpactHash(*body.ImpactHash); err != nil {
			return guardrailRequest{}, false
		}
	}
	if body.GuardrailID != nil {
		id, err := publicid.Parse(*body.GuardrailID)
		if err != nil || id.String() != *body.GuardrailID || *body.ExpectedVersion <= 0 {
			return guardrailRequest{}, false
		}
		parsed.guardrailID, parsed.expectedVersion = id, *body.ExpectedVersion
	}
	return parsed, true
}

// parseGuardrailSpec requires the kind's params keys, each once.
func parseGuardrailSpec(body guardrailRequestBody) (guardrail.Spec, bool) {
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

type guardrailAffectedBody struct {
	TrustContractID string `json:"trust_contract_id"`
	Side            string `json:"side"`
	NetworkID       string `json:"network_id"`
	Label           string `json:"label"`
}

// writeGuardrailPreview answers a preview: the affected shares, at most
// MaximumPreviewItems of them listed, and the hash a save must echo.
func (handler *ManagementHandler) writeGuardrailPreview(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, impact guardrail.Impact) {
	listed := impact.Affected[:min(len(impact.Affected), guardrail.MaximumPreviewItems)]
	affected := make([]guardrailAffectedBody, len(listed))
	for index, contract := range listed {
		affected[index] = guardrailAffectedBody{TrustContractID: contract.ID.String(), Side: string(contract.Side),
			NetworkID: contract.NetworkID.String(), Label: contract.Label}
	}
	var output struct {
		Data struct {
			Mode          string                  `json:"mode"`
			AffectedCount int                     `json:"affected_count"`
			Affected      []guardrailAffectedBody `json:"affected"`
			Truncated     bool                    `json:"truncated"`
			ImpactHash    string                  `json:"impact_hash"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Mode, output.Data.AffectedCount, output.Data.Affected = string(impact.Mode), len(impact.Affected), affected
	output.Data.Truncated, output.Data.ImpactHash = len(listed) < len(impact.Affected), impact.Hash.String()
	output.CorrelationID = correlationID.String()
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
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

	if path.action == "preview" {
		body, valid := parseGuardrailRequest(response, request, true)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		impact, err := handler.guardrails.Preview(ctx, session, path.workspaceID, guardrail.Candidate{
			GuardrailID: body.guardrailID, ExpectedVersion: body.expectedVersion, Spec: body.spec})
		if err != nil {
			return fail(classifyGuardrailError(err))
		}
		handler.writeGuardrailPreview(ctx, response, correlationID, impact)
		return "success"
	}

	var result guardrail.Result
	var err error
	switch path.action {
	case "create":
		body, valid := parseGuardrailRequest(response, request, false)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.guardrails.Create(ctx, session, path.workspaceID, body.spec, body.impact, correlationID)
	default:
		expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		if path.action == "update" {
			body, valid := parseGuardrailRequest(response, request, false)
			if !valid {
				return fail(*invalidManagementRequest())
			}
			result, err = handler.guardrails.Update(ctx, session, path.workspaceID, path.guardrailID,
				expectedVersion, body.spec, body.impact, correlationID)
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
	case errors.Is(err, guardrail.ErrImpactChanged):
		return managementError{Status: http.StatusConflict, Code: "guardrail_impact_changed",
			Message: "The shares this guardrail cuts changed. Preview it again before saving."}
	case errors.Is(err, guardrail.ErrImpactTooLarge):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "guardrail_impact_too_large",
			Message: "This Workspace has too many active shares to preview a guardrail"}
	case errors.Is(err, guardrail.ErrUnavailable):
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload guardrails before trying again.", Retryable: true}
	case errors.Is(err, guardrail.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload guardrails before trying again.", Retryable: true}
	}
}
