package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/flowlog"
)

const (
	storageCredentialListOperation   = "storage_credential_list"
	storageCredentialCreateOperation = "storage_credential_create"
	storageCredentialUpdateOperation = "storage_credential_update"
	storageCredentialDeleteOperation = "storage_credential_delete"
	connectionLogReadOperation       = "connection_log_read"
	connectionLogReplaceOperation    = "connection_log_replace"
)

// ConnectionLogManager keeps a Workspace's storage credentials and its
// Networks' connection log settings (connection logs design §10).
type ConnectionLogManager interface {
	ListCredentials(context.Context, accountsession.Session, workspace.ID) (connectionlog.Credentials, error)
	PutCredential(context.Context, connectionlog.CredentialPut) (connectionlog.Credential, error)
	DeleteCredential(context.Context, connectionlog.CredentialDeletion) error
	ReadSettings(context.Context, accountsession.Session, network.Scope) (connectionlog.NetworkSettings, error)
	ReplaceSettings(context.Context, connectionlog.SettingsReplacement) (connectionlog.SettingsResult, error)
}

type connectionLogPath struct {
	workspaceID  workspace.ID
	scope        network.Scope
	credentialID connectionlog.CredentialID
	methods      restMethods
	operation    string
}

// parseConnectionLogPath matches, under /api/v1/workspaces/{ws}:
//
//	GET|POST     storage-credentials                     list, create
//	PATCH|DELETE storage-credentials/{id}                update or rotate, delete
//	GET|PUT      networks/{net}/connection-logs          read, replace
//
// None takes a query. A path matched with a method it does not accept
// carries no operation, for a 405.
func parseConnectionLogPath(request *http.Request) (connectionLogPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return connectionLogPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" {
		return connectionLogPath{}, false
	}
	workspaceID, ok := canonicalPublicID(segments[3])
	if !ok {
		return connectionLogPath{}, false
	}
	path := connectionLogPath{workspaceID: workspace.ID(workspaceID)}
	var operations map[string]string
	switch {
	case len(segments) == 5 && segments[4] == "storage-credentials":
		path.methods = collectionMethods
		operations = map[string]string{
			http.MethodGet:  storageCredentialListOperation,
			http.MethodPost: storageCredentialCreateOperation,
		}
	case len(segments) == 6 && segments[4] == "storage-credentials":
		id, ok := canonicalPublicID(segments[5])
		if !ok {
			return connectionLogPath{}, false
		}
		path.credentialID, path.methods = connectionlog.CredentialID(id), itemMethods
		operations = map[string]string{
			http.MethodPatch:  storageCredentialUpdateOperation,
			http.MethodDelete: storageCredentialDeleteOperation,
		}
	case len(segments) == 7 && segments[4] == "networks" && segments[6] == "connection-logs":
		networkID, ok := canonicalPublicID(segments[5])
		if !ok {
			return connectionLogPath{}, false
		}
		scope, err := network.NewScope(path.workspaceID, network.ID(networkID))
		if err != nil {
			return connectionLogPath{}, false
		}
		path.scope, path.methods = scope, restMethods{http.MethodGet, http.MethodPut}
		operations = map[string]string{
			http.MethodGet: connectionLogReadOperation,
			http.MethodPut: connectionLogReplaceOperation,
		}
	default:
		return connectionLogPath{}, false
	}
	if path.methods.allows(request.Method) {
		path.operation = operations[request.Method]
	}
	return path, true
}

// isConnectionLogOperation admits only the methods each path accepts.
func isConnectionLogOperation(request *http.Request) bool {
	path, ok := parseConnectionLogPath(request)
	return ok && path.methods.allows(request.Method)
}

// isConnectionLogRead admits the exact, query-free reads.
func isConnectionLogRead(request *http.Request) bool {
	return request != nil && request.Method == http.MethodGet && isConnectionLogOperation(request)
}

// isConnectionLogSettingsWrite admits the PUT of a Network's settings.
func isConnectionLogSettingsWrite(request *http.Request) bool {
	path, ok := parseConnectionLogPath(request)
	return ok && request.Method == http.MethodPut && path.operation == connectionLogReplaceOperation
}

type storageCredentialBody struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Provider        string   `json:"provider"`
	AccountID       *string  `json:"account_id"`
	AccessKeySuffix string   `json:"access_key_suffix"`
	Version         int64    `json:"version"`
	CreatedAt       *string  `json:"created_at"`
	UpdatedAt       *string  `json:"updated_at"`
	Networks        []string `json:"network_ids"`
	UsedBy          []string `json:"used_by_network_ids"`
}

func newStorageCredentialBody(credential connectionlog.Credential) storageCredentialBody {
	body := storageCredentialBody{
		ID: credential.ID.String(), Name: credential.Name, Provider: credential.Provider,
		AccessKeySuffix: credential.AccessKeySuffix, Version: credential.Version,
		CreatedAt: optionalManagementTime(credential.CreatedAt), UpdatedAt: optionalManagementTime(credential.UpdatedAt),
		Networks: make([]string, 0, len(credential.Networks)), UsedBy: make([]string, 0, len(credential.UsedBy)),
	}
	if credential.AccountID != "" {
		account := credential.AccountID
		body.AccountID = &account
	}
	for _, id := range credential.Networks {
		body.Networks = append(body.Networks, id.String())
	}
	for _, id := range credential.UsedBy {
		body.UsedBy = append(body.UsedBy, id.String())
	}
	return body
}

type connectionLogSettingsBody struct {
	Feature       bool    `json:"feature"`
	Enabled       bool    `json:"enabled"`
	CredentialID  *string `json:"credential_id"`
	Bucket        string  `json:"bucket"`
	Region        string  `json:"region"`
	Prefix        string  `json:"prefix"`
	Forwarded     bool    `json:"forwarded"`
	WindowSeconds int     `json:"window_seconds"`
	Version       int64   `json:"version"`
	UpdatedAt     *string `json:"updated_at"`
}

func newConnectionLogSettingsBody(feature bool, settings connectionlog.Settings) connectionLogSettingsBody {
	body := connectionLogSettingsBody{
		Feature: feature, Enabled: settings.Enabled, Bucket: settings.Bucket, Region: settings.Region,
		Prefix: settings.Prefix, Forwarded: settings.Forwarded, WindowSeconds: settings.WindowSeconds,
		Version: settings.Version, UpdatedAt: optionalManagementTime(settings.UpdatedAt),
	}
	if settings.Credential != nil {
		id := settings.Credential.String()
		body.CredentialID = &id
	}
	return body
}

// storageCredentialRequest is a create's or a PATCH's body. A PATCH names
// the provider and account it keeps; a secret in it rotates the
// credential. The secret goes to the store, which seals it at once.
type storageCredentialRequest struct {
	Name            *string   `json:"name"`
	Provider        *string   `json:"provider"`
	AccountID       *string   `json:"account_id"`
	AccessKeyID     *string   `json:"access_key_id"`
	SecretAccessKey *string   `json:"secret_access_key"`
	Networks        *[]string `json:"network_ids"`
}

func (body storageCredentialRequest) put(create bool) (connectionlog.CredentialPut, bool) {
	if body.Name == nil || body.Provider == nil || body.Networks == nil ||
		(body.AccessKeyID == nil) != (body.SecretAccessKey == nil) || create && body.AccessKeyID == nil {
		return connectionlog.CredentialPut{}, false
	}
	put := connectionlog.CredentialPut{Name: *body.Name, Provider: *body.Provider}
	if body.AccountID != nil {
		put.AccountID = *body.AccountID
	}
	if body.AccessKeyID != nil {
		put.Secret = &flowlog.Credential{AccessKeyID: *body.AccessKeyID, SecretAccessKey: *body.SecretAccessKey}
	}
	for _, text := range *body.Networks {
		id, ok := canonicalPublicID(text)
		if !ok {
			return connectionlog.CredentialPut{}, false
		}
		put.Networks = append(put.Networks, network.ID(id))
	}
	return put, true
}

func (handler *ManagementHandler) handleConnectionLogs(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path connectionLogPath, session accountsession.Session,
) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	// Bodies carry secrets; reads change with every setting.
	response.Header().Set("Cache-Control", "no-store")
	if nilContinuationDependency(handler.connectionLogs) {
		return fail(managementError{
			Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Connection logs are temporarily unavailable", Retryable: true,
		})
	}
	manager := handler.connectionLogs
	switch path.operation {
	case storageCredentialListOperation:
		listing, err := manager.ListCredentials(ctx, session, path.workspaceID)
		if err != nil {
			return fail(classifyConnectionLogError(err))
		}
		bodies := make([]storageCredentialBody, 0, len(listing.Credentials))
		for _, credential := range listing.Credentials {
			bodies = append(bodies, newStorageCredentialBody(credential))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			Feature     bool                    `json:"feature"`
			Credentials []storageCredentialBody `json:"storage_credentials"`
		}{listing.Feature, bodies})
	case storageCredentialCreateOperation, storageCredentialUpdateOperation:
		return handler.putStorageCredential(ctx, response, request, correlationID, path, session, fail)
	case storageCredentialDeleteOperation:
		expected, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		if err := manager.DeleteCredential(ctx, connectionlog.CredentialDeletion{
			Session: session, Workspace: path.workspaceID, ID: path.credentialID, ExpectedVersion: expected,
			CorrelationID: correlationID,
		}); err != nil {
			return fail(classifyConnectionLogError(err))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			Deleted bool `json:"deleted"`
		}{true})
	case connectionLogReadOperation:
		settings, err := manager.ReadSettings(ctx, session, path.scope)
		if err != nil {
			return fail(classifyConnectionLogError(err))
		}
		response.Header().Set("ETag", trustVersionETag(settings.Settings.Version))
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK,
			newConnectionLogSettingsBody(settings.Feature, settings.Settings))
	case connectionLogReplaceOperation:
		return handler.replaceConnectionLogSettings(ctx, response, request, correlationID, path, session, fail)
	}
	return "success"
}

func (handler *ManagementHandler) putStorageCredential(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path connectionLogPath, session accountsession.Session,
	fail func(managementError) string,
) string {
	create := path.operation == storageCredentialCreateOperation
	var expected int64
	if !create {
		version, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		expected = version
	}
	var body storageCredentialRequest
	if !readDeviceGroupBody(response, request, &body) {
		return fail(*invalidManagementRequest())
	}
	put, ok := body.put(create)
	if !ok {
		return fail(*invalidManagementRequest())
	}
	put.Session, put.Workspace, put.ExpectedVersion, put.CorrelationID = session, path.workspaceID, expected, correlationID
	put.ID = path.credentialID
	if create {
		id, err := publicid.New()
		if err != nil {
			return fail(classifyConnectionLogError(connectionlog.ErrUnavailable))
		}
		put.ID = connectionlog.CredentialID(id)
	}
	if put.Check() != nil {
		return fail(*invalidManagementRequest())
	}
	credential, err := handler.connectionLogs.PutCredential(ctx, put)
	if err != nil {
		return fail(classifyConnectionLogError(err))
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	response.Header().Set("ETag", strongVersionETag(credential.Version))
	writeKubernetesData(ctx, handler, response, correlationID, status, newStorageCredentialBody(credential))
	return "success"
}

func (handler *ManagementHandler) replaceConnectionLogSettings(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path connectionLogPath, session accountsession.Session,
	fail func(managementError) string,
) string {
	expected, precondition := parseTrustIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var body struct {
		Enabled       *bool   `json:"enabled"`
		CredentialID  *string `json:"credential_id"`
		Bucket        *string `json:"bucket"`
		Region        *string `json:"region"`
		Prefix        *string `json:"prefix"`
		Forwarded     *bool   `json:"forwarded"`
		WindowSeconds *int    `json:"window_seconds"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Enabled == nil || body.Bucket == nil ||
		body.Region == nil || body.Prefix == nil || body.Forwarded == nil || body.WindowSeconds == nil {
		return fail(*invalidManagementRequest())
	}
	settings := connectionlog.Settings{
		Enabled: *body.Enabled, Bucket: *body.Bucket, Region: *body.Region, Prefix: *body.Prefix,
		Forwarded: *body.Forwarded, WindowSeconds: *body.WindowSeconds,
	}
	if body.CredentialID != nil {
		id, ok := canonicalPublicID(*body.CredentialID)
		if !ok {
			return fail(*invalidManagementRequest())
		}
		credential := connectionlog.CredentialID(id)
		settings.Credential = &credential
	}
	replacement := connectionlog.SettingsReplacement{
		Session: session, Scope: path.scope,
		ExpectedVersion: expected, Settings: settings, CorrelationID: correlationID,
	}
	if replacement.Check() != nil {
		return fail(*invalidManagementRequest())
	}
	result, err := handler.connectionLogs.ReplaceSettings(ctx, replacement)
	if err != nil {
		return fail(classifyConnectionLogError(err))
	}
	response.Header().Set("ETag", trustVersionETag(result.Settings.Version))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		connectionLogSettingsBody
		Changed bool `json:"changed"`
	}{newConnectionLogSettingsBody(result.Feature, result.Settings), result.Changed})
	return "success"
}

func classifyConnectionLogError(err error) managementError {
	switch {
	case errors.Is(err, connectionlog.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change connection logs here",
		}
	case errors.Is(err, connectionlog.ErrNotFound):
		return managementError{
			Status: http.StatusNotFound, Code: "storage_credential_not_found",
			Message: "The storage credential or Network no longer exists",
		}
	case errors.Is(err, connectionlog.ErrConflict):
		return managementError{
			Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The settings changed. Reload and review them again.",
		}
	case errors.Is(err, connectionlog.ErrInUse):
		return managementError{
			Status: http.StatusConflict, Code: "storage_credential_in_use",
			Message: "A Network sends its connection logs with this credential",
		}
	case errors.Is(err, connectionlog.ErrNotAllowed):
		return managementError{
			Status: http.StatusConflict, Code: "connection_logs_not_allowed",
			Message: "This Workspace does not have connection logs, or the credential does not allow this Network",
		}
	case errors.Is(err, connectionlog.ErrNameTaken):
		return managementError{
			Status: http.StatusConflict, Code: "storage_credential_name_taken",
			Message: "Another storage credential of this Workspace has that name",
		}
	case errors.Is(err, connectionlog.ErrLimit):
		return managementError{
			Status: http.StatusConflict, Code: "storage_credential_limit",
			Message: "This Workspace has the most storage credentials it can have. Delete one first.",
		}
	case errors.Is(err, connectionlog.ErrNotConfigured):
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "connection_logs_not_configured",
			Message: "This deployment cannot store storage credentials yet. Ask its operator.",
		}
	case errors.Is(err, connectionlog.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload before trying again.", Retryable: true,
		}
	}
}
