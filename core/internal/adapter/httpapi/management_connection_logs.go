package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

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
	// Destination is a push credential's fields (schema 272); never its CA.
	Destination *destinationBody `json:"destination,omitempty"`
}

type destinationBody struct {
	URL       string `json:"url,omitempty"`
	Flavor    string `json:"flavor,omitempty"`
	CASHA256  string `json:"ca_sha256,omitempty"`
	Site      string `json:"site,omitempty"`
	Region    string `json:"region,omitempty"`
	StreamARN string `json:"stream_arn,omitempty"`
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
	if destination := credential.Destination; !destination.Empty() {
		body.Destination = &destinationBody{
			URL: destination.URL, Flavor: destination.Flavor, CASHA256: destination.CASHA256, Site: destination.Site,
			Region: destination.Region, StreamARN: destination.StreamARN,
		}
	}
	return body
}

// connectionLogStatusBody is what the Console shows of a Network's logging
// (design §16i C92): never a receiver instance, fingerprint or version.
type connectionLogStatusBody struct {
	ReceiverAvailable bool    `json:"receiver_available"`
	Report            string  `json:"report"`
	ReportedAt        *string `json:"reported_at"`
	Test              string  `json:"test"`
	TestedAt          *string `json:"tested_at"`
	DeliveredAt       *string `json:"delivered_at"`
	DeliveryError     *string `json:"delivery_error"`
	// ReceiverWritesType is false while a receiver cannot write to the
	// destination's type: nothing is logged until it can (schema 273).
	ReceiverWritesType bool  `json:"receiver_writes_type"`
	Rejected24h        int64 `json:"rejected_24h"`
}

func newConnectionLogStatusBody(view connectionlog.StatusView) connectionLogStatusBody {
	moment := func(at *time.Time) *string {
		if at == nil {
			return nil
		}
		return optionalManagementTime(*at)
	}
	body := connectionLogStatusBody{
		ReceiverAvailable: view.ReceiverAvailable, Report: view.Report, ReportedAt: moment(view.ReportedAt),
		Test: view.Test, TestedAt: moment(view.TestedAt), DeliveredAt: moment(view.DeliveredAt),
		ReceiverWritesType: view.ReceiverWritesType, Rejected24h: view.Rejected24h,
	}
	if view.DeliveryError != "" {
		kind := view.DeliveryError
		body.DeliveryError = &kind
	}
	return body
}

type connectionLogSettingsBody struct {
	Feature       bool     `json:"feature"`
	Enabled       bool     `json:"enabled"`
	CredentialID  *string  `json:"credential_id"`
	Bucket        string   `json:"bucket"`
	Region        string   `json:"region"`
	Prefix        string   `json:"prefix"`
	Forwarded     bool     `json:"forwarded"`
	WindowSeconds int      `json:"window_seconds"`
	BucketOwner   *string  `json:"expected_bucket_owner"`
	Target        *string  `json:"target"`
	TargetKind    *string  `json:"target_kind"`
	Service       *string  `json:"service"`
	Tags          []string `json:"tags"`
	RecordFormat  *string  `json:"record_format"`
	Version       int64    `json:"version"`
	UpdatedAt     *string  `json:"updated_at"`
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
	if settings.ExpectedBucketOwner != "" {
		owner := settings.ExpectedBucketOwner
		body.BucketOwner = &owner
	}
	for _, field := range []struct {
		from string
		to   **string
	}{
		{settings.Target, &body.Target}, {settings.TargetKind, &body.TargetKind}, {settings.Service, &body.Service},
		{settings.RecordFormat, &body.RecordFormat},
	} {
		if field.from != "" {
			value := field.from
			*field.to = &value
		}
	}
	if len(settings.Tags) > 0 {
		body.Tags = append([]string(nil), settings.Tags...)
	}
	return body
}

// storageCredentialRequest is a create's or a PATCH's body. A PATCH names
// the provider and account it keeps; a secret in it rotates the
// credential. The secret goes to the store, which seals it at once. S3 and
// R2 take access_key_id and secret_access_key; a push destination takes
// secret and destination, together (the destination is bound into the
// secret, push destinations design §5 S1).
type storageCredentialRequest struct {
	Name            *string             `json:"name"`
	Provider        *string             `json:"provider"`
	AccountID       *string             `json:"account_id"`
	AccessKeyID     *string             `json:"access_key_id"`
	SecretAccessKey *string             `json:"secret_access_key"`
	Secret          *pushSecretRequest  `json:"secret"`
	Destination     *destinationRequest `json:"destination"`
	Networks        *[]string           `json:"network_ids"`
}

// pushSecretRequest is a push destination's secret: kind api_key (id,
// key), basic (id = user name, key = password), datadog_key (key) or
// aws_keys (id = access key ID, key = secret access key).
type pushSecretRequest struct {
	Kind *string `json:"kind"`
	ID   *string `json:"id"`
	Key  *string `json:"key"`
}

// destinationRequest is a push destination: url, flavor and optional
// ca_pem (Elasticsearch/OpenSearch), site (Datadog) or stream_arn
// (Kinesis, whose region is the ARN's).
type destinationRequest struct {
	URL       *string `json:"url"`
	Flavor    *string `json:"flavor"`
	CAPEM     *string `json:"ca_pem"`
	Site      *string `json:"site"`
	StreamARN *string `json:"stream_arn"`
}

var pushSecretKinds = map[string]flowlog.SecretKind{
	"api_key": flowlog.SecretAPIKey, "basic": flowlog.SecretBasic, "datadog_key": flowlog.SecretDatadogKey,
	"aws_keys": flowlog.SecretAWSKeys,
}

// push builds the secret and destination, false for a malformed one.
func (body storageCredentialRequest) push() (*flowlog.Secret, connectionlog.Destination, bool) {
	if (body.Secret == nil) != (body.Destination == nil) {
		return nil, connectionlog.Destination{}, false
	}
	if body.Secret == nil {
		return nil, connectionlog.Destination{}, true
	}
	kind, known := pushSecretKinds[deref(body.Secret.Kind)]
	if !known || body.Secret.Key == nil {
		return nil, connectionlog.Destination{}, false
	}
	secret := &flowlog.Secret{Kind: kind, ID: deref(body.Secret.ID), Key: *body.Secret.Key}
	if kind == flowlog.SecretDatadogKey {
		// Datadog keys are lower-case hex; a pasted upper-case one is the same key.
		secret.Key = strings.ToLower(secret.Key)
	}
	destination := connectionlog.Destination{
		Flavor: deref(body.Destination.Flavor), CAPEM: []byte(deref(body.Destination.CAPEM)),
		Site: deref(body.Destination.Site), StreamARN: deref(body.Destination.StreamARN),
	}
	if len(destination.CAPEM) == 0 {
		destination.CAPEM = nil
	}
	if body.Destination.URL != nil {
		canonical, err := flowlog.CanonicalURL(*body.Destination.URL)
		if err != nil {
			return nil, connectionlog.Destination{}, false
		}
		destination.URL = canonical
	}
	if destination.StreamARN != "" {
		region, ok := flowlog.ParseStreamARN(destination.StreamARN)
		if !ok {
			return nil, connectionlog.Destination{}, false
		}
		destination.Region = region
	}
	return secret, destination, true
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (body storageCredentialRequest) put(create bool) (connectionlog.CredentialPut, bool) {
	if body.Name == nil || body.Provider == nil || body.Networks == nil ||
		(body.AccessKeyID == nil) != (body.SecretAccessKey == nil) ||
		create && body.AccessKeyID == nil && body.Secret == nil || body.AccessKeyID != nil && body.Secret != nil {
		return connectionlog.CredentialPut{}, false
	}
	put := connectionlog.CredentialPut{Name: *body.Name, Provider: *body.Provider}
	secret, destination, ok := body.push()
	if !ok {
		return connectionlog.CredentialPut{}, false
	}
	put.PushSecret, put.Destination = secret, destination
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
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			connectionLogSettingsBody
			Status connectionLogStatusBody `json:"status"`
		}{
			newConnectionLogSettingsBody(settings.Feature, settings.Settings),
			newConnectionLogStatusBody(settings.Status.View(settings.Settings, time.Now())),
		})
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
	var body connectionLogSettingsRequest
	if !readDeviceGroupBody(response, request, &body) {
		return fail(*invalidManagementRequest())
	}
	settings, ok := body.settings()
	if !ok {
		return fail(*invalidManagementRequest())
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

// connectionLogSettingsRequest is a PUT of a Network's connection log
// settings: every field but credential_id and expected_bucket_owner is
// required.
type connectionLogSettingsRequest struct {
	Enabled       *bool   `json:"enabled"`
	CredentialID  *string `json:"credential_id"`
	Bucket        *string `json:"bucket"`
	Region        *string `json:"region"`
	Prefix        *string `json:"prefix"`
	Forwarded     *bool   `json:"forwarded"`
	WindowSeconds *int    `json:"window_seconds"`
	// Absent or null: the credential's own account; empty is refused.
	BucketOwner *string `json:"expected_bucket_owner"`
	// A push destination's fields (schema 272); absent or null for none,
	// empty refused.
	Target       *string  `json:"target"`
	TargetKind   *string  `json:"target_kind"`
	Service      *string  `json:"service"`
	Tags         []string `json:"tags"`
	RecordFormat *string  `json:"record_format"`
}

// settings builds the replacement's settings, false for a missing field,
// an empty bucket owner or a non-canonical credential ID.
func (body connectionLogSettingsRequest) settings() (connectionlog.Settings, bool) {
	if body.Enabled == nil || body.Bucket == nil || body.Region == nil || body.Prefix == nil || body.Forwarded == nil ||
		body.WindowSeconds == nil {
		return connectionlog.Settings{}, false
	}
	settings := connectionlog.Settings{
		Enabled: *body.Enabled, Bucket: *body.Bucket, Region: *body.Region, Prefix: *body.Prefix,
		Forwarded: *body.Forwarded, WindowSeconds: *body.WindowSeconds,
	}
	if body.BucketOwner != nil {
		if *body.BucketOwner == "" {
			return connectionlog.Settings{}, false
		}
		settings.ExpectedBucketOwner = *body.BucketOwner
	}
	if body.CredentialID != nil {
		id, ok := canonicalPublicID(*body.CredentialID)
		if !ok {
			return connectionlog.Settings{}, false
		}
		credential := connectionlog.CredentialID(id)
		settings.Credential = &credential
	}
	for _, field := range []struct {
		from *string
		to   *string
	}{
		{body.Target, &settings.Target}, {body.TargetKind, &settings.TargetKind}, {body.Service, &settings.Service},
		{body.RecordFormat, &settings.RecordFormat},
	} {
		if field.from != nil {
			if *field.from == "" {
				return connectionlog.Settings{}, false
			}
			*field.to = *field.from
		}
	}
	if len(body.Tags) > 0 {
		settings.Tags = append([]string(nil), body.Tags...)
	}
	return settings, true
}
