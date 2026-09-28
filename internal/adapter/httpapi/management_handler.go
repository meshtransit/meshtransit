package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	deviceRevokeOperation        = "device_revoke"
	policyPublishOperation       = "policy_publish"
	resourceCreateOperation      = "resource_create"
	resourceGetOperation         = "resource_get"
	resourceListOperation        = "resource_list"
	resourceGroupCreateOperation = "resource_group_create"
	resourceGroupGetOperation    = "resource_group_get"
	resourceGroupListOperation   = "resource_group_list"
	unknownManagementOperation   = "unknown"
	maximumManagementBodyBytes   = 4 * 1024
	maximumManagementRequests    = 4096
	minimumManagementTimeout     = 100 * time.Millisecond
	maximumManagementTimeout     = 30 * time.Second
)

var (
	// ErrInvalidManagementHandler reports missing dependencies or unsafe limits.
	ErrInvalidManagementHandler = errors.New("invalid management handler")
)

// AccountSessionAuthenticator authenticates one opaque Core Account Session bearer.
type AccountSessionAuthenticator interface {
	Authenticate(context.Context, accountsession.Token) (accountsession.Session, error)
}

// DeviceRevoker performs one exact-scope Device revocation command.
type DeviceRevoker interface {
	Revoke(context.Context, revocation.Command) (revocation.Result, error)
}

// PolicyPublisher atomically activates one Account-Session-bound compiled policy.
type PolicyPublisher interface {
	Publish(context.Context, policypublication.Command) (policypublication.Result, error)
}

// ResourceCreator atomically creates Resource and Resource Group authority.
type ResourceCreator interface {
	Create(context.Context, authority.Command) (authority.Result, error)
}

// ResourceCatalog reads freshly authorized Resource authority snapshots.
type ResourceCatalog interface {
	GetResource(context.Context, accountsession.Session, network.Scope, resource.ID) (catalog.Resource, error)
	ListResources(context.Context, accountsession.Session, network.Scope, resource.State, int, catalog.PageCursor) (catalog.ResourcePage, error)
	GetGroup(context.Context, accountsession.Session, network.Scope, resource.GroupID) (catalog.Group, error)
	ListGroups(context.Context, accountsession.Session, network.Scope, resource.State, int, catalog.PageCursor) (catalog.GroupPage, error)
}

// IdempotencyProver derives durable evidence without exposing the raw request key.
type IdempotencyProver interface {
	Proof(string) (idempotency.Proof, error)
}

// RateLimitSubjectDigester destroys raw source and session identities.
type RateLimitSubjectDigester interface {
	Subject(ratelimit.SubjectKind, string) (ratelimit.Subject, error)
}

// ManagementRateLimiter consumes one token from a distributed limiter.
type ManagementRateLimiter interface {
	Allow(context.Context, ratelimit.Subject, ratelimit.Policy) (ratelimit.Decision, error)
}

// PublicIDGenerator supplies server-owned correlation identities.
type PublicIDGenerator interface {
	NewID() (publicid.ID, error)
}

// ManagementHandlerOptions contains immutable management-boundary dependencies.
type ManagementHandlerOptions struct {
	Sessions              AccountSessionAuthenticator
	Revocations           DeviceRevoker
	PolicyPublications    PolicyPublisher
	ResourceCreations     ResourceCreator
	ResourceCatalog       ResourceCatalog
	Idempotency           IdempotencyProver
	RateLimitSubjects     RateLimitSubjectDigester
	RateLimiter           ManagementRateLimiter
	TrustedProxyPrefixes  []netip.Prefix
	SourceRateLimit       ratelimit.Policy
	SessionRateLimit      ratelimit.Policy
	CorrelationIDs        PublicIDGenerator
	Logger                *slog.Logger
	RequestTimeout        time.Duration
	MaxConcurrentRequests int
}

// ManagementHandler validates public management requests before application use cases.
type ManagementHandler struct {
	sessions          AccountSessionAuthenticator
	revocations       DeviceRevoker
	policies          PolicyPublisher
	resourceCreations ResourceCreator
	resourceCatalog   ResourceCatalog
	idempotency       IdempotencyProver
	rateSubjects      RateLimitSubjectDigester
	rateLimiter       ManagementRateLimiter
	clientIPs         clientIPResolver
	sourcePolicy      ratelimit.Policy
	sessionPolicy     ratelimit.Policy
	correlationIDs    PublicIDGenerator
	logger            *slog.Logger
	timeout           time.Duration
	slots             chan struct{}
	telemetry         *ManagementTelemetry
}

// NewManagementHandler constructs a bounded, fail-closed management API handler.
func NewManagementHandler(options ManagementHandlerOptions) (*ManagementHandler, error) {
	if options.Sessions == nil || options.Revocations == nil || options.PolicyPublications == nil ||
		options.Idempotency == nil ||
		options.RateLimitSubjects == nil || options.RateLimiter == nil ||
		!options.SourceRateLimit.IsValid() || !options.SessionRateLimit.IsValid() ||
		options.CorrelationIDs == nil || options.Logger == nil ||
		options.RequestTimeout < minimumManagementTimeout ||
		options.RequestTimeout > maximumManagementTimeout ||
		options.MaxConcurrentRequests <= 0 ||
		options.MaxConcurrentRequests > maximumManagementRequests {
		return nil, ErrInvalidManagementHandler
	}
	clientIPs, err := newClientIPResolver(options.TrustedProxyPrefixes)
	if err != nil {
		return nil, errors.Join(ErrInvalidManagementHandler, err)
	}
	telemetry, err := NewManagementTelemetry(options.MaxConcurrentRequests)
	if err != nil {
		return nil, errors.Join(ErrInvalidManagementHandler, err)
	}
	return &ManagementHandler{
		sessions:          options.Sessions,
		revocations:       options.Revocations,
		policies:          options.PolicyPublications,
		resourceCreations: options.ResourceCreations,
		resourceCatalog:   options.ResourceCatalog,
		idempotency:       options.Idempotency,
		rateSubjects:      options.RateLimitSubjects,
		rateLimiter:       options.RateLimiter,
		clientIPs:         clientIPs,
		sourcePolicy:      options.SourceRateLimit,
		sessionPolicy:     options.SessionRateLimit,
		correlationIDs:    options.CorrelationIDs,
		logger:            options.Logger,
		timeout:           options.RequestTimeout,
		slots:             make(chan struct{}, options.MaxConcurrentRequests),
		telemetry:         telemetry,
	}, nil
}

// ServeHTTP exposes the versioned management API without accepting browser cookies.
func (handler *ManagementHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.serveHTTP(response, request, nil)
}

// A private browser admission verifies its own transport/proof and uses these
// same resource contracts. Nil preserves the existing Bearer-only entry point.
func (handler *ManagementHandler) serveHTTP(
	response http.ResponseWriter,
	request *http.Request,
	browser *browserManagementAdmission,
) {
	if handler == nil || response == nil || request == nil || request.URL == nil ||
		handler.sessions == nil || handler.revocations == nil || handler.policies == nil ||
		handler.idempotency == nil ||
		handler.rateSubjects == nil || handler.rateLimiter == nil ||
		!handler.sourcePolicy.IsValid() || !handler.sessionPolicy.IsValid() ||
		handler.correlationIDs == nil || handler.logger == nil || handler.telemetry == nil {
		if response != nil {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		}
		return
	}
	correlationID, err := handler.correlationIDs.NewID()
	if err != nil || !correlationID.IsValid() {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	setManagementSecurityHeaders(response.Header(), correlationID)
	operation := unknownManagementOperation
	resultCode := "internal_failure"
	startedAt := time.Now()
	defer func() {
		handler.telemetry.observe(operation, resultCode, time.Since(startedAt))
		handler.logger.InfoContext(
			request.Context(),
			"management request completed",
			"operation", operation,
			"result", resultCode,
			"correlation_id", correlationID.String(),
			"duration_ms", time.Since(startedAt).Milliseconds(),
		)
	}()

	select {
	case handler.slots <- struct{}{}:
		handler.telemetry.requestOpened()
		defer func() {
			<-handler.slots
			handler.telemetry.requestClosed()
		}()
	default:
		resultCode = "capacity_unavailable"
		writeManagementError(request.Context(), handler.logger, response, correlationID, managementError{
			Status: http.StatusServiceUnavailable, Code: resultCode,
			Message: "request capacity is temporarily unavailable", Retryable: true,
		})
		return
	}

	devicePath, deviceMatched := parseDeviceRevokePath(request)
	policyPath, policyMatched := parsePolicyPublishPath(request)
	resourcePath, resourceMatched := parseResourceManagementPath(request)
	if !deviceMatched && !policyMatched && !resourceMatched {
		resultCode = "not_found"
		writeManagementError(request.Context(), handler.logger, response, correlationID, managementError{
			Status: http.StatusNotFound, Code: resultCode,
			Message: "the requested resource is unavailable",
		})
		return
	}
	if deviceMatched {
		operation = deviceRevokeOperation
	} else if policyMatched {
		operation = policyPublishOperation
	} else {
		operation = resourcePath.operation(request.Method)
	}
	allowedMethod := http.MethodPost
	if resourceMatched {
		allowedMethod = resourcePath.allowedMethod(request.Method)
	}
	if allowedMethod == "" || request.Method != allowedMethod {
		if resourceMatched && resourcePath.isCollection() {
			response.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		} else {
			response.Header().Set("Allow", allowedMethodOrGet(resourceMatched, allowedMethod))
		}
		resultCode = "method_not_allowed"
		writeManagementError(request.Context(), handler.logger, response, correlationID, managementError{
			Status: http.StatusMethodNotAllowed, Code: resultCode,
			Message: "the request method is not allowed",
		})
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	source, sourceErr := handler.clientIPs.Resolve(request)
	if sourceErr != nil {
		resultCode = "invalid_request"
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return
	}
	if limitErr := handler.enforceAdmittedRateLimit(ctx, browser, continuationBudget{
		response: response, kind: ratelimit.SubjectSource, raw: source.String(), policy: handler.sourcePolicy,
	}); limitErr != nil {
		resultCode = limitErr.Code
		writeManagementError(ctx, handler.logger, response, correlationID, *limitErr)
		return
	}
	var session accountsession.Session
	var authenticationErr error
	if browser == nil {
		session, authenticationErr = handler.authenticate(ctx, request)
	} else {
		session, authenticationErr = browser.authenticate(ctx, request)
	}
	if authenticationErr != nil {
		classified := classifyAuthenticationError(authenticationErr)
		resultCode = classified.Code
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return
	}
	if limitErr := handler.enforceAdmittedRateLimit(ctx, browser, continuationBudget{
		response: response, kind: ratelimit.SubjectAccountSession, raw: session.ID().String(), policy: handler.sessionPolicy,
	}); limitErr != nil {
		resultCode = limitErr.Code
		writeManagementError(ctx, handler.logger, response, correlationID, *limitErr)
		return
	}
	if policyMatched {
		resultCode = handler.publishPolicy(ctx, managementPolicyRequest{
			response: response, request: request, correlationID: correlationID,
			path: policyPath, session: session, browser: browser,
		})
		return
	}
	if resourceMatched {
		if browser != nil {
			resultCode = "not_found"
			writeManagementError(ctx, handler.logger, response, correlationID, managementError{
				Status: http.StatusNotFound, Code: resultCode,
				Message: "the requested resource is unavailable",
			})
			return
		}
		resultCode = handler.handleResourceManagement(
			ctx, response, request, correlationID, resourcePath, session,
		)
		return
	}
	command, commandErr := handler.decodeDeviceRevokeCommand(response, request, devicePath, session)
	if commandErr != nil {
		resultCode = commandErr.Code
		writeManagementError(ctx, handler.logger, response, correlationID, *commandErr)
		return
	}
	if err := browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		resultCode = classified.Code
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return
	}
	result, revokeErr := handler.revocations.Revoke(ctx, command)
	if revokeErr != nil {
		classified := classifyRevocationError(revokeErr)
		resultCode = classified.Code
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return
	}
	if !resultMatchesManagementCommand(result, command) {
		resultCode = "internal_failure"
		writeManagementError(ctx, handler.logger, response, correlationID, managementError{
			Status: http.StatusInternalServerError, Code: resultCode,
			Message: "the request could not be completed",
		})
		return
	}

	resultCode = "success"
	response.Header().Set("ETag", strongVersionETag(result.DeviceVersion()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, revokeDeviceResponse{
		Data: revokedDevice{
			DeviceID:          result.NodeID().String(),
			State:             "revoked",
			DeviceVersion:     result.DeviceVersion(),
			SessionGeneration: result.SessionGeneration(),
			NetworkRevision:   result.NetworkRevision(),
			InventoryRevision: result.InventoryRevision(),
		},
		CorrelationID: correlationID.String(),
	})
}

func (handler *ManagementHandler) enforceAdmittedRateLimit(
	ctx context.Context,
	admission *browserManagementAdmission,
	budget continuationBudget,
) *managementError {
	if admission == nil {
		return handler.enforceRateLimit(
			ctx,
			budget.response,
			budget.kind,
			budget.raw,
			budget.policy,
		)
	}
	if err := admission.browser.budget(ctx, budget); err != nil {
		if errors.Is(err, ErrBrowserManagementLimited) {
			return &managementError{Status: http.StatusTooManyRequests, Code: "rate_limited",
				Message: "too many requests", Retryable: true}
		}
		return &managementError{Status: http.StatusServiceUnavailable, Code: "rate_limit_unavailable",
			Message: "request admission is temporarily unavailable", Retryable: true}
	}
	return nil
}

func (handler *ManagementHandler) enforceRateLimit(
	ctx context.Context,
	response http.ResponseWriter,
	kind ratelimit.SubjectKind,
	rawSubject string,
	policy ratelimit.Policy,
) *managementError {
	subject, err := handler.rateSubjects.Subject(kind, rawSubject)
	if err != nil {
		return &managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
	}
	decision, err := handler.rateLimiter.Allow(ctx, subject, policy)
	if err != nil || !decision.IsValid() {
		return &managementError{
			Status: http.StatusServiceUnavailable, Code: "rate_limit_unavailable",
			Message: "request admission is temporarily unavailable", Retryable: true,
		}
	}
	setRateLimitHeaders(response.Header(), decision)
	if decision.Allowed() {
		return nil
	}
	return &managementError{
		Status: http.StatusTooManyRequests, Code: "rate_limited",
		Message: "too many requests", Retryable: true,
	}
}

func setRateLimitHeaders(header http.Header, decision ratelimit.Decision) {
	header.Set("RateLimit-Limit", strconv.FormatInt(decision.Limit(), 10))
	header.Set("RateLimit-Remaining", strconv.FormatInt(decision.Remaining(), 10))
	if decision.RetryAfter() <= 0 {
		header.Del("RateLimit-Reset")
		return
	}
	retrySeconds := int64(math.Ceil(decision.RetryAfter().Seconds()))
	header.Set("RateLimit-Reset", strconv.FormatInt(retrySeconds, 10))
	header.Set("Retry-After", strconv.FormatInt(retrySeconds, 10))
}

func (handler *ManagementHandler) authenticate(
	ctx context.Context,
	request *http.Request,
) (accountsession.Session, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") ||
		len(values[0]) <= len("Bearer ") || strings.TrimSpace(values[0]) != values[0] {
		return accountsession.Session{}, accountsession.ErrUnauthenticated
	}
	token, err := accountsession.ParseToken(strings.TrimPrefix(values[0], "Bearer "))
	if err != nil {
		return accountsession.Session{}, accountsession.ErrUnauthenticated
	}
	return handler.sessions.Authenticate(ctx, token)
}

func (handler *ManagementHandler) decodeDeviceRevokeCommand(
	response http.ResponseWriter,
	request *http.Request,
	path deviceRevokePath,
	session accountsession.Session,
) (revocation.Command, *managementError) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	deviceID, err := node.ParseID(path.deviceID)
	if err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	expectedVersion, preconditionErr := parseIfMatch(request.Header.Values("If-Match"))
	if preconditionErr != nil {
		return revocation.Command{}, preconditionErr
	}
	rawIdempotencyKey := singleHeader(request.Header, "Idempotency-Key")
	if rawIdempotencyKey == "" {
		return revocation.Command{}, invalidManagementRequest()
	}
	proof, err := handler.idempotency.Proof(rawIdempotencyKey)
	if err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return revocation.Command{}, invalidManagementRequest()
	}
	var body revokeDeviceRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumManagementBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	reason, err := revocation.NewReason(body.Reason)
	if err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope: scope, NodeID: deviceID, ExpectedVersion: expectedVersion,
		AccountSession: session, Reason: reason, IdempotencyEvidence: proof,
	})
	if err != nil {
		return revocation.Command{}, invalidManagementRequest()
	}
	return command, nil
}

type deviceRevokePath struct {
	workspaceID string
	networkID   string
	deviceID    string
}

func parseDeviceRevokePath(request *http.Request) (deviceRevokePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return deviceRevokePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 10 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" ||
		segments[6] != "devices" || segments[8] != "actions" || segments[9] != "revoke" {
		return deviceRevokePath{}, false
	}
	return deviceRevokePath{
		workspaceID: segments[3], networkID: segments[5], deviceID: segments[7],
	}, true
}

func parseIfMatch(values []string) (int64, *managementError) {
	if len(values) == 0 {
		return 0, &managementError{
			Status: http.StatusPreconditionRequired, Code: "precondition_required",
			Message: "a strong version precondition is required",
		}
	}
	if len(values) != 1 || len(values[0]) < 3 || values[0][0] != '"' ||
		values[0][len(values[0])-1] != '"' {
		return 0, invalidManagementRequest()
	}
	value := values[0][1 : len(values[0])-1]
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version <= 0 || version == math.MaxInt64 ||
		values[0] != strongVersionETag(version) {
		return 0, invalidManagementRequest()
	}
	return version, nil
}

func strongVersionETag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

func singleHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func validJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, parameter := range parameters {
		if name != "charset" || !strings.EqualFold(parameter, "utf-8") {
			return false
		}
	}
	return true
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("management request contains trailing data")
	}
	return nil
}

func resultMatchesManagementCommand(result revocation.Result, command revocation.Command) bool {
	return result.IsValid() && result.Scope() == command.Scope() &&
		result.NodeID() == command.NodeID() &&
		result.DeviceVersion() == command.ExpectedVersion()+1
}

func invalidManagementRequest() *managementError {
	return &managementError{
		Status: http.StatusBadRequest, Code: "invalid_request",
		Message: "the request is invalid",
	}
}

// PublicCorrelationIDGenerator creates UUIDv7 correlation identities using OS entropy.
type PublicCorrelationIDGenerator struct{}

// NewID returns one server-owned correlation identity.
func (PublicCorrelationIDGenerator) NewID() (publicid.ID, error) {
	id, err := publicid.New()
	if err != nil {
		return publicid.ID{}, fmt.Errorf("generate management correlation id: %w", err)
	}
	return id, nil
}
