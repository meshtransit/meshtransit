package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
)

const (
	// AccountSessionCSRFPreparePath is fixed private same-origin proof preparation.
	AccountSessionCSRFPreparePath = "/auth/v1/session/prepare"
	// AccountSessionLogoutPath is fixed private same-origin durable logout.
	AccountSessionLogoutPath = "/auth/v1/session/logout"
	// AccountSessionManagementScopesPath is the fixed private management-scope projection.
	AccountSessionManagementScopesPath = "/auth/v1/session/management-scopes"
	// DeploymentCapabilitiesPath is the fixed authenticated Deployment projection.
	DeploymentCapabilitiesPath = "/v1/system/capabilities"
)

var (
	// ErrInvalidBrowserManagement conceals invalid profile/input, never authority.
	ErrInvalidBrowserManagement = errors.New("http api: invalid browser management")
	// ErrBrowserManagementUnavailable conceals budget/authority/time failure.
	ErrBrowserManagementUnavailable = errors.New("http api: browser management unavailable")
	// ErrBrowserManagementLimited means a shared prepare budget denied input.
	ErrBrowserManagementLimited = errors.New("http api: browser management limited")
	// ErrBrowserManagementSaturated means local ownership rejected without queueing.
	ErrBrowserManagementSaturated = errors.New("http api: browser management saturated")
	// ErrBrowserManagementDelivery is uncertain submission, never non-commit proof.
	ErrBrowserManagementDelivery = errors.New("http api: browser management delivery failed")
)

// BrowserManagementOptions supplies a private profile, not environment configuration.
// Management's durable ports must use this clock and confirmed transaction contracts.
type BrowserManagementOptions struct {
	Management    *ManagementHandler
	Logout        AccountSessionLogout
	Scopes        SessionManagementScopes
	Inventory     SessionDeviceInventory
	Capabilities  SessionDeploymentCapabilities
	DeploymentID  deployment.ID
	Origin        string
	Key           BrowserLoginKey
	Clock         accountsession.Clock
	ProofLifetime time.Duration
}

// BrowserManagement owns cookie-only intent transport around the same resource API.
// It never enables a listener, synthesizes Authorization or stores a caller Session.
type BrowserManagement struct {
	management   *ManagementHandler
	logout       AccountSessionLogout
	scopes       SessionManagementScopes
	inventory    SessionDeviceInventory
	capabilities SessionDeploymentCapabilities
	deploymentID deployment.ID
	origin, host string
	keyID        string
	key          [32]byte
	clock        accountsession.Clock
	lifetime     time.Duration
	entropy      io.Reader
	telemetry    *BrowserManagementTelemetry
	// Handle owns tokens through real submission. Never close or queue on slots.
	slots chan struct{}
}

// AccountSessionLogout ends the exact opaque cookie authority without exposing it.
type AccountSessionLogout interface {
	Logout(context.Context, accountsession.Token) (bool, error)
}

// SessionManagementScopes reads one fresh server-authoritative Console projection.
type SessionManagementScopes interface {
	List(context.Context, accountsession.Session, int, network.ID) (sessioncontext.Page, error)
}

// NewBrowserManagement validates all resident input before any port/entropy effect.
// Its isolated collector requires explicit private root registration later.
func NewBrowserManagement(options BrowserManagementOptions) (*BrowserManagement, error) {
	handler := options.Management
	validAuthorityProfile := validBrowserManagementHandler(handler) && options.DeploymentID.IsValid() &&
		!nilContinuationDependency(options.Logout) && !nilContinuationDependency(options.Scopes) &&
		!nilContinuationDependency(options.Capabilities)
	if !validAuthorityProfile || nilContinuationDependency(options.Clock) {
		return nil, ErrInvalidBrowserManagement
	}
	if len(options.Origin) == 0 || len(options.Origin) > 256 {
		return nil, ErrInvalidBrowserManagement
	}
	origin, err := url.Parse(options.Origin)
	if err != nil || origin == nil {
		return nil, ErrInvalidBrowserManagement
	}
	invalidOrigin := origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Opaque != ""
	invalidOriginTarget := origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || origin.RawFragment != ""
	invalidOriginShape := invalidOrigin || invalidOriginTarget
	if invalidOriginShape || "https://"+origin.Host != options.Origin || !canonicalBrowserManagementHost(origin) {
		return nil, ErrInvalidBrowserManagement
	}
	var zero [32]byte
	if !validBrowserManagementKeyID(options.Key.ID) || len(options.Key.Material) != len(zero) {
		return nil, ErrInvalidBrowserManagement
	}
	if subtle.ConstantTimeCompare(options.Key.Material, zero[:]) == 1 {
		return nil, ErrInvalidBrowserManagement
	}
	validLifetime := options.ProofLifetime >= 30*time.Second && options.ProofLifetime <= 120*time.Second &&
		options.ProofLifetime%time.Second == 0
	if !validLifetime {
		return nil, ErrInvalidBrowserManagement
	}
	browser := &BrowserManagement{management: handler, logout: options.Logout, scopes: options.Scopes, inventory: options.Inventory,
		capabilities: options.Capabilities,
		deploymentID: options.DeploymentID,
		origin:       options.Origin, host: origin.Host, keyID: options.Key.ID, clock: options.Clock,
		lifetime: options.ProofLifetime, entropy: rand.Reader, telemetry: NewBrowserManagementTelemetry(),
		slots: make(chan struct{}, cap(handler.slots))}
	copy(browser.key[:], options.Key.Material)
	return browser, nil
}

// validBrowserManagementOwner rechecks the sealed owner before it is joined to
// another browser graph. It performs no authentication, budget or clock effect.
func validBrowserManagementOwner(browser *BrowserManagement) bool {
	if browser == nil || !validBrowserManagementHandler(browser.management) ||
		nilContinuationDependency(browser.logout) ||
		nilContinuationDependency(browser.scopes) ||
		nilContinuationDependency(browser.capabilities) ||
		nilContinuationDependency(browser.clock) || browser.slots == nil {
		return false
	}
	validCapacity := cap(browser.slots) >= 1 && cap(browser.slots) <= 128
	validLifetime := browser.lifetime >= 30*time.Second && browser.lifetime <= 120*time.Second &&
		browser.lifetime%time.Second == 0
	var zero [32]byte
	validKey := validBrowserManagementKeyID(browser.keyID) &&
		subtle.ConstantTimeCompare(browser.key[:], zero[:]) != 1
	return browser.deploymentID.IsValid() && browser.origin != "" && browser.host != "" &&
		validCapacity && validLifetime && validKey
}

func canonicalBrowserManagementHost(origin *url.URL) bool {
	if origin.Host != strings.ToLower(origin.Host) || strings.ContainsAny(origin.Host, "\\ \t\r\n%") {
		return false
	}
	if port := origin.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port || value == 443 {
			return false
		}
	} else if strings.HasSuffix(origin.Host, ":") {
		return false
	}
	host := origin.Hostname()
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == host
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			letter := character >= 'a' && character <= 'z'
			digit := character >= '0' && character <= '9'
			validCharacter := letter || digit || character == '-'
			if !validCharacter {
				return false
			}
		}
	}
	return true
}

func validBrowserManagementHandler(handler *ManagementHandler) bool {
	if handler == nil || handler.logger == nil || handler.telemetry == nil {
		return false
	}
	for _, port := range []any{handler.sessions, handler.revocations, handler.policies, handler.idempotency,
		handler.rateSubjects, handler.rateLimiter, handler.correlationIDs} {
		if nilContinuationDependency(port) {
			return false
		}
	}
	validTimeout := handler.timeout >= minimumManagementTimeout && handler.timeout <= maximumManagementTimeout
	validCapacity := cap(handler.slots) >= 1 && cap(handler.slots) <= 128
	return validTimeout && validCapacity && handler.sourcePolicy.IsValid() && handler.sessionPolicy.IsValid() &&
		validBrowserProxies(handler.clientIPs.trustedProxyPrefixes)
}

func validBrowserManagementKeyID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, character := range id {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

// Handle owns fixed proof preparation or an existing protected management operation.
// Pre-release errors leave response untouched. No retry, rewrite or commit inference.
func (browser *BrowserManagement) Handle(response http.ResponseWriter, request *http.Request) (resultErr error) {
	if browser == nil || browser.slots == nil || request == nil || nilContinuationDependency(response) {
		return ErrBrowserManagementUnavailable
	}
	operation := "unknown"
	started := time.Now()
	browser.telemetry.opened()
	defer func() { browser.telemetry.closed(operation, resultErr, time.Since(started)) }()
	if response.Header() == nil || !pristineBrowserManagementResponse(response.Header()) ||
		!browser.validRequest(request) {
		return ErrInvalidBrowserManagement
	}
	prepare := request.URL.Path == AccountSessionCSRFPreparePath
	logout := request.URL.Path == AccountSessionLogoutPath
	managementScopes := request.URL.Path == AccountSessionManagementScopesPath && request.Method == http.MethodGet
	inventoryScope, inventoryMatched := parseDeviceInventoryPath(request)
	inventoryRead := inventoryMatched && !nilContinuationDependency(browser.inventory)
	deploymentCapabilities := request.URL.Path == DeploymentCapabilitiesPath && request.Method == http.MethodGet
	_, device := parseDeviceRevokePath(request)
	_, policy := parsePolicyPublishPath(request)
	_, simulation := parsePolicySimulationPath(request)
	_, policyRead := parseActivePolicyPath(request)
	approvalPath, approvalMatched := parsePolicyApprovalPath(request)
	approval := approvalMatched && approvalPath.allowedMethod(request.Method) == request.Method
	_, accessGraph := parseAccessGraphExplainPath(request)
	_, workspaceRename := parseWorkspaceRenamePath(request)
	workspaceRoles := isWorkspaceRoleOperation(request) ||
		isWorkspaceCollectionPath(request) && request.Method == http.MethodPost ||
		isNetworkCollectionPost(request) || isSessionWorkspaceOperation(request)
	resourceSharing, _ := browserResourceSharingOperation(request)
	if !prepare && !logout && !managementScopes && !inventoryRead && !deploymentCapabilities && !device && !policy && !simulation &&
		!approval && !accessGraph && !policyRead && !workspaceRename && !workspaceRoles && !resourceSharing {
		return ErrInvalidBrowserManagement
	}
	operation = "mutation"
	if prepare {
		operation = "prepare"
	} else if logout {
		operation = "logout"
	} else if request.Method == http.MethodGet {
		operation = "read"
	}
	ctx, cancel := context.WithTimeout(request.Context(), browser.management.timeout)
	defer cancel()
	if ctx.Err() != nil {
		return ErrBrowserManagementUnavailable
	}
	if deploymentCapabilities {
		ctx = accountsession.WithActivity(ctx)
	}
	select {
	case browser.slots <- struct{}{}:
		defer func() { <-browser.slots }()
	default:
		return ErrBrowserManagementSaturated
	}
	deadline, ok := ctx.Deadline()
	controller := http.NewResponseController(response)
	if !ok {
		return ErrBrowserManagementUnavailable
	}
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		return ErrBrowserManagementUnavailable
	}
	request = request.WithContext(ctx)
	candidate := &browserManagementResponse{header: response.Header().Clone()}
	admission := &browserManagementAdmission{browser: browser, requiresProof: request.Method != http.MethodGet}
	if prepare {
		if err := browser.prepare(ctx, candidate, request, admission); err != nil {
			return err
		}
	} else if logout {
		if err := browser.endSession(ctx, candidate, request, admission); err != nil {
			return err
		}
	} else if managementScopes {
		if err := browser.readManagementScopes(ctx, candidate, request, admission); err != nil {
			return err
		}
	} else if inventoryRead {
		if err := browser.readDeviceInventory(ctx, candidate, request, admission, inventoryScope); err != nil {
			return err
		}
	} else if deploymentCapabilities {
		if err := browser.readDeploymentCapabilities(ctx, candidate, request, admission); err != nil {
			return err
		}
	} else {
		browser.management.serveHTTP(candidate, request, admission)
	}
	logoutCompleted := logout && candidate.status == http.StatusNoContent
	invalidCandidateBody := logoutCompleted && len(candidate.body) != 0 || !logoutCompleted && len(candidate.body) == 0
	if candidate.err != nil || candidate.statusWrites != 1 || invalidCandidateBody {
		return ErrBrowserManagementUnavailable
	}
	// A cookie-only profile never invites a Bearer credential fallback.
	candidate.header.Del("WWW-Authenticate")
	// Private fetch responses return created identifiers in the JSON body and
	// never emit navigation authority, even when the Bearer contract has a
	// same-origin Location header.
	candidate.header.Del("Location")
	validCandidateHeader := pristineBrowserManagementResponse(candidate.header)
	if logoutCompleted {
		validCandidateHeader = validBrowserLogoutResponse(candidate.header)
	}
	if !validCandidateHeader || !boundedLoginHeaders(candidate.header) {
		return ErrInvalidBrowserManagement
	}
	if err := admission.validate(ctx); err != nil {
		return ErrBrowserManagementUnavailable
	}
	if ctx.Err() != nil {
		return ErrBrowserManagementUnavailable
	}
	candidate.header.Set("Content-Length", strconv.Itoa(len(candidate.body)))
	if !boundedLoginHeaders(candidate.header) {
		return ErrInvalidBrowserManagement
	}
	minimumRemaining := time.Duration(0)
	if prepare {
		minimumRemaining = time.Second
	}
	if err := admission.validateFresh(ctx, minimumRemaining); err != nil || ctx.Err() != nil {
		return ErrBrowserManagementUnavailable
	}
	header := response.Header()
	clear(header)
	for name, values := range candidate.header {
		header[name] = values
	}
	response.WriteHeader(candidate.status)
	if len(candidate.body) == 0 {
		return nil
	}
	written, err := response.Write(candidate.body)
	if err != nil || written != len(candidate.body) {
		return ErrBrowserManagementDelivery
	}
	return nil
}

func (browser *BrowserManagement) endSession(
	ctx context.Context,
	response *browserManagementResponse,
	request *http.Request,
	admission *browserManagementAdmission,
) error {
	correlationID, err := browser.management.correlationIDs.NewID()
	if err != nil || !correlationID.IsValid() {
		return ErrBrowserManagementUnavailable
	}
	setManagementSecurityHeaders(response.header, correlationID)
	address, err := browser.management.clientIPs.Resolve(request)
	if err != nil {
		return ErrInvalidBrowserManagement
	}
	if err := browser.budget(ctx, continuationBudget{response: response, kind: ratelimit.SubjectSource,
		raw:    "browser-session-logout-source/v1\x00" + browser.deploymentID.String() + "\x00" + address.String(),
		policy: browser.management.sourcePolicy}); err != nil {
		return err
	}
	if !validLoginBody(response, request) {
		return ErrInvalidBrowserManagement
	}
	session, authenticationErr := admission.authenticate(ctx, request)
	if authenticationErr != nil {
		writeManagementError(
			ctx,
			browser.management.logger,
			response,
			correlationID,
			classifyAuthenticationError(authenticationErr),
		)
		return nil
	}
	if err := browser.budget(ctx, continuationBudget{response: response, kind: ratelimit.SubjectAccountSession,
		raw:    "browser-session-logout-session/v1\x00" + browser.deploymentID.String() + "\x00" + session.ID().String(),
		policy: browser.management.sessionPolicy}); err != nil {
		return err
	}
	if err := admission.validateFresh(ctx, time.Second); err != nil {
		return ErrBrowserManagementUnavailable
	}
	if _, err := browser.logout.Logout(ctx, admission.token); err != nil || ctx.Err() != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, managementError{
			Status: http.StatusServiceUnavailable, Code: "logout_unavailable",
			Message: "logout is temporarily unavailable", Retryable: true,
		})
		return nil
	}
	cookie, err := expiredAccountSessionCookie()
	if err != nil {
		return ErrBrowserManagementUnavailable
	}
	response.header.Add("Set-Cookie", cookie.String())
	response.WriteHeader(http.StatusNoContent)
	return nil
}

func (browser *BrowserManagement) validRequest(request *http.Request) bool {
	target, transport := request.URL, request.TLS
	validTransport := transport != nil && transport.HandshakeComplete && transport.Version >= tls.VersionTLS12
	if target == nil || !validTransport || request.Host != browser.host ||
		(request.Method != http.MethodGet && request.Method != http.MethodPost) {
		return false
	}
	if len(target.Path) > 512 || !canonicalCallbackPath(target.Path) || !boundedLoginHeaders(request.Header) {
		return false
	}
	if target.RawPath != "" || target.Scheme != "" || target.Host != "" || target.User != nil || target.Opaque != "" {
		return false
	}
	if target.ForceQuery || target.Fragment != "" || target.RawFragment != "" ||
		request.RequestURI != target.RequestURI() {
		return false
	}
	approvalPath, approvalMatched := parsePolicyApprovalPath(request)
	approvalRead := approvalMatched && request.Method == http.MethodGet &&
		(approvalPath.kind == policyApprovalPathCollection || approvalPath.kind == policyApprovalPathItem)
	managementScopeRead := request.Method == http.MethodGet && target.Path == AccountSessionManagementScopesPath
	_, inventoryMatched := parseDeviceInventoryPath(request)
	inventoryRead := inventoryMatched && !nilContinuationDependency(browser.inventory)
	deploymentCapabilityRead := request.Method == http.MethodGet && target.Path == DeploymentCapabilitiesPath
	_, policyMatched := parseActivePolicyPath(request)
	policyRead := policyMatched && request.Method == http.MethodGet
	resourceSharing, resourceSharingCollectionRead := browserResourceSharingOperation(request)
	resourceSharingRead := resourceSharing && request.Method == http.MethodGet
	// Member directory and switchable Workspaces are exact, query-free reads.
	directoryRead := request.Method == http.MethodGet &&
		(isWorkspaceRoleOperation(request) || isSessionWorkspaceOperation(request))
	safeRead := approvalRead || managementScopeRead || inventoryRead || deploymentCapabilityRead || policyRead ||
		resourceSharingRead || directoryRead
	if request.Method == http.MethodGet && !safeRead {
		return false
	}
	queryAllowed := approvalRead && approvalPath.kind == policyApprovalPathCollection || managementScopeRead || inventoryRead || resourceSharingCollectionRead
	if (!queryAllowed && target.RawQuery != "") || len(target.RawQuery) > maximumCallbackQueryBytes {
		return false
	}
	if safeRead {
		if !validResourceReadHeaders(request) {
			return false
		}
		if _, present := request.Header["X-Meshtransit-Csrf"]; present {
			return false
		}
	} else {
		invalidBodyTransport := request.ContentLength < 0 || len(request.TransferEncoding) != 0 ||
			len(request.Trailer) != 0
		if nilContinuationDependency(request.Body) || invalidBodyTransport {
			return false
		}
	}
	maximumBody := int64(maximumManagementBodyBytes)
	_, policy := parsePolicyPublishPath(request)
	_, simulation := parsePolicySimulationPath(request)
	_, approval := parsePolicyApprovalPath(request)
	if policy || simulation || approval && approvalPath.kind == policyApprovalPathCollection {
		maximumBody = maximumPolicyPublicationBodyBytes
	}
	if request.ContentLength > maximumBody {
		return false
	}
	for _, name := range []string{
		"Authorization", "Host", "Content-Encoding", "Transfer-Encoding", "Trailer", "Expect", "Upgrade",
	} {
		if _, present := request.Header[name]; present {
			return false
		}
	}
	invalidIntent := singleHeader(request.Header, "Origin") != browser.origin ||
		singleHeader(request.Header, "X-Meshtransit-Session") != "v1"
	invalidContentType := request.Method == http.MethodPost &&
		!validJSONContentType(singleHeader(request.Header, "Content-Type"))
	if invalidIntent || invalidContentType {
		return false
	}
	if values, present := request.Header["Content-Length"]; present {
		if len(values) != 1 || values[0] != strconv.FormatInt(request.ContentLength, 10) {
			return false
		}
	}
	_, site := request.Header["Sec-Fetch-Site"]
	_, mode := request.Header["Sec-Fetch-Mode"]
	_, destination := request.Header["Sec-Fetch-Dest"]
	for name, expected := range map[string]string{
		"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
	} {
		if site || mode || destination {
			if singleHeader(request.Header, name) != expected {
				return false
			}
		}
	}
	_, user := request.Header["Sec-Fetch-User"]
	return !user
}

func (browser *BrowserManagement) prepare(
	ctx context.Context,
	response *browserManagementResponse,
	request *http.Request,
	admission *browserManagementAdmission,
) error {
	if _, present := request.Header["X-Meshtransit-Csrf"]; present {
		return ErrInvalidBrowserManagement
	}
	address, err := browser.management.clientIPs.Resolve(request)
	if err != nil {
		return ErrInvalidBrowserManagement
	}
	if err := browser.budget(ctx, continuationBudget{response: response, kind: ratelimit.SubjectSource,
		raw:    "browser-session-prepare-source/v1\x00" + browser.deploymentID.String() + "\x00" + address.String(),
		policy: browser.management.sourcePolicy}); err != nil {
		return err
	}
	if !validLoginBody(response, request) {
		return ErrInvalidBrowserManagement
	}
	token, err := readBrowserSessionCookie(request.Header)
	if err != nil || token.DeploymentID() != browser.deploymentID {
		return ErrInvalidBrowserManagement
	}
	session, err := browser.management.sessions.Authenticate(ctx, token)
	if err != nil || !browser.activeSession(token, session, browser.clock.Now()) || ctx.Err() != nil {
		return ErrBrowserManagementUnavailable
	}
	if err := browser.budget(ctx, continuationBudget{response: response, kind: ratelimit.SubjectAccountSession,
		raw:    "browser-session-prepare-session/v1\x00" + browser.deploymentID.String() + "\x00" + session.ID().String(),
		policy: browser.management.sessionPolicy}); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrBrowserManagementUnavailable
	}
	var nonce [32]byte
	if _, err := io.ReadFull(browser.entropy, nonce[:]); err != nil {
		return ErrBrowserManagementUnavailable
	}
	proof, err := browser.sealProof(token, session, browser.clock.Now(), nonce)
	if err != nil {
		return err
	}
	admission.token, admission.session, admission.proof = token, session, proof
	admission.hasSession = true
	admission.requiresProof = true
	if err := admission.validateFresh(ctx, time.Second); err != nil {
		return ErrBrowserManagementUnavailable
	}
	body, err := json.Marshal(struct {
		Token     string    `json:"csrf_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}{Token: proof.encoded, ExpiresAt: proof.expires})
	if err != nil {
		return ErrBrowserManagementUnavailable
	}
	correlationID, err := browser.management.correlationIDs.NewID()
	if err != nil || !correlationID.IsValid() {
		return ErrBrowserManagementUnavailable
	}
	setManagementSecurityHeaders(response.header, correlationID)
	response.header.Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(body); err != nil {
		return ErrBrowserManagementUnavailable
	}
	return nil
}

func (browser *BrowserManagement) budget(ctx context.Context, budget continuationBudget) error {
	if ctx.Err() != nil {
		return ErrBrowserManagementUnavailable
	}
	subject, err := browser.management.rateSubjects.Subject(budget.kind, budget.raw)
	if err != nil || !subject.IsValid() || subject.Kind() != budget.kind {
		return ErrBrowserManagementUnavailable
	}
	decision, err := browser.management.rateLimiter.Allow(ctx, subject, budget.policy)
	if err != nil || ctx.Err() != nil {
		return ErrBrowserManagementUnavailable
	}
	validDecision := decision.IsValid() && decision.Limit() == budget.policy.Capacity() &&
		decision.RetryAfter() <= 24*time.Hour
	if !validDecision {
		return ErrBrowserManagementUnavailable
	}
	setRateLimitHeaders(budget.response.Header(), decision)
	if !decision.Allowed() {
		return ErrBrowserManagementLimited
	}
	return nil
}

type browserManagementAdmission struct {
	browser       *BrowserManagement
	token         accountsession.Token
	session       accountsession.Session
	proof         browserSessionProof
	hasSession    bool
	requiresProof bool
}

func (admission *browserManagementAdmission) authenticate(
	ctx context.Context,
	request *http.Request,
) (accountsession.Session, error) {
	browser := admission.browser
	token, err := readBrowserSessionCookie(request.Header)
	if err != nil || token.DeploymentID() != browser.deploymentID {
		return accountsession.Session{}, accountsession.ErrUnauthenticated
	}
	proof := browserSessionProof{}
	if admission.requiresProof {
		proof, err = browser.readProof(
			token, singleHeader(request.Header, "X-Meshtransit-Csrf"), browser.clock.Now(),
		)
		if err != nil {
			return accountsession.Session{}, accountsession.ErrUnauthenticated
		}
	}
	session, err := browser.management.sessions.Authenticate(ctx, token)
	if err != nil {
		if errors.Is(err, accountsession.ErrAuthenticationUnavailable) || ctx.Err() != nil {
			return accountsession.Session{}, accountsession.ErrAuthenticationUnavailable
		}
		return accountsession.Session{}, accountsession.ErrUnauthenticated
	}
	admission.token, admission.session, admission.proof = token, session, proof
	admission.hasSession = true
	if err := admission.validate(ctx); err != nil {
		return accountsession.Session{}, err
	}
	return session, nil
}

func (admission *browserManagementAdmission) validate(ctx context.Context) error {
	return admission.validateFresh(ctx, 0)
}

func (admission *browserManagementAdmission) validateFresh(ctx context.Context, minimumRemaining time.Duration) error {
	// A nil admission is the unchanged Bearer-only path, not cookie authority.
	if admission == nil {
		return nil
	}
	if ctx.Err() != nil {
		return accountsession.ErrAuthenticationUnavailable
	}
	if !admission.hasSession {
		return nil // A buffered generic authentication denial carries no authority.
	}
	browser := admission.browser
	now := browser.clock.Now()
	if !browser.activeSession(admission.token, admission.session, now) {
		return accountsession.ErrUnauthenticated
	}
	if admission.requiresProof {
		if admission.proof.expires.After(admission.session.IdleExpiresAt()) ||
			admission.proof.expires.After(admission.session.AbsoluteExpiresAt()) {
			return accountsession.ErrUnauthenticated
		}
		if _, err := browser.readProof(admission.token, admission.proof.encoded, now); err != nil {
			return accountsession.ErrUnauthenticated
		}
		if admission.proof.expires.Sub(now) < minimumRemaining {
			return accountsession.ErrUnauthenticated
		}
	}
	// The clock is a port too: no late cancellation may hide behind a valid
	// timestamp/MAC. Freshness and remaining lifetime share exactly this snapshot.
	if ctx.Err() != nil {
		return accountsession.ErrAuthenticationUnavailable
	}
	return nil
}

// MetricsCollector exposes only isolated profile telemetry for explicit private registration.
func (browser *BrowserManagement) MetricsCollector() prometheus.Collector { return browser.telemetry }

// String conceals resident key material and the private profile's topology.
func (BrowserManagementOptions) String() string { return "[REDACTED]" }

// GoString conceals configuration during detailed incidental formatting.
func (BrowserManagementOptions) GoString() string {
	return "httpapi.BrowserManagementOptions([REDACTED])"
}

// LogValue conceals resident configuration from structured logs.
func (BrowserManagementOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental resident credential publication.
func (BrowserManagementOptions) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidBrowserManagement
}

// String conceals private component topology during incidental formatting.
func (*BrowserManagement) String() string { return "[REDACTED]" }

// GoString conceals private ownership details during detailed formatting.
func (*BrowserManagement) GoString() string { return "httpapi.BrowserManagement([REDACTED])" }

// LogValue conceals private component topology from structured logs.
func (*BrowserManagement) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
