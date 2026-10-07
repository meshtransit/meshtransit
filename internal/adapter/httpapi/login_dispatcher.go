package httpapi

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ErrInvalidLoginDispatcher conceals incomplete graphs and rejected HTTP shape.
	ErrInvalidLoginDispatcher = errors.New("http api: invalid login dispatcher")
	// ErrLoginDispatchUnavailable conceals missing ownership or canceled dispatch.
	ErrLoginDispatchUnavailable = errors.New("http api: login dispatch unavailable")
)

// LoginDispatcher selects exact private login operations, never a public HTTP
// error mapper. It accepts no alternate key, route, service or authentication
// profile. Callers must preserve component response ownership on every return.
type LoginDispatcher struct {
	browser      *BrowserLogin
	management   *BrowserManagement
	registration *BrowserRegistrationPage
	metrics      *loginDispatchTelemetry
}

// NewLoginDispatcher accepts only coherent, already validated login and browser
// session graphs. The callback cannot occupy another fixed operation, and only
// the browser management operations owned by BrowserManagement are admitted.
// Construction performs no application effect.
func NewLoginDispatcher(browser *BrowserLogin, management *BrowserManagement) (*LoginDispatcher, error) {
	if browser == nil || browser.start == nil || browser.reader == nil || browser.capsule == nil ||
		browser.gate == nil || browser.completion == nil || browser.landing == nil || browser.metrics == nil {
		return nil, ErrInvalidLoginDispatcher
	}
	completeOwnership := browser.slots != nil && browser.start.slots != nil && browser.gate.slots != nil &&
		browser.completion.slots != nil && browser.landing.slots != nil
	coherentManagement := validBrowserManagementOwner(management) &&
		management.deploymentID == browser.reader.route.DeploymentID() &&
		management.origin == browser.reader.origin && management.host == browser.reader.host
	if !completeOwnership || !browser.reader.route.IsValid() || !validDispatcherCallbackPath(browser.reader.path) ||
		!coherentManagement {
		return nil, ErrInvalidLoginDispatcher
	}
	return &LoginDispatcher{browser: browser, management: management, metrics: newLoginDispatchTelemetry()}, nil
}

// NewLoginDispatcherWithRegistration adds a read-only browser intent page to
// the same private TLS host. The existing SSO and management routes stay owned
// by their original handlers.
func NewLoginDispatcherWithRegistration(
	browser *BrowserLogin, management *BrowserManagement,
	registration *BrowserRegistrationPage,
) (*LoginDispatcher, error) {
	dispatcher, err := NewLoginDispatcher(browser, management)
	if err != nil || registration == nil || registration.host != browser.reader.host ||
		!registration.keys.IsValid() || nilContinuationDependency(registration.choices) ||
		registration.slots == nil || registration.loginPage == nil ||
		registration.choicesPage == nil || registration.approvedPage == nil ||
		((registration.management == nil) != nilContinuationDependency(registration.approval)) ||
		(registration.management != nil && registration.management != management) {
		return nil, ErrInvalidLoginDispatcher
	}
	dispatcher.registration = registration
	return dispatcher, nil
}

// WithRegistration preserves the existing dispatch metrics while adding the
// validated page before the listener is constructed.
func (dispatcher *LoginDispatcher) WithRegistration(
	registration *BrowserRegistrationPage,
) (*LoginDispatcher, error) {
	if dispatcher == nil || dispatcher.metrics == nil {
		return nil, ErrInvalidLoginDispatcher
	}
	withPage, err := NewLoginDispatcherWithRegistration(
		dispatcher.browser, dispatcher.management, registration,
	)
	if err != nil {
		return nil, err
	}
	withPage.metrics = dispatcher.metrics
	return withPage, nil
}

func validDispatcherCallbackPath(value string) bool {
	if len(value) > 256 || !strings.HasPrefix(value, "/auth/") || !canonicalCallbackPath(value) {
		return false
	}
	switch value {
	case LoginPreparePath, LoginStartPath, LoginCallbackContinuePath, LoginContinuationPreparePath,
		AccountSessionCSRFPreparePath, AccountSessionLogoutPath, AccountSessionManagementScopesPath:
		return false
	default:
		return true
	}
}

// CallbackPath returns only the graph's immutable canonical path for source
// document composition. It is not a client selector or provider/return URL.
func (dispatcher *LoginDispatcher) CallbackPath() string {
	if dispatcher == nil || dispatcher.browser == nil || dispatcher.browser.reader == nil {
		return ""
	}
	return dispatcher.browser.reader.path
}

// Handle delegates the original writer/request/context to exactly one existing
// owner. It never redirects, canonicalizes, retries or overwrites delegated
// failures/partial output. Nil means normal dispatch return, NOT login success,
// commit or browser receipt. No ServeHTTP is provided to hide closed errors.
func (dispatcher *LoginDispatcher) Handle(response http.ResponseWriter, request *http.Request) (resultErr error) {
	if dispatcher == nil || dispatcher.browser == nil || dispatcher.metrics == nil {
		return ErrLoginDispatchUnavailable
	}
	operation := "unknown"
	started := time.Now()
	dispatcher.metrics.active.Inc()
	defer func() { dispatcher.metrics.closed(operation, resultErr, time.Since(started)) }()
	if !dispatcher.validRequest(response, request) {
		return ErrInvalidLoginDispatcher
	}
	if request.Context().Err() != nil {
		return ErrLoginDispatchUnavailable
	}
	if isBrowserManagementOperation(request) {
		operation = "management"
		return dispatcher.management.Handle(response, request)
	}
	if dispatcher.registration != nil &&
		(request.Method == http.MethodGet || request.Method == http.MethodPost) &&
		strings.HasPrefix(request.URL.Path, browserRegistrationPagePrefix) {
		operation = "registration_landing"
		if request.Method == http.MethodPost {
			operation = "registration_approval"
		}
		dispatcher.registration.ServeHTTP(response, request)
		return nil
	}
	browser := dispatcher.browser
	switch request.URL.Path {
	case LoginPreparePath, LoginStartPath:
		if request.Method != http.MethodPost {
			return ErrInvalidLoginDispatcher
		}
		operation = "prepare"
		if request.URL.Path == LoginStartPath {
			operation = "start"
		}
		browser.start.ServeHTTP(response, request)
		return nil
	case browser.reader.path:
		if request.Method != http.MethodGet {
			return ErrInvalidLoginDispatcher
		}
		operation = "capture"
		return browser.Capture(response, request)
	case LoginContinuationPreparePath:
		if request.Method != http.MethodPost {
			return ErrInvalidLoginDispatcher
		}
		operation = "continue_prepare"
		return browser.gate.Prepare(response, request)
	case AccountSessionCSRFPreparePath:
		if request.Method != http.MethodPost {
			return ErrInvalidLoginDispatcher
		}
		operation = "session_prepare"
		return dispatcher.management.Handle(response, request)
	case AccountSessionLogoutPath:
		if request.Method != http.MethodPost {
			return ErrInvalidLoginDispatcher
		}
		operation = "session_logout"
		return dispatcher.management.Handle(response, request)
	case LoginCallbackContinuePath:
		switch request.Method {
		case http.MethodGet, http.MethodHead:
			operation = "landing"
			return browser.landing.Present(response, request)
		case http.MethodPost:
			operation = "complete"
			return browser.completion.Complete(response, request)
		}
	}
	return ErrInvalidLoginDispatcher
}

func isBrowserManagementOperation(request *http.Request) bool {
	if request == nil {
		return false
	}
	if resourceSharing, _ := browserResourceSharingOperation(request); resourceSharing || isWorkspaceRoleOperation(request) ||
		isWorkspaceCollectionPath(request) && request.Method == http.MethodPost || isNetworkCollectionPost(request) ||
		isSessionWorkspaceOperation(request) || isShareTargetRead(request) || isNetworkAliasRangeOperation(request) ||
		isAuditEventListRead(request) || isAuditEventExportRead(request) || isGuardrailOperation(request) ||
		isDeviceGroupOperation(request) {
		return true
	}
	_, device := parseDeviceRevokePath(request)
	_, inventory := parseDeviceInventoryPath(request)
	_, activePolicy := parseActivePolicyPath(request)
	_, policy := parsePolicyPublishPath(request)
	_, simulation := parsePolicySimulationPath(request)
	approvalPath, approval := parsePolicyApprovalPath(request)
	_, accessGraph := parseAccessGraphExplainPath(request)
	_, workspaceRename := parseWorkspaceRenamePath(request)
	managementScopes := request.URL != nil && request.URL.Path == AccountSessionManagementScopesPath
	deploymentCapabilities := request.URL != nil && request.URL.Path == DeploymentCapabilitiesPath
	if request.Method == http.MethodPost {
		return device || policy || simulation || accessGraph || workspaceRename ||
			approval && (approvalPath.kind == policyApprovalPathCollection || approvalPath.isAction())
	}
	_, accessGraphList := parseAccessGraphListPath(request)
	return request.Method == http.MethodGet && (activePolicy || accessGraphList || inventory || managementScopes || deploymentCapabilities ||
		approval && (approvalPath.kind == policyApprovalPathCollection || approvalPath.kind == policyApprovalPathItem))
}

func (dispatcher *LoginDispatcher) validRequest(response http.ResponseWriter, request *http.Request) bool {
	if request == nil || request.URL == nil || nilContinuationDependency(response) {
		return false
	}
	transport, target := request.TLS, request.URL
	validTLS := transport != nil && transport.HandshakeComplete && transport.Version >= tls.VersionTLS12
	validHost := request.Host == dispatcher.browser.reader.host
	if !validTLS || !validHost || !boundedLoginHeaders(request.Header) {
		return false
	}
	header := response.Header()
	if !pristineLandingResponse(header) || !boundedLoginHeaders(header) {
		return false
	}
	foreignTarget := target.Scheme != "" || target.Host != "" || target.User != nil || target.Opaque != ""
	uncleanTarget := target.RawPath != "" || target.ForceQuery || target.Fragment != "" || target.RawFragment != ""
	invalidBounds := len(target.Path) > 256 || len(target.RawQuery) > maximumCallbackQueryBytes
	if foreignTarget || uncleanTarget || invalidBounds || request.RequestURI != target.RequestURI() {
		return false
	}
	if _, present := request.Header["Authorization"]; present {
		return false
	}
	callback := target.Path == dispatcher.browser.reader.path && request.Method == http.MethodGet
	approvalPath, approval := parsePolicyApprovalPath(request)
	approvalList := approval && request.Method == http.MethodGet &&
		approvalPath.kind == policyApprovalPathCollection
	managementScopes := target.Path == AccountSessionManagementScopesPath && request.Method == http.MethodGet
	_, inventoryRead := parseDeviceInventoryPath(request)
	deploymentCapabilities := target.Path == DeploymentCapabilitiesPath && request.Method == http.MethodGet &&
		target.RawQuery == ""
	registrationRead := dispatcher.registration != nil && request.Method == http.MethodGet &&
		dispatcher.registration.validRequest(request)
	_, resourceSharingCollectionRead := browserResourceSharingOperation(request)
	_, accessGraphListed := parseAccessGraphListPath(request)
	accessGraphRead := accessGraphListed && request.Method == http.MethodGet
	return callback || approvalList || managementScopes || inventoryRead || deploymentCapabilities || registrationRead ||
		resourceSharingCollectionRead || accessGraphRead || isAuditEventListRead(request) ||
		isAuditEventExportRead(request) || target.RawQuery == ""
}

// MetricsCollector permits private root registration only, never a public endpoint.
func (dispatcher *LoginDispatcher) MetricsCollector() prometheus.Collector {
	if dispatcher == nil || dispatcher.metrics == nil {
		return nil
	}
	return dispatcher.metrics
}

// String conceals private graph/key/configuration custody.
func (*LoginDispatcher) String() string { return "[REDACTED]" }

// GoString conceals detailed private graph/configuration custody.
func (*LoginDispatcher) GoString() string { return "httpapi.LoginDispatcher([REDACTED])" }

// LogValue conceals private graph/configuration custody from structured logging.
func (*LoginDispatcher) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental private graph publication.
func (*LoginDispatcher) MarshalJSON() ([]byte, error) { return nil, ErrInvalidLoginDispatcher }

type loginDispatchTelemetry struct {
	active   prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newLoginDispatchTelemetry() *loginDispatchTelemetry {
	// Dashboard: meshtransit_browser_login_dispatch_requests_active
	// Alert (for: 5m): meshtransit_browser_login_dispatch_requests_active > 128
	// Dashboard: sum by (operation, result) (rate(meshtransit_browser_login_dispatch_requests_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_login_dispatch_requests_total{result="handler_error"}[5m])) > 1
	// p99 dashboard/alert (>10s for: 5m): histogram_quantile(0.99,
	// sum by (le) (rate(meshtransit_browser_login_dispatch_duration_seconds_bucket[5m])))
	return &loginDispatchTelemetry{
		active: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_browser_login_dispatch_requests_active", Help: "Owned private login dispatch calls.",
		}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_browser_login_dispatch_requests_total", Help: "Private dispatch returns, not login or receipt.",
		}, []string{"operation", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "meshtransit_browser_login_dispatch_duration_seconds", Help: "Private dispatch duration through return.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
		}, []string{"operation", "result"}),
	}
}

func (telemetry *loginDispatchTelemetry) closed(operation string, err error, elapsed time.Duration) {
	result := "delegated"
	switch {
	case errors.Is(err, ErrInvalidLoginDispatcher):
		result = "invalid"
	case errors.Is(err, ErrLoginDispatchUnavailable):
		result = "unavailable"
	case err != nil:
		result = "handler_error"
	}
	telemetry.active.Dec()
	telemetry.requests.WithLabelValues(operation, result).Inc()
	telemetry.duration.WithLabelValues(operation, result).Observe(max(elapsed.Seconds(), 0))
}

func (telemetry *loginDispatchTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.requests.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

func (telemetry *loginDispatchTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.requests.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var _ prometheus.Collector = (*loginDispatchTelemetry)(nil)
