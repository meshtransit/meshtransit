package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"meshtransit.net/core/internal/adapter/oidc"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/platform/ratelimit"
)

const (
	// LoginPreparePath issues browser intent only, never durable authority.
	LoginPreparePath = "/auth/v1/login/prepare"
	// LoginStartPath creates one confirmed browser AuthTransaction.
	LoginStartPath           = "/auth/v1/login/start"
	maximumLoginHeaderBytes  = 16384
	maximumLoginHeaderFields = 64
	maximumLoginHeaderValues = 128
	maximumLoginBodyBytes    = 32
)

// ErrInvalidLoginHTTP rejects incomplete dependencies before opening a listener.
var ErrInvalidLoginHTTP = errors.New("http api: invalid browser login handler")

// LoginRouteAdmission rechecks current durable login routing, not user membership.
// Implementations must not treat an IdP role, email, or proof as Core authority.
type LoginRouteAdmission interface {
	Admit(context.Context, oidcauth.Route) error
}

// BrowserLoginStarter prepares and atomically commits an already admitted route.
type BrowserLoginStarter interface {
	Start(context.Context, oidcauth.Route) (oidcauth.StartResult, error)
}

// LoginHTTPOutcome is a closed telemetry category containing no browser secrets.
type LoginHTTPOutcome uint8

const (
	// LoginHTTPUnknown represents unsupported telemetry evidence.
	LoginHTTPUnknown LoginHTTPOutcome = iota
	// LoginHTTPPrepared means pre-session browser intent was issued, not committed authority.
	LoginHTTPPrepared
	// LoginHTTPStarted means confirmed durable creation was released.
	LoginHTTPStarted
	// LoginHTTPInvalid means malformed input or failed origin/CSRF evidence.
	LoginHTTPInvalid
	// LoginHTTPLimited means the distributed source budget was exhausted.
	LoginHTTPLimited
	// LoginHTTPUnavailable means dependency, cancellation, or local capacity failure.
	LoginHTTPUnavailable
)

// String maps even unknown numeric values to bounded labels.
func (outcome LoginHTTPOutcome) String() string {
	switch outcome {
	case LoginHTTPPrepared:
		return "prepared"
	case LoginHTTPStarted:
		return "started"
	case LoginHTTPInvalid:
		return "invalid"
	case LoginHTTPLimited:
		return "limited"
	case LoginHTTPUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// LoginHTTPObserver receives only closed outcomes and duration, never dependency errors.
// Implementations must be concurrency-safe, nonblocking, and private to operators.
type LoginHTTPObserver interface {
	ObserveLoginHTTP(LoginHTTPOutcome, time.Duration)
}

// LoginStartHandlerOptions supplies explicit immutable browser-boundary ownership.
// Trusted proxies may identify a source IP only; they never supply TLS or Origin.
type LoginStartHandlerOptions struct {
	Initiation            *oidc.LoginInitiationGuard
	Admission             LoginRouteAdmission
	Starter               BrowserLoginStarter
	RateLimitSubjects     RateLimitSubjectDigester
	RateLimiter           ManagementRateLimiter
	SourceRateLimit       ratelimit.Policy
	TrustedProxyPrefixes  []netip.Prefix
	Clock                 oidcauth.StartClock
	Observer              LoginHTTPObserver
	RequestTimeout        time.Duration
	MaxConcurrentRequests int
}

// LoginStartHandler owns bounded prepare/start admission for one Core-selected route.
// It is intentionally not registered in public runtime composition yet.
type LoginStartHandler struct {
	options   LoginStartHandlerOptions
	host      string
	clientIPs clientIPResolver
	slots     chan struct{}
}

// NewLoginStartHandler validates before any network, entropy, or authority effect.
// Composition must supply durable admission and shared Redis rate limiting; no fallback exists.
func NewLoginStartHandler(options LoginStartHandlerOptions) (*LoginStartHandler, error) {
	if !options.Initiation.IsValid() || options.Admission == nil || options.Starter == nil ||
		options.RateLimitSubjects == nil || options.RateLimiter == nil || !options.SourceRateLimit.IsValid() ||
		options.Clock == nil || options.Observer == nil || options.RequestTimeout <= 0 ||
		options.RequestTimeout > 30*time.Second || options.MaxConcurrentRequests < 1 || options.MaxConcurrentRequests > 128 {
		return nil, ErrInvalidLoginHTTP
	}
	clientIPs, err := newClientIPResolver(options.TrustedProxyPrefixes)
	if err != nil {
		return nil, ErrInvalidLoginHTTP
	}
	origin, err := url.Parse(options.Initiation.Origin())
	if err != nil || origin.Host == "" {
		return nil, ErrInvalidLoginHTTP
	}
	// The resolver owns its copy; no caller-owned mutable slice remains reachable.
	options.TrustedProxyPrefixes = nil
	return &LoginStartHandler{options: options, host: origin.Host, clientIPs: clientIPs,
		slots: make(chan struct{}, options.MaxConcurrentRequests)}, nil
}

// ServeHTTP rejects untrusted requests before admission/discovery/creation.
// Header limits supplement, rather than replace, the listener's transport limits.
func (handler *LoginStartHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setLoginSecurityHeaders(response.Header())
	if handler == nil || !handler.options.Initiation.IsValid() || handler.options.Observer == nil {
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	started := time.Now()
	outcome := LoginHTTPInvalid
	defer func() { handler.options.Observer.ObserveLoginHTTP(outcome, time.Since(started)) }()
	if !handler.validRequest(request) {
		if err := writeLoginError(response, http.StatusForbidden); err != nil {
			outcome = LoginHTTPUnavailable
		}
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		outcome = LoginHTTPUnavailable
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.options.RequestTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		outcome = LoginHTTPUnavailable
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	deadline, hasDeadline := ctx.Deadline()
	controller := http.NewResponseController(response)
	if !hasDeadline || controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		outcome = LoginHTTPUnavailable
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	// Context cancellation alone cannot interrupt a stalled body read. Enforce
	// transport deadlines too; wrappers must support ResponseController/Unwrap.
	if !validLoginBody(response, request) {
		if err := writeLoginError(response, http.StatusBadRequest); err != nil {
			outcome = LoginHTTPUnavailable
		}
		return
	}
	status := handler.applySourceBudget(ctx, response, request)
	if status != 0 {
		outcome = LoginHTTPUnavailable
		if status == http.StatusTooManyRequests {
			outcome = LoginHTTPLimited
		}
		if err := writeLoginError(response, status); err != nil {
			outcome = LoginHTTPUnavailable
		}
		return
	}
	if request.URL.Path == LoginStartPath {
		if err := handler.options.Initiation.Verify(request.Header, handler.options.Clock.Now()); err != nil {
			if err := writeLoginError(response, http.StatusForbidden); err != nil {
				outcome = LoginHTTPUnavailable
			}
			return
		}
	}
	if err := ctx.Err(); err != nil {
		outcome = LoginHTTPUnavailable
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	if err := handler.options.Admission.Admit(ctx, handler.options.Initiation.Route()); err != nil {
		outcome = LoginHTTPUnavailable
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	if err := ctx.Err(); err != nil {
		outcome = LoginHTTPUnavailable
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	outcome = LoginHTTPUnavailable
	if request.URL.Path == LoginStartPath {
		if err := handler.options.Initiation.Verify(request.Header, handler.options.Clock.Now()); err != nil {
			outcome = LoginHTTPInvalid
			if err := writeLoginError(response, http.StatusForbidden); err != nil {
				outcome = LoginHTTPUnavailable
			}
			return
		}
	}
	var body []byte
	var cookies []*http.Cookie
	var err error
	if request.URL.Path == LoginPreparePath {
		body, cookies, err = handler.prepareResponse()
	} else {
		body, cookies, err = handler.startResponse(ctx)
	}
	if err != nil || ctx.Err() != nil {
		if err := writeLoginError(response, http.StatusServiceUnavailable); err != nil {
			return
		}
		return
	}
	if request.URL.Path == LoginStartPath {
		if err := handler.options.Initiation.Verify(request.Header, handler.options.Clock.Now()); err != nil {
			outcome = LoginHTTPInvalid
			if err := writeLoginError(response, http.StatusForbidden); err != nil {
				outcome = LoginHTTPUnavailable
			}
			return
		}
	}
	// No raw value reaches ResponseWriter until every effect and encoding succeeds.
	for _, cookie := range cookies {
		http.SetCookie(response, cookie)
	}
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(body); err != nil {
		return
	}
	outcome = LoginHTTPStarted
	if request.URL.Path == LoginPreparePath {
		outcome = LoginHTTPPrepared
	}
}

func (handler *LoginStartHandler) validRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.TLS == nil || request.TLS.Version < tls.VersionTLS12 ||
		request.Host != handler.host || request.Method != http.MethodPost || !boundedLoginHeaders(request.Header) {
		return false
	}
	path := request.URL.Path
	if path != LoginPreparePath && path != LoginStartPath {
		return false
	}
	if request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" ||
		request.URL.User != nil || request.URL.Opaque != "" {
		return false
	}
	if request.URL.IsAbs() && (request.URL.Scheme != "https" || request.URL.Host != handler.host) {
		return false
	}
	for name, expected := range map[string]string{"Origin": handler.options.Initiation.Origin(),
		"X-Meshtransit-Login": "v1", "Content-Type": "application/json"} {
		values := request.Header.Values(name)
		if len(values) != 1 || values[0] != expected {
			return false
		}
	}
	fetchSite := request.Header.Values("Sec-Fetch-Site")
	if len(fetchSite) > 1 || len(fetchSite) == 1 && fetchSite[0] != "same-origin" {
		return false
	}
	return request.ContentLength >= 0 && request.ContentLength <= maximumLoginBodyBytes && len(request.TransferEncoding) == 0
}

func boundedLoginHeaders(headers http.Header) bool {
	if len(headers) > maximumLoginHeaderFields {
		return false
	}
	var usedBytes, usedValues int
	for name, values := range headers {
		if name == "" || name != http.CanonicalHeaderKey(name) || len(name) > maximumLoginHeaderBytes-usedBytes {
			return false
		}
		for _, character := range name {
			isLetter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
			isDigit := character >= '0' && character <= '9'
			if isLetter || isDigit || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
				continue
			}
			return false
		}
		usedBytes += len(name)
		for _, value := range values {
			usedValues++
			if usedValues > maximumLoginHeaderValues || len(value) > maximumLoginHeaderBytes-usedBytes {
				return false
			}
			usedBytes += len(value)
			for _, character := range value {
				if character > 0x7e || character < 0x20 && character != '\t' {
					return false
				}
			}
		}
	}
	return true
}

func validLoginBody(response http.ResponseWriter, request *http.Request) bool {
	if request.Body == nil {
		return false
	}
	body := http.MaxBytesReader(response, request.Body, maximumLoginBodyBytes)
	value, err := io.ReadAll(body)
	closeErr := body.Close()
	return err == nil && closeErr == nil && strings.Trim(string(value), " \t\r\n") == "{}"
}

func (handler *LoginStartHandler) applySourceBudget(ctx context.Context, response http.ResponseWriter, request *http.Request) int {
	if err := ctx.Err(); err != nil {
		return http.StatusServiceUnavailable
	}
	address, err := handler.clientIPs.Resolve(request)
	if err != nil {
		return http.StatusForbidden
	}
	// Sharing a Redis adapter with management must never share the same counter.
	raw := "browser-login/v1\x00" + handler.options.Initiation.Route().DeploymentID().String() + "\x00" + address.String()
	subject, err := handler.options.RateLimitSubjects.Subject(ratelimit.SubjectSource, raw)
	if err != nil || !subject.IsValid() {
		return http.StatusServiceUnavailable
	}
	decision, err := handler.options.RateLimiter.Allow(ctx, subject, handler.options.SourceRateLimit)
	if err != nil || ctx.Err() != nil || !decision.IsValid() || decision.Limit() != handler.options.SourceRateLimit.Capacity() {
		return http.StatusServiceUnavailable
	}
	if decision.RetryAfter() > 24*time.Hour {
		return http.StatusServiceUnavailable
	}
	setRateLimitHeaders(response.Header(), decision)
	if !decision.Allowed() {
		return http.StatusTooManyRequests
	}
	return 0
}

func (handler *LoginStartHandler) prepareResponse() ([]byte, []*http.Cookie, error) {
	prepared, err := handler.options.Initiation.Prepare(handler.options.Clock.Now())
	if err != nil {
		return nil, nil, err
	}
	cookie, err := prepared.ResponseCookie(handler.options.Clock.Now())
	if err != nil {
		return nil, nil, err
	}
	body, err := json.Marshal(struct {
		Token     string `json:"csrf_token"`
		ExpiresIn int    `json:"expires_in"`
	}{
		Token: prepared.Proof(), ExpiresIn: cookie.MaxAge})
	return body, []*http.Cookie{cookie}, err
}

func (handler *LoginStartHandler) startResponse(ctx context.Context) ([]byte, []*http.Cookie, error) {
	result, err := handler.options.Starter.Start(ctx, handler.options.Initiation.Route())
	if err != nil || ctx.Err() != nil || !result.IsValid() {
		return nil, nil, ErrInvalidLoginHTTP
	}
	location := result.AuthorizationRequest().Location()
	if !loginAuthorizationMatchesRoute(location, handler.options.Initiation.Route()) {
		return nil, nil, ErrInvalidLoginHTTP
	}
	cookie, err := oidc.PreAuthResponseCookie(result, handler.options.Clock.Now())
	if err != nil {
		return nil, nil, err
	}
	body, err := json.Marshal(struct {
		URL string `json:"authorization_url"`
	}{URL: location})
	return body, []*http.Cookie{cookie, oidc.ExpiredLoginInitiationCookie()}, err
}

func loginAuthorizationMatchesRoute(location string, route oidcauth.Route) bool {
	parsed, err := url.Parse(location)
	if err != nil {
		return false
	}
	query := parsed.Query()
	parsed.RawQuery = ""
	return parsed.String() == route.AuthorizationEndpoint() && query.Get("client_id") == route.OIDCClientID() &&
		query.Get("redirect_uri") == route.RedirectURI() && query.Get("scope") == strings.Join(route.Scopes(), " ")
}

func setLoginSecurityHeaders(header http.Header) {
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Strict-Transport-Security", "max-age=31536000")
	header.Del("Access-Control-Allow-Origin")
	header.Del("Access-Control-Allow-Credentials")
}

func writeLoginError(response http.ResponseWriter, status int) error {
	response.WriteHeader(status)
	_, err := io.WriteString(response, `{"error":{"code":"login_unavailable","message":"login could not be completed"}}`)
	return err
}

var _ http.Handler = (*LoginStartHandler)(nil)
