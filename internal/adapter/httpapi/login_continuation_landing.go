package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	_ "embed" // Only immutable build-owned landing content is embedded.
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed login_continuation_landing.html
var loginContinuationLandingHTML string

const maximumLoginLandingBytes = 16384

var (
	// ErrInvalidLoginLanding conceals malformed construction, transport or header ownership.
	ErrInvalidLoginLanding = errors.New("http api: invalid login landing")
	// ErrLoginLandingUnavailable conceals absent ownership, cancellation or transport failure.
	ErrLoginLandingUnavailable = errors.New("http api: login landing unavailable")
	// ErrLoginLandingSaturated means non-queuing static presentation capacity was full.
	ErrLoginLandingSaturated = errors.New("http api: login landing saturated")
	// ErrLoginLandingDelivery means delivery began; never rewrite or retry the response.
	ErrLoginLandingDelivery = errors.New("http api: login landing delivery failed")
)

// LoginLandingOutcome is presentation metadata, never authentication or browser receipt.
type LoginLandingOutcome uint8

const (
	// LoginLandingUnknown coalesces unsupported numeric values.
	LoginLandingUnknown LoginLandingOutcome = iota
	// LoginLandingPresented means static content was submitted, not received or acted on.
	LoginLandingPresented
	// LoginLandingHeaderOnly means HEAD headers were submitted without active content.
	LoginLandingHeaderOnly
	// LoginLandingInvalid means the clean transport/header boundary rejected input.
	LoginLandingInvalid
	// LoginLandingSaturated means capacity rejected without queueing.
	LoginLandingSaturated
	// LoginLandingUnavailable means cancellation or absent transport/owner support.
	LoginLandingUnavailable
	// LoginLandingDeliveryFailed means a static response may already have been partly delivered.
	LoginLandingDeliveryFailed
)

// String emits only a closed bounded label set.
func (outcome LoginLandingOutcome) String() string {
	switch outcome {
	case LoginLandingPresented:
		return "presented"
	case LoginLandingHeaderOnly:
		return "header_only"
	case LoginLandingInvalid:
		return "invalid"
	case LoginLandingSaturated:
		return "saturated"
	case LoginLandingUnavailable:
		return "unavailable"
	case LoginLandingDeliveryFailed:
		return "delivery_failed"
	default:
		return "unknown"
	}
}

// LoginLandingObserver receives closed metadata only. Implementations must be
// private, bounded, nonblocking, concurrency-safe and perform no external I/O.
type LoginLandingObserver interface {
	LandingOpened()
	LandingClosed(LoginLandingOutcome, time.Duration)
}

// LoginContinuationLandingOptions extracts only immutable completion mappings.
// No application port from Completion is retained or invoked by the landing.
type LoginContinuationLandingOptions struct {
	Completion     *LoginCompletion
	Observer       LoginLandingObserver
	RequestTimeout time.Duration
	MaxConcurrent  int
}

// LoginContinuationLanding owns bounded static delivery, never credentials or authority.
// It registers no route/listener and creates no queue, goroutine or browser memory.
type LoginContinuationLanding struct {
	host, origin, body, policy string
	observer                   LoginLandingObserver
	timeout                    time.Duration
	// Present owns these non-queuing slots through delivery; never close the channel.
	slots chan struct{}
}

// NewLoginContinuationLanding pre-renders build-owned content before any request.
// A zero/unvalidated completion or unsafe mapping cannot become a landing.
func NewLoginContinuationLanding(options LoginContinuationLandingOptions) (*LoginContinuationLanding, error) {
	completion := options.Completion
	validBounds := options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second &&
		options.MaxConcurrent >= 1 && options.MaxConcurrent <= 128
	missingCompletion := completion == nil || completion.slots == nil
	missingObserver := nilContinuationDependency(options.Observer)
	if missingCompletion || missingObserver || !validBounds {
		return nil, ErrInvalidLoginLanding
	}
	gate := completion.options.Admission
	if gate == nil || !gate.options.CSRF.IsValid() || !gate.options.Capsule.valid() {
		return nil, ErrInvalidLoginLanding
	}
	validMapping := completion.options.ReturnRouteID == gate.options.CSRF.Route().ReturnRouteID() &&
		validLoginReturnPath(completion.options.ReturnPath)
	if !validMapping || gate.host == "" {
		return nil, ErrInvalidLoginLanding
	}
	page, err := template.New("login-continuation").Parse(loginContinuationLandingHTML)
	if err != nil {
		return nil, ErrInvalidLoginLanding
	}
	var rendered bytes.Buffer
	if err := page.Execute(&rendered, struct{ ReturnPath string }{ReturnPath: completion.options.ReturnPath}); err != nil {
		return nil, ErrInvalidLoginLanding
	}
	if rendered.Len() == 0 || rendered.Len() > maximumLoginLandingBytes {
		return nil, ErrInvalidLoginLanding
	}
	body := rendered.String()
	scriptHash, scriptErr := landingAssetHash(body, "script")
	styleHash, styleErr := landingAssetHash(body, "style")
	if scriptErr != nil || styleErr != nil {
		return nil, ErrInvalidLoginLanding
	}
	policy := "default-src 'none'; script-src 'sha256-" + scriptHash + "'; style-src 'sha256-" + styleHash +
		"'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
	return &LoginContinuationLanding{host: gate.host, origin: gate.options.CSRF.Origin(), body: body, policy: policy,
		observer: options.Observer, timeout: options.RequestTimeout, slots: make(chan struct{}, options.MaxConcurrent)}, nil
}

// Present submits static GET/HEAD content only on an exact clean navigation.
// It neither reads/opens cookies nor prepares proof, consumes budgets, claims,
// exchanges, issues or queries authority. Prerelease errors write no status/body.
// ErrLoginLandingDelivery forbids response rewrite after delivery has begun.
func (landing *LoginContinuationLanding) Present(
	response http.ResponseWriter,
	request *http.Request,
) (resultErr error) {
	missingOwner := landing == nil || landing.slots == nil
	missingCall := request == nil || nilContinuationDependency(response)
	if missingOwner || missingCall {
		return ErrLoginLandingUnavailable
	}
	started := time.Now()
	outcome := LoginLandingUnavailable
	landing.observer.LandingOpened()
	defer func() { landing.observer.LandingClosed(landingOutcome(outcome, resultErr), time.Since(started)) }()
	header := response.Header()
	if !pristineLandingResponse(header) || !landing.validRequest(request) {
		return ErrInvalidLoginLanding
	}
	ctx, cancel := context.WithTimeout(request.Context(), landing.timeout)
	defer cancel()
	if ctx.Err() != nil {
		return errors.Join(ErrLoginLandingUnavailable, ctx.Err())
	}
	select {
	case landing.slots <- struct{}{}:
		defer func() { <-landing.slots }()
	default:
		return ErrLoginLandingSaturated
	}
	deadline, hasDeadline := ctx.Deadline()
	controller := http.NewResponseController(response)
	if !hasDeadline || controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		return ErrLoginLandingUnavailable
	}
	candidate := header.Clone()
	setLoginSecurityHeaders(candidate)
	candidate.Set("Content-Type", "text/html; charset=utf-8")
	candidate.Set("Content-Security-Policy", landing.policy)
	candidate.Set("Content-Length", strconv.Itoa(len(landing.body)))
	candidate.Set("Cross-Origin-Opener-Policy", "same-origin")
	candidate.Set("Cross-Origin-Resource-Policy", "same-origin")
	candidate.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if !boundedLoginHeaders(candidate) {
		return ErrInvalidLoginLanding
	}
	if ctx.Err() != nil {
		return errors.Join(ErrLoginLandingUnavailable, ctx.Err())
	}
	clear(header)
	for name, values := range candidate {
		header[name] = values
	}
	outcome = LoginLandingHeaderOnly
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return nil
	}
	outcome = LoginLandingPresented
	// Always use the ResponseWriter boundary. A promoted StringWriter must not
	// bypass a wrapper's owned delivery/deadline/error instrumentation.
	if written, err := response.Write([]byte(landing.body)); err != nil || written != len(landing.body) {
		return ErrLoginLandingDelivery
	}
	return nil
}

func (landing *LoginContinuationLanding) validRequest(request *http.Request) bool {
	if request.URL == nil || request.TLS == nil {
		return false
	}
	validTLS := request.TLS.HandshakeComplete && request.TLS.Version >= tls.VersionTLS12
	validMethod := request.Method == http.MethodGet || request.Method == http.MethodHead
	validNavigation := validMethod && request.Host == landing.host
	if !validTLS || !validNavigation || !boundedLoginHeaders(request.Header) {
		return false
	}
	target := request.URL
	cleanPath := target.Path == LoginCallbackContinuePath && request.RequestURI == LoginCallbackContinuePath &&
		target.RequestURI() == LoginCallbackContinuePath
	foreignURL := target.Scheme != "" || target.Host != "" || target.User != nil || target.Opaque != ""
	uncleanURL := target.RawPath != "" || target.RawQuery != "" || target.ForceQuery ||
		target.Fragment != "" || target.RawFragment != ""
	hasBody := request.Body != nil && request.Body != http.NoBody
	hasTransfer := request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0
	if !cleanPath || foreignURL || uncleanURL || hasBody || hasTransfer {
		return false
	}
	for _, name := range []string{"Authorization", "Host", "Content-Type", "Content-Encoding", "Transfer-Encoding",
		"Trailer", "Expect", "Upgrade"} {
		if _, present := request.Header[name]; present {
			return false
		}
	}
	if lengths, present := request.Header["Content-Length"]; present {
		if len(lengths) != 1 || lengths[0] != "0" {
			return false
		}
	}
	if origins, present := request.Header["Origin"]; present {
		if len(origins) != 1 || origins[0] != landing.origin {
			return false
		}
	}
	return validCallbackNavigation(request.Header)
}

func pristineLandingResponse(header http.Header) bool {
	if !pristineLoginResponse(header) {
		return false
	}
	// Middleware must not add alternate navigation, external fetch/reporting or
	// encodings which invalidate this page's exact hash-CSP/content boundary.
	for _, name := range []string{"Refresh", "Link", "Content-Encoding", "Content-Location", "Report-To",
		"Reporting-Endpoints", "Nel", "Www-Authenticate", "Authentication-Info", "Proxy-Authenticate"} {
		if _, present := header[name]; present {
			return false
		}
	}
	return true
}

// Hash the exact rendered inline bytes, never a runtime-selected script/style.
func landingAssetHash(body, name string) (string, error) {
	openingTag, closingTag := "<"+name+">", "</"+name+">"
	if strings.Count(body, openingTag) != 1 || strings.Count(body, closingTag) != 1 {
		return "", ErrInvalidLoginLanding
	}
	start, end := strings.Index(body, openingTag)+len(openingTag), strings.Index(body, closingTag)
	if end <= start {
		return "", ErrInvalidLoginLanding
	}
	digest := sha256.Sum256([]byte(body[start:end]))
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

func landingOutcome(success LoginLandingOutcome, err error) LoginLandingOutcome {
	switch {
	case errors.Is(err, ErrLoginLandingDelivery):
		return LoginLandingDeliveryFailed
	case errors.Is(err, ErrInvalidLoginLanding):
		return LoginLandingInvalid
	case errors.Is(err, ErrLoginLandingSaturated):
		return LoginLandingSaturated
	case err != nil:
		return LoginLandingUnavailable
	default:
		return success
	}
}

// String omits configured topology from incidental formatting.
func (*LoginContinuationLanding) String() string { return "[REDACTED]" }

// GoString omits detailed configuration from diagnostic formatting.
func (*LoginContinuationLanding) GoString() string {
	return "httpapi.LoginContinuationLanding([REDACTED])"
}

// LogValue prevents configured origins/return mappings entering structured logs.
func (*LoginContinuationLanding) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
