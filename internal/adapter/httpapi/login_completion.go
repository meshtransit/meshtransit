package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

// AccountSessionCookieName carries only a freshly confirmed Core bearer.
const AccountSessionCookieName = "__Host-mt_session"

var (
	// ErrInvalidLoginCompletion conceals invalid configuration/admission/release.
	ErrInvalidLoginCompletion = errors.New("http api: invalid browser completion")
	// ErrLoginCompletionUnavailable conceals dependency/transport failure, not retry permission.
	ErrLoginCompletionUnavailable = errors.New("http api: browser completion unavailable")
	// ErrLoginCompletionDelivery means delivery began; never rewrite/retry the response.
	ErrLoginCompletionDelivery = errors.New("http api: browser completion delivery failed")
	// ErrLoginCompletionSaturated means whole-request capacity rejected without queueing.
	ErrLoginCompletionSaturated = errors.New("http api: browser completion saturated")
)

// BrowserLoginCompleter accepts syntax only after protected HTTP admission.
// Its opaque result must come from confirmed-only application orchestration.
type BrowserLoginCompleter interface {
	CompleteBrowser(context.Context, oidcauth.CallbackCommand) (oidcauth.CallbackResult, error)
}

// LoginCompletionOutcome is closed delivery metadata, never a browser receipt or RBAC grant.
type LoginCompletionOutcome uint8

const (
	// LoginCompletionUnknown coalesces unsupported observation values.
	LoginCompletionUnknown LoginCompletionOutcome = iota
	// LoginCompletionIssued means a confirmed Session response was submitted, not received.
	LoginCompletionIssued
	// LoginCompletionNoGrant means confirmed provider-error erasure without a Session.
	LoginCompletionNoGrant
	// LoginCompletionInvalid means malformed admission or stale/substituted evidence.
	LoginCompletionInvalid
	// LoginCompletionLimited means a shared or application budget was exhausted.
	LoginCompletionLimited
	// LoginCompletionSaturated means local whole-request/admission capacity was full.
	LoginCompletionSaturated
	// LoginCompletionUnavailable means canceled work or unavailable dependency/transport.
	LoginCompletionUnavailable
	// LoginCompletionCommitUnknown means lost acknowledgement without retry or response.
	LoginCompletionCommitUnknown
	// LoginCompletionDeliveryFailed means a response may already have been partly delivered.
	LoginCompletionDeliveryFailed
)

// String maps arbitrary observation values to one fixed bounded label set.
func (outcome LoginCompletionOutcome) String() string {
	switch outcome {
	case LoginCompletionIssued:
		return "issued"
	case LoginCompletionNoGrant:
		return "no_grant"
	case LoginCompletionInvalid:
		return "invalid"
	case LoginCompletionLimited:
		return "limited"
	case LoginCompletionSaturated:
		return "saturated"
	case LoginCompletionUnavailable:
		return "unavailable"
	case LoginCompletionCommitUnknown:
		return "commit_unknown"
	case LoginCompletionDeliveryFailed:
		return "delivery_failed"
	default:
		return "unknown"
	}
}

// LoginCompletionObserver receives only closed metadata; implementations must
// be private, bounded, nonblocking, concurrency-safe and perform no external I/O.
type LoginCompletionObserver interface {
	CompletionOpened()
	CompletionClosed(LoginCompletionOutcome, time.Duration)
}

// LoginCompletionOptions binds a Core-owned return-route mapping and whole-request owner.
// Admission's live clock must be shared with Callback at composition time.
type LoginCompletionOptions struct {
	Admission      *LoginContinuationGate
	Callback       BrowserLoginCompleter
	ReturnRouteID  string
	ReturnPath     string
	Observer       LoginCompletionObserver
	RequestTimeout time.Duration
	MaxConcurrent  int
}

// LoginCompletion privately composes admission, confirmed issuance and BFF delivery.
// It registers no route, owns no browser memory/goroutine and does not enable public login.
type LoginCompletion struct {
	options LoginCompletionOptions
	// Complete owns each non-queuing slot through joined cleanup and delivery; never close.
	slots chan struct{}
}

// NewLoginCompletion rejects invalid dependencies/mapping/bounds before effects.
func NewLoginCompletion(options LoginCompletionOptions) (*LoginCompletion, error) {
	gate := options.Admission
	missingPorts := nilContinuationDependency(options.Callback) || nilContinuationDependency(options.Observer)
	validBounds := options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second &&
		options.MaxConcurrent >= 1 && options.MaxConcurrent <= 128
	if gate == nil || missingPorts || !validBounds {
		return nil, ErrInvalidLoginCompletion
	}
	validAdmission := gate.slots != nil && gate.options.CSRF.IsValid() && gate.options.Capsule.valid() &&
		!nilContinuationDependency(gate.options.Clock)
	if !validAdmission {
		return nil, ErrInvalidLoginCompletion
	}
	validMapping := options.ReturnRouteID == gate.options.CSRF.Route().ReturnRouteID() &&
		validLoginReturnPath(options.ReturnPath)
	if !validAdmission || !validMapping {
		return nil, ErrInvalidLoginCompletion
	}
	return &LoginCompletion{options: options, slots: make(chan struct{}, options.MaxConcurrent)}, nil
}

// Complete requires a pristine writer; it releases no status/body/cookies before
// confirmed fresh exact-route evidence. Closed errors are for a future HTTP caller.
// ErrLoginCompletionDelivery forbids response rewrite: partial delivery and durable
// issuance cannot be undone or retried. Existing Session cookies survive no-grant/errors.
func (completion *LoginCompletion) Complete(response http.ResponseWriter, request *http.Request) (resultErr error) {
	missingOwner := completion == nil || completion.slots == nil
	missingCall := request == nil || nilContinuationDependency(response)
	if missingOwner || missingCall {
		return ErrLoginCompletionUnavailable
	}
	started := time.Now()
	outcome := LoginCompletionUnavailable
	completion.options.Observer.CompletionOpened()
	defer func() {
		completion.options.Observer.CompletionClosed(completionOutcome(outcome, resultErr), time.Since(started))
	}()
	header := response.Header()
	if !pristineLoginResponse(header) {
		return ErrInvalidLoginCompletion
	}
	ctx, cancel := context.WithTimeout(request.Context(), completion.options.RequestTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return safeCompletionError(ctx.Err())
	}
	select {
	case completion.slots <- struct{}{}:
		defer func() { <-completion.slots }()
	default:
		return ErrLoginCompletionSaturated
	}
	if !completion.options.Admission.validRequest(request, LoginContinuationRead) {
		return ErrInvalidLoginCompletion
	}
	// Bound before cloning. Application ports never receive these private HTTP
	// headers; caller-owned mutable cookies/proof cannot change admitted input.
	request = request.Clone(ctx)
	input, err := completion.options.Admission.Read(response, request)
	if err != nil {
		return safeCompletionError(err)
	}
	// Read cancels only its own child. Reset its shorter transport deadline to the
	// still-live whole request; never reuse the gate's returned/canceled context.
	deadline, hasDeadline := ctx.Deadline()
	controller := http.NewResponseController(response)
	if !hasDeadline || ctx.Err() != nil {
		return ErrLoginCompletionUnavailable
	}
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		return ErrLoginCompletionUnavailable
	}
	command, err := input.Command()
	if err != nil {
		return ErrInvalidLoginCompletion
	}
	result, err := completion.options.Callback.CompleteBrowser(ctx, command)
	if err != nil {
		return safeCompletionError(err) // An error, including release failure, is never non-commit proof.
	}
	if ctx.Err() != nil {
		return safeCompletionError(ctx.Err())
	}
	if !result.IsLiveAt(completion.options.Admission.options.Clock.Now()) {
		return ErrInvalidLoginCompletion
	}
	binding, err := callbackRouteFingerprint(result.Route())
	if err != nil || binding != completion.options.Admission.options.Capsule.binding {
		return ErrInvalidLoginCompletion
	}
	body := []byte(`{"error":{"code":"login_unavailable","message":"login could not be completed"}}`)
	status := http.StatusForbidden
	cookies := []*http.Cookie{oidc.ExpiredPreAuthCookie(), oidc.ExpiredLoginCallbackCookie(),
		oidc.ExpiredLoginInitiationCookie()}
	outcome = LoginCompletionNoGrant
	if result.Issued().IsValid() {
		body, err = json.Marshal(struct {
			ReturnPath string `json:"return_path"`
		}{ReturnPath: completion.options.ReturnPath})
		if err != nil {
			return ErrLoginCompletionUnavailable
		}
		status, outcome = http.StatusOK, LoginCompletionIssued
	}
	if ctx.Err() != nil {
		return safeCompletionError(ctx.Err())
	}
	// Admission's short proof/capsule windows are not extended by provider/DB
	// waits. If delivery is suppressed after issuance, only normal expiry owns it.
	gate := completion.options.Admission
	releaseAt := gate.options.Clock.Now()
	if gate.options.CSRF.Verify(request.Header, releaseAt) != nil {
		return ErrInvalidLoginCompletion
	}
	if _, err := gate.options.Capsule.Open(ctx, request.Header, releaseAt); err != nil {
		return safeCompletionError(continuationCapsuleError(err))
	}
	if !pristineLoginResponse(header) || !result.IsLiveAt(releaseAt) {
		return ErrInvalidLoginCompletion
	}
	if gate.options.CSRF.Verify(request.Header, releaseAt) != nil {
		return ErrInvalidLoginCompletion
	}
	if result.Issued().IsValid() {
		cookie, err := confirmedSessionCookie(result, releaseAt)
		if err != nil {
			return err
		}
		cookies = append(cookies, cookie)
	}
	// Prepare the complete bounded header candidate privately; bearer material
	// must not touch the writer until all encoding, bounds and cancellation checks pass.
	candidate := header.Clone()
	setLoginSecurityHeaders(candidate)
	for _, cookie := range cookies {
		candidate.Add("Set-Cookie", cookie.String())
	}
	if !boundedLoginHeaders(candidate) {
		return ErrInvalidLoginCompletion
	}
	if ctx.Err() != nil {
		return safeCompletionError(ctx.Err())
	}
	clear(header)
	for name, values := range candidate {
		header[name] = values
	}
	response.WriteHeader(status)
	if written, err := response.Write(body); err != nil || written != len(body) {
		return ErrLoginCompletionDelivery
	}
	return nil
}

func confirmedSessionCookie(result oidcauth.CallbackResult, now time.Time) (*http.Cookie, error) {
	liveIssuance := result.IsLiveAt(now) && result.Issued().IsValid()
	if !validCapsuleTime(now) || !liveIssuance {
		return nil, ErrInvalidLoginCompletion
	}
	session := result.Issued().Session()
	expiry := session.IdleExpiresAt()
	if session.AbsoluteExpiresAt().Before(expiry) {
		expiry = session.AbsoluteExpiresAt()
	}
	expiry = expiry.UTC().Truncate(time.Second)
	remaining := expiry.Sub(now.UTC()) / time.Second
	validLifetime := remaining >= 1 && remaining <= 24*60*60 && expiry.Year() <= 9998
	if !validLifetime {
		return nil, ErrInvalidLoginCompletion
	}
	cookie := &http.Cookie{Name: AccountSessionCookieName, Value: result.Issued().Token().Encoded(), Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expiry, MaxAge: int(remaining)}
	if err := cookie.Valid(); err != nil || len(cookie.String()) >= 4096 {
		return nil, ErrInvalidLoginCompletion
	}
	return cookie, nil
}

func pristineLoginResponse(header http.Header) bool {
	if header == nil || !boundedLoginHeaders(header) {
		return false
	}
	for name := range header {
		switch name {
		case "Set-Cookie", "Location", "Content-Length", "Transfer-Encoding", "Authorization":
			return false
		}
	}
	return true
}

func validLoginReturnPath(value string) bool {
	if len(value) > 256 || value != "/" && !canonicalCallbackPath(value) {
		return false
	}
	return value != "/auth" && !strings.HasPrefix(value, "/auth/")
}

// Preserve only closed categories/signals; never return arbitrary dependency chains.
func safeCompletionError(err error) error {
	category := ErrLoginCompletionUnavailable
	switch {
	case errors.Is(err, ErrInvalidLoginContinuation), errors.Is(err, oidcauth.ErrCallbackRejected):
		category = ErrInvalidLoginCompletion
	case errors.Is(err, ErrLoginContinuationLimited), errors.Is(err, oidcauth.ErrCallbackLimited):
		category = ErrLoginContinuationLimited
	case errors.Is(err, ErrLoginContinuationSaturated):
		category = ErrLoginCompletionSaturated
	}
	for _, signal := range []error{oidcauth.ErrCommitOutcomeUnknown, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, signal) {
			category = errors.Join(category, signal)
		}
	}
	return category
}

func completionOutcome(success LoginCompletionOutcome, err error) LoginCompletionOutcome {
	switch {
	case errors.Is(err, ErrLoginCompletionDelivery):
		return LoginCompletionDeliveryFailed
	case errors.Is(err, oidcauth.ErrCommitOutcomeUnknown):
		return LoginCompletionCommitUnknown
	case errors.Is(err, ErrInvalidLoginCompletion):
		return LoginCompletionInvalid
	case errors.Is(err, ErrLoginContinuationLimited):
		return LoginCompletionLimited
	case errors.Is(err, ErrLoginCompletionSaturated):
		return LoginCompletionSaturated
	case err != nil:
		return LoginCompletionUnavailable
	default:
		return success
	}
}

var _ BrowserLoginCompleter = (*oidcauth.CallbackService)(nil)
