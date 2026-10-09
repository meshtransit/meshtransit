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
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/invitation"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

// InvitationPreparePath previews an invitation and binds it to the next
// sign-in in this browser.
const InvitationPreparePath = "/auth/v1/invitations/prepare"

// InvitationCookieName carries the invitation token from the prepare call to
// the sign-in completion. It is HttpOnly, host-only and lives ten minutes.
const InvitationCookieName = "__Host-mt_invite"

const (
	invitationCookieLifetime   = 10 * time.Minute
	maximumInvitationBodyBytes = 128
)

// InvitationPreviewer reads what an invitation link is for.
type InvitationPreviewer interface {
	Preview(context.Context, invitation.Token) (invitation.Preview, error)
}

// InvitationPrepareOptions configure the unauthenticated prepare endpoint.
type InvitationPrepareOptions struct {
	Origin                string
	DeploymentID          deployment.ID
	Previewer             InvitationPreviewer
	RateLimitSubjects     RateLimitSubjectDigester
	RateLimiter           ManagementRateLimiter
	SourceRateLimit       ratelimit.Policy
	TrustedProxyPrefixes  []netip.Prefix
	RequestTimeout        time.Duration
	MaxConcurrentRequests int
}

// InvitationPrepareHandler answers a link's preview and sets the invitation
// cookie; it grants nothing by itself.
type InvitationPrepareHandler struct {
	options   InvitationPrepareOptions
	host      string
	clientIPs clientIPResolver
	slots     chan struct{}
}

// NewInvitationPrepareHandler validates before any effect.
func NewInvitationPrepareHandler(options InvitationPrepareOptions) (*InvitationPrepareHandler, error) {
	origin, err := url.Parse(options.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.Path != "" ||
		!options.DeploymentID.IsValid() || nilContinuationDependency(options.Previewer) ||
		options.RateLimitSubjects == nil || options.RateLimiter == nil || !options.SourceRateLimit.IsValid() ||
		options.RequestTimeout <= 0 || options.RequestTimeout > 30*time.Second ||
		options.MaxConcurrentRequests < 1 || options.MaxConcurrentRequests > 128 {
		return nil, ErrInvalidLoginHTTP
	}
	clientIPs, err := newClientIPResolver(options.TrustedProxyPrefixes)
	if err != nil {
		return nil, ErrInvalidLoginHTTP
	}
	options.TrustedProxyPrefixes = nil
	return &InvitationPrepareHandler{options: options, host: origin.Host, clientIPs: clientIPs,
		slots: make(chan struct{}, options.MaxConcurrentRequests)}, nil
}

func (handler *InvitationPrepareHandler) validRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.TLS == nil || request.TLS.Version < tls.VersionTLS12 ||
		request.Host != handler.host || request.Method != http.MethodPost || request.URL.Path != InvitationPreparePath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		!boundedLoginHeaders(request.Header) {
		return false
	}
	for name, expected := range map[string]string{"Origin": handler.options.Origin,
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
	return request.ContentLength >= 0 && request.ContentLength <= maximumInvitationBodyBytes &&
		len(request.TransferEncoding) == 0
}

func (handler *InvitationPrepareHandler) allowed(ctx context.Context, response http.ResponseWriter,
	request *http.Request) int {
	address, err := handler.clientIPs.Resolve(request)
	if err != nil {
		return http.StatusForbidden
	}
	raw := "invitation-prepare/v1\x00" + handler.options.DeploymentID.String() + "\x00" + address.String()
	subject, err := handler.options.RateLimitSubjects.Subject(ratelimit.SubjectSource, raw)
	if err != nil || !subject.IsValid() {
		return http.StatusServiceUnavailable
	}
	decision, err := handler.options.RateLimiter.Allow(ctx, subject, handler.options.SourceRateLimit)
	if err != nil || ctx.Err() != nil || !decision.IsValid() || decision.RetryAfter() > 24*time.Hour {
		return http.StatusServiceUnavailable
	}
	setRateLimitHeaders(response.Header(), decision)
	if !decision.Allowed() {
		return http.StatusTooManyRequests
	}
	return 0
}

// ServeHTTP previews one invitation and binds it to this browser's sign-in.
func (handler *InvitationPrepareHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setLoginSecurityHeaders(response.Header())
	if handler == nil || !handler.validRequest(request) {
		_ = writeLoginError(response, http.StatusForbidden)
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		_ = writeLoginError(response, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.options.RequestTimeout)
	defer cancel()
	var body struct {
		Invitation *string `json:"invitation"`
	}
	reader := http.MaxBytesReader(response, request.Body, maximumInvitationBodyBytes)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || body.Invitation == nil || decoder.Decode(&struct{}{}) != io.EOF {
		_ = writeLoginError(response, http.StatusBadRequest)
		return
	}
	if status := handler.allowed(ctx, response, request); status != 0 {
		_ = writeLoginError(response, status)
		return
	}
	token, ok := invitation.ParseToken(*body.Invitation)
	if !ok {
		writeInvitationNotFound(response)
		return
	}
	preview, err := handler.options.Previewer.Preview(ctx, token)
	if errors.Is(err, invitation.ErrNotFound) {
		writeInvitationNotFound(response)
		return
	}
	if err != nil || ctx.Err() != nil {
		_ = writeLoginError(response, http.StatusServiceUnavailable)
		return
	}
	var role *string
	if preview.Role != "" {
		role = &preview.Role
	}
	encoded, err := json.Marshal(struct {
		WorkspaceName string  `json:"workspace_name"`
		InviterName   string  `json:"inviter_name"`
		Email         string  `json:"email"`
		Role          *string `json:"role"`
		ExpiresAt     string  `json:"expires_at"`
	}{preview.WorkspaceName, preview.InviterName, preview.Email, role, preview.ExpiresAt.UTC().Format(time.RFC3339)})
	if err != nil {
		_ = writeLoginError(response, http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(response, &http.Cookie{Name: InvitationCookieName, Value: token.String(), Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(invitationCookieLifetime / time.Second)})
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func writeInvitationNotFound(response http.ResponseWriter) {
	response.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(response,
		`{"error":{"code":"invitation_unavailable","message":"this invitation link is not valid"}}`)
}

// expiredInvitationCookie removes the invitation binding.
func expiredInvitationCookie() *http.Cookie {
	return &http.Cookie{Name: InvitationCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1}
}

// invitationProofFromRequest reads the invitation cookie, if any.
func invitationProofFromRequest(request *http.Request) (invitation.Token, bool) {
	cookie, err := request.Cookie(InvitationCookieName)
	if err != nil {
		return invitation.Token{}, false
	}
	return invitation.ParseToken(cookie.Value)
}

var _ http.Handler = (*InvitationPrepareHandler)(nil)
