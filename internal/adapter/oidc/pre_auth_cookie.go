package oidc

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const (
	// PreAuthCookieName is a host-only browser handle, never an Account Session.
	PreAuthCookieName         = "__Host-mt_pre_auth"
	maximumCookieHeaderBytes  = 8192
	maximumCookieHeaderFields = 8
	maximumCookiePairs        = 64
)

// ErrPreAuthCookie reports missing, ambiguous, malformed, or expired browser evidence.
// It intentionally carries neither Cookie headers nor raw handle material.
var ErrPreAuthCookie = errors.New("oidc: invalid pre-auth cookie")

// PreAuthResponseCookie builds cookie attributes only from a confirmed live start.
// The caller must enforce exact HTTPS origin/trusted-proxy and CSRF admission,
// emit no-store responses, and never log this secret-bearing http.Cookie.
// This helper opens no public route and emits no HTTP response by itself.
func PreAuthResponseCookie(result oidcauth.StartResult, now time.Time) (*http.Cookie, error) {
	if !result.IsValid() || now.IsZero() || now.Before(result.Created().CreatedAt()) {
		return nil, ErrPreAuthCookie
	}
	expiresAt := result.Created().ExpiresAt().UTC().Truncate(time.Second)
	remaining := expiresAt.Sub(now.UTC()) / time.Second
	if remaining < 1 || remaining > 600 {
		return nil, ErrPreAuthCookie
	}
	return &http.Cookie{
		Name: PreAuthCookieName, Value: result.PreAuthCookie().Encoded(),
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: expiresAt, MaxAge: int(remaining),
	}, nil
}

// ExpiredPreAuthCookie clears the same host-only scope after a terminal transition.
// Clearing a browser handle never replaces durable callback/session revocation.
func ExpiredPreAuthCookie() *http.Cookie {
	return &http.Cookie{
		Name: PreAuthCookieName, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
	}
}

// ReadPreAuthCookie bounds all Cookie input and rejects duplicate/quoted handles.
// HTTP origin/TLS validation and authoritative proof verification remain separate
// mandatory checks before any callback claim or token exchange. SameSite is not CSRF.
func ReadPreAuthCookie(headers http.Header) (oidcauth.PreAuthCookie, error) {
	fields := headers.Values("Cookie")
	if len(fields) == 0 || len(fields) > maximumCookieHeaderFields {
		return oidcauth.PreAuthCookie{}, ErrPreAuthCookie
	}
	var headerBytes int
	for _, field := range fields {
		if len(field) > maximumCookieHeaderBytes-headerBytes {
			return oidcauth.PreAuthCookie{}, ErrPreAuthCookie
		}
		headerBytes += len(field)
		for _, character := range field {
			if character > 0x7e || character < 0x20 && character != '\t' {
				return oidcauth.PreAuthCookie{}, ErrPreAuthCookie
			}
		}
	}
	var pairs, matches int
	var cookie oidcauth.PreAuthCookie
	for _, field := range fields {
		for pair := range strings.SplitSeq(field, ";") {
			pairs++
			if pairs > maximumCookiePairs {
				return oidcauth.PreAuthCookie{}, ErrPreAuthCookie
			}
			name, value, ok := strings.Cut(strings.Trim(pair, " \t"), "=")
			if strings.Trim(name, " \t") != PreAuthCookieName {
				continue
			}
			matches++
			if !ok || name != PreAuthCookieName || matches > 1 {
				return oidcauth.PreAuthCookie{}, ErrPreAuthCookie
			}
			parsed, err := oidcauth.ParsePreAuthCookie(value)
			if err != nil {
				return oidcauth.PreAuthCookie{}, ErrPreAuthCookie
			}
			cookie = parsed
		}
	}
	if matches != 1 || !cookie.IsValid() {
		return oidcauth.PreAuthCookie{}, ErrPreAuthCookie
	}
	return cookie, nil
}
