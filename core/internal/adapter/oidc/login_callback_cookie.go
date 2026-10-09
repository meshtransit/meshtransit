package oidc

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

// LoginCallbackCookieName is encrypted no-grant input, never an Account Session.
const LoginCallbackCookieName = "__Host-mt_login_callback"

// ErrLoginCallbackCookie conceals missing, ambiguous or unbounded capture material.
var ErrLoginCallbackCookie = errors.New("oidc: invalid callback capture cookie")

// ReadLoginCallbackCookie releases only bounded canonical encrypted material.
// Never log the returned value; AEAD/time/current-cookie verification is still mandatory.
func ReadLoginCallbackCookie(headers http.Header) (string, error) {
	value, err := boundedCookieValue(headers, LoginCallbackCookieName)
	if err != nil || len(value) == 0 || len(value) > 3800 {
		return "", ErrLoginCallbackCookie
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return "", ErrLoginCallbackCookie
	}
	return value, nil
}

// ExpiredLoginCallbackCookie clears only browser transport, not durable authority.
func ExpiredLoginCallbackCookie() *http.Cookie {
	return &http.Cookie{Name: LoginCallbackCookieName, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: time.Unix(1, 0).UTC(), MaxAge: -1}
}
