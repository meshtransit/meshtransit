package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeLoginNavigationAnswersAFailedNavigationWithAPage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		cause  error
		status int
		title  string
	}{
		{name: "expired or reused link", cause: ErrInvalidBrowserLogin, status: http.StatusBadRequest,
			title: "This sign-in link has expired"},
		{name: "invalid landing", cause: ErrInvalidLoginLanding, status: http.StatusBadRequest,
			title: "This sign-in link has expired"},
		{name: "rate limited", cause: ErrBrowserCaptureLimited, status: http.StatusTooManyRequests,
			title: "Too many sign-in attempts"},
		{name: "saturated", cause: ErrBrowserCaptureSaturated, status: http.StatusServiceUnavailable,
			title: "Sign-in is busy"},
		{name: "unavailable", cause: ErrLoginLandingUnavailable, status: http.StatusServiceUnavailable,
			title: "Sign-in is temporarily unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://control.example.test/auth/v1/callback", nil)
			refused, err := serveLoginNavigation(response, request, func(writer http.ResponseWriter, _ *http.Request) error {
				// A handler may stage a cookie before it fails; it must never be delivered.
				writer.Header().Set("Set-Cookie", "synthetic-private=1")
				return test.cause
			})
			if err != nil || !refused {
				t.Fatalf("serveLoginNavigation() = %t, %v; want a refusal page", refused, err)
			}
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			header := response.Header()
			if header.Get("Set-Cookie") != "" {
				t.Fatal("a staged cookie reached the refusal page")
			}
			if header.Get("Content-Type") != "text/html; charset=utf-8" || header.Get("Cache-Control") != "no-store" ||
				header.Get("X-Frame-Options") != "DENY" || header.Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("refusal page headers = %v", header)
			}
			csp := header.Get("Content-Security-Policy")
			if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "style-src 'sha256-") ||
				strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "script-src") {
				t.Fatalf("refusal page CSP = %q", csp)
			}
			body := response.Body.String()
			if !strings.Contains(body, test.title) || !strings.Contains(body, `href="/"`) ||
				strings.Contains(body, "<script") {
				t.Fatalf("refusal page body = %q", body)
			}
		})
	}
}

func TestServeLoginNavigationKeepsHeadBodiless(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "https://control.example.test/auth/v1/login/continue", nil)
	refused, err := serveLoginNavigation(response, request, func(http.ResponseWriter, *http.Request) error {
		return ErrInvalidLoginLanding
	})
	if err != nil || !refused || response.Code != http.StatusBadRequest || response.Body.Len() != 0 {
		t.Fatalf("HEAD refusal = %t, %v, %d, %d bytes", refused, err, response.Code, response.Body.Len())
	}
}

func TestServeLoginNavigationLeavesSuccessAndPartialOutputAlone(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://control.example.test/auth/v1/callback", nil)

	success := httptest.NewRecorder()
	refused, err := serveLoginNavigation(success, request, func(writer http.ResponseWriter, _ *http.Request) error {
		writer.WriteHeader(http.StatusSeeOther)
		return nil
	})
	if err != nil || refused || success.Code != http.StatusSeeOther {
		t.Fatalf("success = %t, %v, %d", refused, err, success.Code)
	}

	// Once anything was written the transport must still be aborted by the caller.
	partial := httptest.NewRecorder()
	cause := errors.New("synthetic delivery failure")
	refused, err = serveLoginNavigation(partial, request, func(writer http.ResponseWriter, _ *http.Request) error {
		writer.WriteHeader(http.StatusSeeOther)
		return cause
	})
	if !errors.Is(err, cause) || refused || partial.Code != http.StatusSeeOther || partial.Body.Len() != 0 {
		t.Fatalf("partial = %t, %v, %d, %q", refused, err, partial.Code, partial.Body.String())
	}
}

func TestServeLoginNavigationExposesTheTransportController(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://control.example.test/auth/v1/callback", nil)
	_, err := serveLoginNavigation(response, request, func(writer http.ResponseWriter, _ *http.Request) error {
		unwrapper, ok := writer.(interface{ Unwrap() http.ResponseWriter })
		if !ok || unwrapper.Unwrap() != response {
			t.Fatal("handlers lost the ResponseController path to the transport")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
