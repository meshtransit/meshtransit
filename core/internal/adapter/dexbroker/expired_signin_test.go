//go:build dexbroker

package dexbroker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dexErrorPage answers like Dex's renderError: WriteHeader with no
// Content-Type, then the page.
func dexErrorPage(status int) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(status)
		_, _ = response.Write([]byte("<p>Requested resource does not exist.</p>"))
	})
}

func TestExpiredSignInReplacesDexCallbackPage(t *testing.T) {
	component := &dexComponent{callbackPath: "/dex/callback", returnURL: "https://app.example.test/"}
	serve := func(handler http.Handler, method, target string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, target, nil)
		handler.ServeHTTP(component.responseFor(recorder, request), request)
		return recorder
	}
	expired := serve(dexErrorPage(http.StatusBadRequest), http.MethodGet, "https://issuer.example/dex/callback?state=old")
	body := expired.Body.String()
	if expired.Code != http.StatusBadRequest || strings.Contains(body, "Requested resource") ||
		!strings.Contains(body, `href="https://app.example.test/"`) || expired.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expired page = %d %q", expired.Code, body)
	}
	// A typed non-HTML answer is left alone.
	jsonError := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte(`{"error":"Requested resource"}`))
	})
	if kept := serve(jsonError, http.MethodGet, "https://issuer.example/dex/callback?state=old"); !strings.Contains(kept.Body.String(), "Requested resource") {
		t.Fatalf("JSON answer replaced: %q", kept.Body.String())
	}
	// Other statuses and paths keep Dex's answer.
	for _, test := range []struct {
		status int
		target string
	}{
		{http.StatusInternalServerError, "https://issuer.example/dex/callback?state=old"},
		{http.StatusBadRequest, "https://issuer.example/dex/auth?client_id=x"},
	} {
		kept := serve(dexErrorPage(test.status), http.MethodGet, test.target)
		if kept.Code != test.status || !strings.Contains(kept.Body.String(), "Requested resource") {
			t.Fatalf("%s: page = %d %q", test.target, kept.Code, kept.Body.String())
		}
	}
}

func TestReturnURLIsTheFirstClientOrigin(t *testing.T) {
	configuration := componentConfiguration{clients: []componentClient{
		{redirectURI: "https://app.example.test/auth/v1/callback"},
	}}
	if got := returnURLOf(configuration); got != "https://app.example.test/" {
		t.Fatalf("returnURLOf() = %q", got)
	}
	if got := returnURLOf(componentConfiguration{}); got != "" {
		t.Fatalf("returnURLOf(empty) = %q", got)
	}
}
