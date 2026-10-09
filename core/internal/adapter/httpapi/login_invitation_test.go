package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/invitation"
)

type invitationPreviewFake struct {
	known invitation.Token
	calls int
}

func (fake *invitationPreviewFake) Preview(_ context.Context, token invitation.Token) (invitation.Preview, error) {
	fake.calls++
	if token != fake.known {
		return invitation.Preview{}, invitation.ErrNotFound
	}
	return invitation.Preview{WorkspaceName: "Test ABC", InviterName: "Lan", Email: "member@example.com",
		Role: "auditor", ExpiresAt: time.Date(2026, time.October, 15, 9, 0, 0, 0, time.UTC)}, nil
}

func newInvitationPrepareFixture(t *testing.T) (*InvitationPrepareHandler, *invitationPreviewFake) {
	t.Helper()
	login := newLoginHTTPFixture(t)
	token, err := invitation.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	fake := &invitationPreviewFake{known: token}
	handler, err := NewInvitationPrepareHandler(InvitationPrepareOptions{
		Origin: "https://console.example.test", DeploymentID: deploymentID, Previewer: fake,
		RateLimitSubjects: login.options.RateLimitSubjects, RateLimiter: login, SourceRateLimit: login.options.SourceRateLimit,
		RequestTimeout: time.Second, MaxConcurrentRequests: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, fake
}

func invitationPrepareRequest(ctx context.Context, body string) *http.Request {
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://console.example.test"+InvitationPreparePath,
		strings.NewReader(body))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MeshTransit-Login", "v1")
	request.RemoteAddr = "192.0.2.10:12345"
	return request
}

func TestInvitationPrepareSetsTheBindingCookie(t *testing.T) {
	t.Parallel()
	handler, fake := newInvitationPrepareFixture(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, invitationPrepareRequest(t.Context(), `{"invitation":"`+fake.known.String()+`"}`))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status = %d, headers = %v", response.Code, response.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["workspace_name"] != "Test ABC" ||
		body["role"] != "auditor" || body["email"] != "member@example.com" || len(body) != 5 {
		t.Fatalf("body = %s", response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != InvitationCookieName || cookies[0].Value != fake.known.String() ||
		!cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode ||
		cookies[0].MaxAge != 600 || cookies[0].Domain != "" {
		t.Fatalf("cookies = %+v", cookies)
	}
	if strings.Contains(response.Body.String(), fake.known.String()) {
		t.Fatal("the token must not echo in the body")
	}
}

func TestInvitationPrepareRefusesWithoutDetail(t *testing.T) {
	t.Parallel()
	handler, fake := newInvitationPrepareFixture(t)
	other, _ := invitation.NewToken()
	for name, test := range map[string]struct {
		body   string
		mutate func(*http.Request)
		status int
	}{
		"unknown token":   {body: `{"invitation":"` + other.String() + `"}`, status: http.StatusNotFound},
		"malformed token": {body: `{"invitation":"short"}`, status: http.StatusNotFound},
		"extra field":     {body: `{"invitation":"` + fake.known.String() + `","workspace":"x"}`, status: http.StatusBadRequest},
		"foreign origin": {body: `{"invitation":"` + fake.known.String() + `"}`, status: http.StatusForbidden,
			mutate: func(request *http.Request) { request.Header.Set("Origin", "https://evil.example") }},
		"no login channel": {body: `{"invitation":"` + fake.known.String() + `"}`, status: http.StatusForbidden,
			mutate: func(request *http.Request) { request.Header.Del("X-MeshTransit-Login") }},
		"query": {body: `{"invitation":"` + fake.known.String() + `"}`, status: http.StatusForbidden,
			mutate: func(request *http.Request) { request.URL.RawQuery = "workspace=x" }},
	} {
		request := invitationPrepareRequest(t.Context(), test.body)
		if test.mutate != nil {
			test.mutate(request)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || len(response.Result().Cookies()) != 0 {
			t.Errorf("%s: status %d cookies %d, want %d and none", name, response.Code,
				len(response.Result().Cookies()), test.status)
		}
	}
}

func TestInvitationCookieReadsOnlyACanonicalToken(t *testing.T) {
	t.Parallel()
	token, _ := invitation.NewToken()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	request.AddCookie(&http.Cookie{Name: InvitationCookieName, Value: token.String(), Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
	if got, ok := invitationProofFromRequest(request); !ok || got != token {
		t.Fatal("a canonical invitation cookie must be read")
	}
	bad := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	bad.AddCookie(&http.Cookie{Name: InvitationCookieName, Value: "not-a-token", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
	if _, ok := invitationProofFromRequest(bad); ok {
		t.Fatal("a malformed invitation cookie must be ignored")
	}
	if expired := expiredInvitationCookie(); expired.MaxAge >= 0 || expired.Name != InvitationCookieName {
		t.Fatalf("expired cookie = %+v", expired)
	}
}
