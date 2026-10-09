package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

var browserPageTestToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

type browserPageChoiceFake struct {
	page  control.BrowserChoicePage
	found bool
	calls int
	want  accountsession.Digest
}

type browserPageApprovalFake struct {
	wantDigest    accountsession.Digest
	wantNetwork   network.ID
	wantWorkspace workspace.ID
	calls         int
}

func (fake *browserPageApprovalFake) ApproveInWorkspace(
	_ context.Context, digest accountsession.Digest, token string, chosenWorkspace workspace.ID, selected network.ID,
) (bool, error) {
	fake.calls++
	return digest == fake.wantDigest && token == browserPageTestToken &&
		selected == fake.wantNetwork && chosenWorkspace == fake.wantWorkspace, nil
}

func (fake *browserPageChoiceFake) ReadNetworks(
	_ context.Context, digest accountsession.Digest, token string,
	selected workspace.ID, _ network.ID, limit int,
) (control.BrowserChoicePage, bool, error) {
	fake.calls++
	if digest != fake.want || token != browserPageTestToken || limit != 100 {
		return control.BrowserChoicePage{}, false, control.ErrInvalidBrowserChoice
	}
	if selected != fake.page.Choices.WorkspaceID {
		return control.BrowserChoicePage{}, false, nil
	}
	return fake.page, fake.found, nil
}

func (fake *browserPageChoiceFake) ReadWorkspaces(_ context.Context, digest accountsession.Digest,
	token string, _ workspace.ID, limit int,
) (control.BrowserWorkspaceChoicePage, bool, error) {
	fake.calls++
	if digest != fake.want || token != browserPageTestToken || limit != 100 {
		return control.BrowserWorkspaceChoicePage{}, false, control.ErrInvalidBrowserChoice
	}
	return control.BrowserWorkspaceChoicePage{Landing: fake.page.Landing,
		Choices: enrollment.BrowserEnrollmentWorkspaceChoices{
			Workspaces: []enrollment.BrowserEnrollmentWorkspaceChoice{
				{WorkspaceID: fake.page.Choices.WorkspaceID, DisplayName: fake.page.Choices.WorkspaceDisplayName},
			},
		}}, fake.found, nil
}

func TestBrowserRegistrationPageRequiresSSOAndEscapesNetworkNames(t *testing.T) {
	t.Parallel()
	page, reader, session := browserRegistrationPageFixture(t)
	path := browserRegistrationPagePrefix + browserPageTestToken
	unauthenticated := serveBrowserRegistrationPage(page, path, "")
	if unauthenticated.Code != http.StatusOK || reader.calls != 0 ||
		!strings.Contains(unauthenticated.Body.String(), "Sign in to continue") ||
		!strings.Contains(unauthenticated.Body.String(), `href="/"`) ||
		strings.Contains(unauthenticated.Body.String(), "client.js") {
		t.Fatalf("unauthenticated landing = (%d, %q)", unauthenticated.Code, unauthenticated.Body.String())
	}
	// One landing reads the Workspaces and each Workspace's Networks together.
	authenticated := serveBrowserRegistrationPage(page, path, session.Encoded())
	if authenticated.Code != http.StatusOK || reader.calls != 2 ||
		!strings.Contains(authenticated.Body.String(), "Choose where to connect") ||
		!strings.Contains(authenticated.Body.String(), "Member Workspace") ||
		!strings.Contains(authenticated.Body.String(), "node-one.example") ||
		!strings.Contains(authenticated.Body.String(), "&lt;img") ||
		strings.Contains(authenticated.Body.String(), "<img") ||
		strings.Contains(authenticated.Body.String(), "<form") {
		t.Fatalf("authenticated landing = (%d, %q)", authenticated.Code, authenticated.Body.String())
	}
	for name, want := range map[string]string{
		"Cache-Control":   "no-store",
		"Referrer-Policy": "no-referrer",
		"X-Frame-Options": "DENY",
		"Content-Type":    "text/html; charset=utf-8",
	} {
		if got := authenticated.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if policy := authenticated.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "form-action 'none'") ||
		!strings.Contains(policy, "frame-ancestors 'none'") {
		t.Fatalf("browser page CSP = %q", policy)
	}
	styles := serveBrowserRegistrationPage(page, browserRegistrationStylesPath, "")
	if styles.Code != http.StatusOK || styles.Header().Get("Content-Type") != "text/css; charset=utf-8" ||
		!strings.Contains(styles.Body.String(), "focus-visible") {
		t.Fatal("read-only landing styles unavailable")
	}
}

func TestBrowserRegistrationPageRejectsInvalidBoundary(t *testing.T) {
	t.Parallel()
	page, reader, session := browserRegistrationPageFixture(t)
	path := browserRegistrationPagePrefix + browserPageTestToken
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "non TLS", mutate: func(r *http.Request) { r.TLS = nil }},
		{name: "foreign host", mutate: func(r *http.Request) { r.Host = "other.example.test" }},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "network=other"; r.RequestURI = r.URL.RequestURI() }},
		{name: "short token", mutate: func(r *http.Request) { r.URL.Path = browserRegistrationPagePrefix + "short"; r.RequestURI = r.URL.Path }},
		{name: "POST", mutate: func(r *http.Request) { r.Method = http.MethodPost }},
		{name: "absolute target", mutate: func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = r.Host }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := newBrowserRegistrationPageRequest(path, session.Encoded())
			test.mutate(request)
			response := httptest.NewRecorder()
			page.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || reader.calls != 0 ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("invalid %s = (%d, calls=%d)", test.name, response.Code, reader.calls)
			}
		})
	}
}

func TestBrowserRegistrationPageServesApprovalScript(t *testing.T) {
	t.Parallel()
	page, _, _ := browserRegistrationPageFixture(t)
	script := serveBrowserRegistrationPage(page, "/register/v1/client.js", "")
	if script.Code != http.StatusOK ||
		script.Header().Get("Content-Type") != "text/javascript; charset=utf-8" ||
		script.Header().Get("Cache-Control") != "no-store" || script.Body.Len() == 0 {
		t.Fatalf("approval script = (%d, %q)", script.Code, script.Header())
	}
}

func TestLoginDispatcherRoutesReadOnlyBrowserRegistrationPage(t *testing.T) {
	t.Parallel()
	page, reader, _ := browserRegistrationPageFixture(t)
	dispatcher, _, _, _ := dispatcherTestGraphWithManagement(t)
	withRegistration, err := NewLoginDispatcherWithRegistration(
		dispatcher.browser, dispatcher.management, page,
	)
	if err != nil {
		t.Fatalf("register browser route: %v", err)
	}
	request := newBrowserRegistrationPageRequest(
		browserRegistrationPagePrefix+browserPageTestToken, "",
	)
	response := httptest.NewRecorder()
	if err := withRegistration.Handle(response, request); err != nil ||
		response.Code != http.StatusOK || reader.calls != 0 ||
		!strings.Contains(response.Body.String(), "Sign in to continue") {
		t.Fatalf("dispatch browser page = (%d, %v, calls=%d)",
			response.Code, err, reader.calls)
	}
}

func TestBrowserRegistrationPageApprovesOnlyWithCurrentSSOAndCSRF(t *testing.T) {
	t.Parallel()
	page, reader, session := browserRegistrationPageFixture(t)
	management, _ := newBrowserManagementFixture(t)
	boundToken, err := accountsession.ParseToken(managementTokenFixture)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := page.keys.ActiveDigest(boundToken)
	if err != nil {
		t.Fatal(err)
	}
	reader.want = digest
	selected := reader.page.Choices.Networks[0].NetworkID
	approval := &browserPageApprovalFake{wantDigest: digest, wantNetwork: selected, wantWorkspace: reader.page.Choices.WorkspaceID}
	page, err = NewBrowserRegistrationPage(BrowserRegistrationPageOptions{
		Origin: management.origin, SessionKeys: page.keys,
		Choices: reader, Management: management, Approval: approval,
		Timeout: 5 * time.Second, Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := browserRegistrationPagePrefix + browserPageTestToken
	landing := serveBrowserRegistrationPage(page, path, session.Encoded())
	if landing.Code != http.StatusServiceUnavailable && landing.Code != http.StatusNotFound {
		t.Fatalf("unrelated SSO Session reached approval form: %d", landing.Code)
	}
	signedOut := serveBrowserRegistrationPage(page, path, "")
	if signedOut.Code != http.StatusOK || !strings.Contains(signedOut.Body.String(), `id="registration-signin" data-path="`+path+`"`) ||
		!strings.Contains(signedOut.Body.String(), `src="/register/v1/client.js"`) ||
		!strings.Contains(signedOut.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("signed-out approval landing = (%d, %q)", signedOut.Code, signedOut.Body.String())
	}
	landing = serveBrowserRegistrationPage(page, path, boundToken.Encoded())
	if landing.Code != http.StatusOK || !strings.Contains(landing.Body.String(), `<form id="registration-form" method="post"`) ||
		!strings.Contains(landing.Body.String(), `value="`+selected.String()+`" data-workspace="`+
			reader.page.Choices.WorkspaceID.String()+`"`) ||
		!strings.Contains(landing.Body.String(), `src="/register/v1/client.js"`) ||
		!strings.Contains(landing.Header().Get("Content-Security-Policy"), "form-action 'self'") ||
		!strings.Contains(landing.Header().Get("Content-Security-Policy"), "script-src 'self'; connect-src 'self'") {
		t.Fatalf("SSO choice form = (%d, %q)", landing.Code, landing.Body.String())
	}
	marker := `name="csrf" value="`
	_, after, ok := strings.Cut(landing.Body.String(), marker)
	if !ok {
		t.Fatal("missing CSRF form field")
	}
	proof, _, ok := strings.Cut(after, `"`)
	if !ok || proof == "" {
		t.Fatal("missing CSRF proof")
	}
	form := url.Values{"csrf": {proof}, "workspace": {reader.page.Choices.WorkspaceID.String()}, "network": {selected.String()}}
	post := browserRegistrationPostRequest(path, boundToken.Encoded(), form)
	response := httptest.NewRecorder()
	page.ServeHTTP(response, post)
	if response.Code != http.StatusOK || approval.calls != 1 ||
		!strings.Contains(response.Body.String(), "Device approved") ||
		strings.Contains(response.Body.String(), proof) ||
		strings.Contains(response.Body.String(), managementTokenFixture) {
		t.Fatalf("approval response = (%d, calls=%d)", response.Code, approval.calls)
	}
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "foreign origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		{name: "missing CSRF", mutate: func(r *http.Request) { r.Body = http.NoBody }},
		{name: "missing Workspace", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(url.Values{"csrf": {proof}, "network": {selected.String()}}.Encode()))
		}},
		{name: "Network in another Workspace", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(url.Values{"csrf": {proof}, "workspace": {"01890f00-0000-7000-8000-000000000104"}, "network": {selected.String()}}.Encode()))
		}},
		{name: "bad CSRF", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(url.Values{"csrf": {"forged"}, "network": {selected.String()}}.Encode()))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := browserRegistrationPostRequest(path, boundToken.Encoded(), form)
			test.mutate(request)
			denied := httptest.NewRecorder()
			page.ServeHTTP(denied, request)
			if denied.Code == http.StatusOK {
				t.Fatalf("invalid %s approved: status=%d calls=%d", test.name, denied.Code, approval.calls)
			}
		})
	}
}

func browserRegistrationPostRequest(path, cookie string, form url.Values) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Host = "console.example.test"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS12}
	request.Header.Set("Cookie", AccountSessionCookieName+"="+cookie)
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func browserRegistrationPageFixture(t *testing.T) (
	*BrowserRegistrationPage, *browserPageChoiceFake, accountsession.Token,
) {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	session, err := accountsession.GenerateToken(deploymentID, 1)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := accountsession.NewDigestKeyID("session-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := accountsession.NewDigestKey(keyID, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := accountsession.NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := keys.ActiveDigest(session)
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := enrollment.ParseBrowserIntentID("01890f00-0000-7000-8000-000000016301")
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000203")
	if err != nil {
		t.Fatal(err)
	}
	reader := &browserPageChoiceFake{
		found: true, want: digest,
		page: control.BrowserChoicePage{
			Landing: enrollment.BrowserIntentLanding{
				IntentID: intentID, State: "pending", Hostname: "node-one.example",
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			Choices: enrollment.BrowserEnrollmentChoices{
				WorkspaceID:          workspaceID,
				WorkspaceDisplayName: "Member Workspace",
				Networks: []enrollment.BrowserEnrollmentNetworkChoice{
					{NetworkID: networkID, DisplayName: `<img src=x onerror=alert(1)>`},
				},
			},
		},
	}
	page, err := NewBrowserRegistrationPage(BrowserRegistrationPageOptions{
		Origin: "https://console.example.test", SessionKeys: keys,
		Choices: reader, Timeout: 5 * time.Second, Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return page, reader, session
}

func newBrowserRegistrationPageRequest(path, cookie string) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	request.Host = "console.example.test"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS12}
	if cookie != "" {
		request.Header.Set("Cookie", AccountSessionCookieName+"="+cookie)
	}
	return request
}

func serveBrowserRegistrationPage(page *BrowserRegistrationPage, path, cookie string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	page.ServeHTTP(response, newBrowserRegistrationPageRequest(path, cookie))
	return response
}
