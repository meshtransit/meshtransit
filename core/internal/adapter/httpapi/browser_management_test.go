package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node/revocation"
	approval "github.com/meshtransit/meshtransit/core/internal/domain/policy/approval"
	policypublication "github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

type browserManagementFixture struct {
	at                                              time.Time
	auth, budgets, revoke, publish, explain, logout int
	approvalGet, approvalList                       int
	capabilityReads                                 int
	sessionRevoked                                  bool
}

func preparedBrowserProof(t *testing.T, browser *BrowserManagement) string {
	t.Helper()
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Token == "" {
		t.Fatal("missing prepared proof", err)
	}
	return body.Token
}

func newBrowserManagementFixture(t *testing.T) (*BrowserManagement, *browserManagementFixture) {
	t.Helper()
	options, fixture := browserManagementTestOptions(t)
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	return browser, fixture
}

func TestBrowserManagementOperationsKeepResourceContracts(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"revoke", "publish", "explain"} {
		t.Run(operation, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			proof := preparedBrowserProof(t, browser)
			path, body := validManagementPath(), `{"reason":"compromised peer"}`
			switch operation {
			case "publish":
				path, body = validPolicyPublishPath(), validPolicyPublishBody()
			case "explain":
				path, body = validAccessGraphExplainPath(), validAccessGraphExplainBody()
			}
			request := browserManagementRequest(t, path, body)
			request.Header.Set("X-MeshTransit-CSRF", proof)
			original := request.Header.Clone()
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := browser.Handle(response, request); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || response.statusWrites != 1 || fixture.auth != 2 || fixture.budgets != 4 ||
				fixture.revoke+fixture.publish+fixture.explain != 1 || !reflect.DeepEqual(original, request.Header) {
				t.Fatal("cookie mutation bypassed/replaced the resource contract or mutated credentials")
			}
			expectedETag := `"2"`
			if operation == "explain" {
				expectedETag = `"6"`
			}
			if response.Header().Get("ETag") != expectedETag || response.Header().Get("Set-Cookie") != "" ||
				response.Header().Get("Www-Authenticate") != "" || strings.Contains(response.Body.String(), proof) ||
				strings.Contains(response.Body.String(), managementTokenFixture) {
				t.Fatal("mutation leaked credentials or changed optimistic version")
			}
		})
	}
}

func TestBrowserManagementReadsPolicyApprovalCatalog(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	snapshot := managementPolicyApprovalSnapshot(t, approval.StatePending)

	getRequest := browserManagementReadRequest(
		t, managementPolicyApprovalCollectionPath()+"/"+snapshot.RequestID().String(),
	)
	getResponse := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(getResponse, getRequest); err != nil {
		t.Fatal(err)
	}
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != `"1"` ||
		getResponse.Header().Get("Cache-Control") != "no-store" || fixture.approvalGet != 1 {
		t.Fatalf("approval get = %d/%+v/%s", getResponse.Code, getResponse.Header(), getResponse.Body.String())
	}

	listRequest := browserManagementReadRequest(
		t, managementPolicyApprovalCollectionPath()+"?state=pending&page_size=1",
	)
	listResponse := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(listResponse, listRequest); err != nil {
		t.Fatal(err)
	}
	var body policyApprovalListEnvelope
	if err := json.Unmarshal(listResponse.Body.Bytes(), &body); err != nil ||
		listResponse.Code != http.StatusOK || len(body.Data) != 1 ||
		body.Data[0].RequestID != snapshot.RequestID().String() || fixture.approvalList != 1 {
		t.Fatalf("approval list = %d/%+v/%v", listResponse.Code, body, err)
	}
	if fixture.auth != 2 || fixture.budgets != 4 ||
		getResponse.Header().Get("Set-Cookie") != "" || listResponse.Header().Get("Set-Cookie") != "" ||
		getResponse.Header().Get("Www-Authenticate") != "" || listResponse.Header().Get("Www-Authenticate") != "" {
		t.Fatal("approval reads bypassed fresh admission or released credential authority")
	}
}

func TestBrowserManagementReadsServerAuthoritativeScopes(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	request := browserManagementReadRequest(
		t, AccountSessionManagementScopesPath+"?page_size=1",
	)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	var body managementScopeEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	expectedSession := managementSessionFixture(t)
	validScope := body.Data.PrincipalID == expectedSession.PrincipalID().String() &&
		body.Data.Workspace.ID == "01890f00-0000-7000-8000-000000000101" &&
		body.Data.Workspace.DisplayName == "Primary" && body.Data.Workspace.DisplayCode == "000000000101" && len(body.Data.Networks) == 1 &&
		body.Data.Networks[0].ID == "01890f00-0000-7000-8000-000000000202" &&
		body.Data.Networks[0].DisplayCode == "000000000202" &&
		reflect.DeepEqual(body.Data.Networks[0].Permissions, []string{"policy.approve"})
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Set-Cookie") != "" || response.Header().Get("Www-Authenticate") != "" ||
		fixture.auth != 1 || fixture.budgets != 2 || !validScope ||
		strings.Contains(response.Body.String(), expectedSession.ID().String()) {
		t.Fatalf("management scopes = %d/%+v/%s", response.Code, body, response.Body.String())
	}

	unsafe := browserManagementReadRequest(t, AccountSessionManagementScopesPath)
	unsafe.Header.Set("X-MeshTransit-CSRF", "unexpected")
	unsafeResponse := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(unsafeResponse, unsafe); !errors.Is(err, ErrInvalidBrowserManagement) ||
		unsafeResponse.statusWrites != 0 || unsafeResponse.Body.Len() != 0 {
		t.Fatal("management-scope read accepted mutation transport", err)
	}
}

func TestBrowserManagementReadsServerAuthoritativeDeploymentCapabilities(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	request := browserManagementReadRequest(t, DeploymentCapabilitiesPath)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	var body deploymentCapabilityResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	validProjection := body.DeploymentProfile == "self_hosted" && body.WorkspaceMode == "single" &&
		body.MaxActiveWorkspaces == 1 && body.WorkspaceCreation == "bootstrap_only" &&
		!body.CloudBilling && !body.PlatformOperations && body.CapabilityRevision == 7
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Set-Cookie") != "" || response.Header().Get("Www-Authenticate") != "" ||
		fixture.auth != 1 || fixture.budgets != 2 || fixture.capabilityReads != 1 || !validProjection ||
		strings.Contains(response.Body.String(), managementSessionFixture(t).ID().String()) {
		t.Fatalf("deployment capabilities = %d/%+v/%s", response.Code, body, response.Body.String())
	}

	unsafe := browserManagementReadRequest(t, DeploymentCapabilitiesPath+"?profile=cloud")
	unsafeResponse := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(unsafeResponse, unsafe); !errors.Is(err, ErrInvalidBrowserManagement) ||
		unsafeResponse.statusWrites != 0 || unsafeResponse.Body.Len() != 0 {
		t.Fatal("deployment capability read accepted client-selected profile", err)
	}
}

func TestManagementScopeQueryIsCanonicalAndWorkspaceBound(t *testing.T) {
	t.Parallel()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatal(err)
	}
	token, err := encodeManagementScopePageToken(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	limit, after, requestErr := parseManagementScopeQuery("page_size=1&page_token="+token, workspaceID)
	if requestErr != nil || limit != 1 || after != networkID {
		t.Fatalf("canonical management-scope query = %d/%v/%+v", limit, after, requestErr)
	}
	limit, after, requestErr = parseManagementScopeQuery("", workspaceID)
	if requestErr != nil || limit != defaultManagementScopePageSize || after.IsValid() {
		t.Fatalf("default management-scope query = %d/%v/%+v", limit, after, requestErr)
	}
	for _, rawQuery := range []string{
		"page_size=01",
		"page_size=101",
		"page_size=1&page_size=2",
		"unknown=1",
		"page_token=not_base64",
		"page_token=" + token,
	} {
		scope := workspaceID
		if rawQuery == "page_token="+token {
			scope = otherWorkspaceID
		}
		if _, _, requestErr := parseManagementScopeQuery(rawQuery, scope); requestErr == nil {
			t.Fatal("noncanonical or cross-Workspace query was accepted", rawQuery)
		}
	}
}

func TestBrowserManagementBuffersMaximumApprovalCatalogPage(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	snapshot := managementPolicyApprovalSnapshot(t, approval.StatePending)
	items := make([]approval.Snapshot, approval.MaximumCatalogPageSize)
	for index := range items {
		items[index] = snapshot
	}
	browser.management.policyApprovalCatalog = &managementPolicyApprovalCatalog{
		list: func(
			_ context.Context,
			_ accountsession.Session,
			_ network.Scope,
			state approval.State,
			limit int,
			_ approval.RequestID,
		) (approval.CatalogPage, error) {
			if state != approval.StatePending || limit != approval.MaximumCatalogPageSize {
				return approval.CatalogPage{}, approval.ErrInvalidCatalogRequest
			}
			return approval.CatalogPage{Items: items}, nil
		},
	}
	request := browserManagementReadRequest(
		t,
		managementPolicyApprovalCollectionPath()+"?state=pending&page_size=100",
	)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || response.Body.Len() <= 32<<10 ||
		response.Body.Len() > maximumBrowserManagementResponseBytes {
		t.Fatalf("maximum approval page response = %d/%d", response.Code, response.Body.Len())
	}
}

func TestBrowserManagementApprovalReadsRejectMutationTransport(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"body", "content type", "csrf", "if match", "idempotency", "transfer",
		"item query", "post item", "get mutation",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			browser, fixture := newBrowserManagementFixture(t)
			path := managementPolicyApprovalCollectionPath() + "/" +
				managementPolicyApprovalSnapshot(t, approval.StatePending).RequestID().String()
			request := browserManagementReadRequest(t, path)
			switch mode {
			case "body":
				request.Body = io.NopCloser(strings.NewReader("{}"))
				request.ContentLength = 2
			case "content type":
				request.Header.Set("Content-Type", "application/json")
			case "csrf":
				request.Header.Set("X-MeshTransit-CSRF", "unexpected")
			case "if match":
				request.Header.Set("If-Match", `"1"`)
			case "idempotency":
				request.Header.Set("Idempotency-Key", "unexpected")
			case "transfer":
				request.TransferEncoding = []string{"chunked"}
			case "item query":
				request.URL.RawQuery = "page_size=1"
				request.RequestURI = request.URL.RequestURI()
			case "post item":
				request = browserManagementRequest(t, path, "{}")
			case "get mutation":
				request = browserManagementReadRequest(t, validManagementPath())
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := browser.Handle(response, request)
			unexpectedEffect := fixture.auth+fixture.budgets+fixture.approvalGet+fixture.approvalList != 0
			if !errors.Is(err, ErrInvalidBrowserManagement) || unexpectedEffect ||
				response.statusWrites != 0 || response.Body.Len() != 0 || len(response.Header()) != 0 {
				t.Fatal("unsafe approval read transport reached authority", err)
			}
		})
	}
}

func TestBrowserManagementLogoutRevokesOnceAndClearsOnlyItsCookie(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	proof := preparedBrowserProof(t, browser)
	request := browserManagementRequest(t, AccountSessionLogoutPath, "{}")
	request.Header.Set("X-MeshTransit-CSRF", proof)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal("logout was not submitted", err)
	}
	values := response.Header().Values("Set-Cookie")
	if response.Code != http.StatusNoContent || response.statusWrites != 1 || response.Body.Len() != 0 ||
		fixture.logout != 1 || fixture.auth != 2 || fixture.budgets != 4 || len(values) != 1 {
		t.Fatal("logout changed mutation, authentication or response ownership")
	}
	cookie, err := http.ParseSetCookie(values[0])
	invalidCookie := err != nil || cookie.Name != AccountSessionCookieName || cookie.Value != "" ||
		cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge >= 0 || cookie.Expires.After(time.Unix(1, 0).UTC())
	if invalidCookie || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("logout did not emit the exact host-only deletion cookie", err)
	}

	replay := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	request = browserManagementRequest(t, AccountSessionLogoutPath, "{}")
	request.Header.Set("X-MeshTransit-CSRF", proof)
	if err := browser.Handle(replay, request); err != nil {
		t.Fatal("revoked-session replay did not receive a bounded denial", err)
	}
	if replay.Code != http.StatusUnauthorized || fixture.logout != 1 || replay.Header().Get("Set-Cookie") != "" {
		t.Fatal("logout replay repeated mutation or renewed cookie authority")
	}
}

func TestBrowserManagementConstructorIsClosedAndCopiesKey(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{
		"nil handler", "nil logout", "nil scopes", "typed nil scopes", "nil capabilities",
		"typed nil capabilities", "typed nil clock", "nil sessions",
		"short key", "zero key", "bad key id",
		"short ttl", "fraction ttl", "long ttl", "http", "path", "query", "userinfo", "uppercase",
		"default port", "empty port", "leading port", "bad dns",
	} {
		t.Run(invalid, func(t *testing.T) {
			options, fixture := browserManagementTestOptions(t)
			switch invalid {
			case "nil handler":
				options.Management = nil
			case "nil logout":
				options.Logout = nil
			case "nil scopes":
				options.Scopes = nil
			case "typed nil scopes":
				options.Scopes = (*sessioncontext.Service)(nil)
			case "nil capabilities":
				options.Capabilities = nil
			case "typed nil capabilities":
				options.Capabilities = (*sessioncontext.CapabilityService)(nil)
			case "typed nil clock":
				options.Clock = (*browserManagementFixture)(nil)
			case "nil sessions":
				options.Management.sessions = managementSessionAuthenticatorFunc(nil)
			case "short key":
				options.Key.Material = options.Key.Material[:31]
			case "zero key":
				options.Key.Material = make([]byte, 32)
			case "bad key id":
				options.Key.ID = "key.id"
			case "short ttl":
				options.ProofLifetime = 29 * time.Second
			case "fraction ttl":
				options.ProofLifetime = 30*time.Second + time.Nanosecond
			case "long ttl":
				options.ProofLifetime = 121 * time.Second
			case "http":
				options.Origin = "http://console.example.test"
			case "path":
				options.Origin += "/"
			case "query":
				options.Origin += "?"
			case "userinfo":
				options.Origin = "https://user@console.example.test"
			case "uppercase":
				options.Origin = "https://Console.example.test"
			case "default port":
				options.Origin += ":443"
			case "empty port":
				options.Origin += ":"
			case "leading port":
				options.Origin += ":08443"
			case "bad dns":
				options.Origin = "https://-console.example.test"
			}
			_, constructionErr := NewBrowserManagement(options)
			if !errors.Is(constructionErr, ErrInvalidBrowserManagement) || fixture.auth+fixture.budgets != 0 {
				t.Fatal("invalid constructor used dependencies or was accepted", constructionErr)
			}
		})
	}
	options, _ := browserManagementTestOptions(t)
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	clear(options.Key.Material)
	if browser.key == ([32]byte{}) {
		t.Fatal("constructor retained caller key storage")
	}
	for _, value := range []any{options, browser} {
		if strings.Contains(fmt.Sprintf("%v %#v", value, value), "console.example.test") {
			t.Fatal("configuration formatting exposed topology")
		}
	}
	if _, err := json.Marshal(options); err == nil {
		t.Fatal("options serialized secrets")
	}
}

func TestBrowserManagementRejectsIngressBeforeEffects(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{
		"tls absent", "tls incomplete", "tls old", "get", "head", "options", "host", "origin absent",
		"origin foreign", "origin duplicate", "marker absent", "marker duplicate", "auth", "empty auth",
		"header alias", "query", "raw path", "authority", "userinfo", "force query", "fragment", "request uri",
		"transfer", "trailer", "negative length", "oversize", "content encoding", "expect", "upgrade", "fetch empty",
		"fetch foreign", "fetch user", "body typed nil", "cookie duplicate", "unknown", "prepare csrf",
	} {
		t.Run(invalid, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			request := browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")
			switch invalid {
			case "tls absent":
				request.TLS = nil
			case "tls incomplete":
				request.TLS.HandshakeComplete = false
			case "tls old":
				request.TLS.Version = tls.VersionTLS11
			case "get":
				request.Method = http.MethodGet
			case "head":
				request.Method = http.MethodHead
			case "options":
				request.Method = http.MethodOptions
			case "host":
				request.Host = "other.example.test"
			case "origin absent":
				request.Header.Del("Origin")
			case "origin foreign":
				request.Header.Set("Origin", "https://other.example.test")
			case "origin duplicate":
				request.Header.Add("Origin", browser.origin)
			case "marker absent":
				request.Header.Del("X-MeshTransit-Session")
			case "marker duplicate":
				request.Header.Add("X-MeshTransit-Session", "v1")
			case "auth":
				request.Header.Set("Authorization", "Bearer "+managementTokenFixture)
			case "empty auth":
				request.Header["Authorization"] = []string{}
			case "header alias":
				request.Header["origin"] = []string{browser.origin}
			case "query":
				request.URL.RawQuery = "x=1"
			case "raw path":
				request.URL.RawPath = request.URL.Path
			case "authority":
				request.URL.Host = request.Host
			case "userinfo":
				request.URL.User = url.User("user")
			case "force query":
				request.URL.ForceQuery = true
			case "fragment":
				request.URL.Fragment = "x"
			case "request uri":
				request.RequestURI += "?"
			case "transfer":
				request.TransferEncoding = []string{"chunked"}
			case "trailer":
				request.Trailer = http.Header{"X-Test": {"x"}}
			case "negative length":
				request.ContentLength = -1
			case "oversize":
				request.ContentLength = maximumManagementBodyBytes + 1
			case "content encoding":
				request.Header.Set("Content-Encoding", "gzip")
			case "expect":
				request.Header.Set("Expect", "100-continue")
			case "upgrade":
				request.Header.Set("Upgrade", "websocket")
			case "fetch empty":
				request.Header["Sec-Fetch-Mode"] = []string{}
			case "fetch foreign":
				request.Header.Set("Sec-Fetch-Site", "cross-site")
			case "fetch user":
				request.Header.Set("Sec-Fetch-User", "?1")
			case "body typed nil":
				request.Body = (*browserManagementNilBody)(nil)
			case "cookie duplicate":
				request.Header.Add("Cookie", request.Header.Get("Cookie"))
			case "unknown":
				request.URL.Path, request.RequestURI = "/unknown", "/unknown"
			case "prepare csrf":
				request.Header.Set("X-MeshTransit-CSRF", "unexpected")
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := browser.Handle(response, request)
			unexpectedResponse := response.statusWrites != 0 || response.Body.Len() != 0 || len(response.Header()) != 0
			unexpectedAuthority := fixture.auth+fixture.revoke+fixture.publish+fixture.explain+fixture.logout != 0
			if err == nil || unexpectedResponse || unexpectedAuthority {
				t.Fatal("invalid ingress released authority/response", err)
			}
			if invalid != "cookie duplicate" && fixture.budgets != 0 {
				t.Fatal("structural rejection spent shared budget")
			}
		})
	}
}

type browserManagementNilBody struct{}

func (*browserManagementNilBody) Read([]byte) (int, error) { panic("typed nil body used") }
func (*browserManagementNilBody) Close() error             { panic("typed nil body closed") }

func TestBrowserManagementProofAndAuthorityBothRequired(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"missing", "tampered", "changed cookie", "expiry", "authority revoked", "authority unavailable",
	} {
		t.Run(mode, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			proof := preparedBrowserProof(t, browser)
			request := browserManagementRequest(t, validManagementPath(), `{}`)
			switch mode {
			case "missing":
				proof = ""
			case "tampered":
				proof = "X" + proof[1:]
			case "changed cookie":
				changedToken := strings.Replace(
					managementTokenFixture,
					"AQE",
					"AgI",
					1,
				)
				request.Header.Set("Cookie", AccountSessionCookieName+"="+changedToken)
			case "expiry":
				fixture.at = fixture.at.Add(time.Minute)
			case "authority revoked", "authority unavailable":
				browser.management.sessions = managementSessionAuthenticatorFunc(func(
					context.Context,
					accountsession.Token,
				) (accountsession.Session, error) {
					fixture.auth++
					if mode == "authority unavailable" {
						return accountsession.Session{}, accountsession.ErrAuthenticationUnavailable
					}
					return accountsession.Session{}, accountsession.ErrUnauthenticated
				})
			}
			request.Header.Set("X-MeshTransit-CSRF", proof)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := browser.Handle(response, request); err != nil {
				t.Fatal(err)
			}
			expected := http.StatusUnauthorized
			if mode == "authority unavailable" {
				expected = http.StatusServiceUnavailable
			}
			invalidStatus := response.Code != expected || response.statusWrites != 1
			unexpectedAuthority := fixture.revoke+fixture.publish+fixture.explain != 0
			if invalidStatus || unexpectedAuthority || response.Header().Get("Www-Authenticate") != "" {
				t.Fatal("proof replaced current authority or invited Bearer fallback")
			}
			if mode != "authority revoked" && mode != "authority unavailable" && fixture.auth != 1 {
				t.Fatal("invalid proof reached durable authentication")
			}
		})
	}
	options, fixture := browserManagementTestOptions(t)
	response := httptest.NewRecorder()
	options.Management.ServeHTTP(response, browserManagementRequest(t, validManagementPath(), `{}`))
	if response.Code != http.StatusUnauthorized || fixture.auth != 0 || fixture.revoke != 0 {
		t.Fatal("Bearer entry point accepted cookie authority")
	}
}

func TestBrowserManagementPrepareBudgetsPrecedeEntropy(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"source denied", "session denied", "unavailable", "wrong capacity", "large retry", "cancelled",
		"entropy failed", "zero entropy",
	} {
		t.Run(mode, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			browser.management.rateLimiter = managementRateLimiterFunc(func(
				_ context.Context,
				_ ratelimit.Subject,
				policy ratelimit.Policy,
			) (ratelimit.Decision, error) {
				fixture.budgets++
				switch mode {
				case "source denied", "session denied":
					if mode == "source denied" || fixture.budgets == 2 {
						return ratelimit.NewDecision(
							false,
							policy.Capacity(),
							0,
							time.Second,
						)
					}
				case "unavailable":
					return ratelimit.Decision{}, errors.New("private-budget-diagnostic")
				case "wrong capacity":
					return ratelimit.NewDecision(
						true,
						policy.Capacity()+1,
						0,
						0,
					)
				case "large retry":
					return ratelimit.NewDecision(
						false,
						policy.Capacity(),
						0,
						25*time.Hour,
					)
				case "cancelled":
					cancel()
				}
				return ratelimit.NewDecision(
					true,
					policy.Capacity(),
					0,
					0,
				)
			})
			entropy := &browserManagementEntropy{zero: mode == "zero entropy"}
			browser.entropy = entropy
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := browser.Handle(response, browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}").WithContext(ctx))
			if err == nil || response.statusWrites != 0 || len(response.Header()) != 0 ||
				fixture.revoke+fixture.publish+fixture.explain != 0 {
				t.Fatal("failed admission released prepare", err)
			}
			if mode != "entropy failed" && mode != "zero entropy" && entropy.calls != 0 {
				t.Fatal("entropy preceded both budgets")
			}
			if mode == "source denied" && fixture.auth != 0 {
				t.Fatal("source denial reached authority")
			}
		})
	}
}

type browserManagementEntropy struct {
	calls int
	zero  bool
}

func (entropy *browserManagementEntropy) Read(target []byte) (int, error) {
	entropy.calls++
	if entropy.zero {
		clear(target)
		return len(target), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestBrowserManagementChecksTimeBeforeMutationAndSubmission(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"before mutation", "after commit", "cancel after commit"} {
		t.Run(mode, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			proof := preparedBrowserProof(t, browser)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "before mutation" {
				browser.management.rateLimiter = managementRateLimiterFunc(func(
					context.Context,
					ratelimit.Subject,
					ratelimit.Policy,
				) (ratelimit.Decision, error) {
					fixture.budgets++
					if fixture.budgets == 4 {
						fixture.at = fixture.at.Add(time.Minute)
					}
					return ratelimit.NewDecision(
						true,
						browser.management.sessionPolicy.Capacity(),
						0,
						0,
					)
				})
			} else {
				browser.management.revocations = managementDeviceRevokerFunc(func(
					_ context.Context,
					command revocation.Command,
				) (revocation.Result, error) {
					fixture.revoke++
					if mode == "after commit" {
						fixture.at = fixture.at.Add(time.Minute)
					} else {
						cancel()
					}
					return managementResultFixture(t, command), nil
				})
			}
			request := browserManagementRequest(t, validManagementPath(), `{"reason":"compromised peer"}`).WithContext(ctx)
			request.Header.Set("X-MeshTransit-CSRF", proof)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			managementErr := browser.Handle(response, request)
			unexpectedResponse := response.statusWrites != 0 || response.Body.Len() != 0 || len(response.Header()) != 0
			if !errors.Is(managementErr, ErrBrowserManagementUnavailable) || unexpectedResponse {
				t.Fatal("late time/cancellation released candidate", managementErr)
			}
			expected := 1
			if mode == "before mutation" {
				expected = 0
			}
			if fixture.revoke != expected || fixture.auth != 2 {
				t.Fatal("time check retried, reauthenticated after commit, or crossed expired mutation seam")
			}
		})
	}
}

func TestBrowserManagementOwnsDeadlinesAndClosedDelivery(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"parent deadline", "read unsupported", "write unsupported", "short write", "write error",
		"initial cookie", "initial cors", "combined headers",
	} {
		t.Run(mode, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			request := browserManagementRequest(t, AccountSessionCSRFPreparePath, `{}`)
			response := &landingDeliveryRecorder{
				continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
			}
			switch mode {
			case "parent deadline":
				ctx, cancel := context.WithTimeout(request.Context(), 500*time.Millisecond)
				defer cancel()
				request = request.WithContext(ctx)
			case "read unsupported":
				response.failRead = true
			case "write unsupported":
				response.failWrite = true
			case "short write":
				response.onWrite = func(body []byte) (int, error) { return len(body) - 1, nil }
			case "write error":
				response.onWrite = func([]byte) (int, error) { return 0, errors.New("private-cookie-writer-diagnostic") }
			case "initial cookie":
				response.Header().Set("Set-Cookie", "unexpected")
			case "initial cors":
				response.Header().Set("Access-Control-Allow-Origin", browser.origin)
			case "combined headers":
				response.Header().Set("X-Padding", strings.Repeat("x", 16370))
			}
			initial := response.Header().Clone()
			err := browser.Handle(response, request)
			switch mode {
			case "parent deadline":
				deadline, ok := request.Context().Deadline()
				if err != nil || !ok || !response.read.Equal(deadline) || !response.write.Equal(deadline) {
					t.Fatal("parent deadline was extended", err)
				}
			case "short write", "write error":
				invalidDelivery := !errors.Is(err, ErrBrowserManagementDelivery) || response.statusWrites != 1
				if invalidDelivery || strings.Contains(err.Error(), "diagnostic") {
					t.Fatal("delivery failure leaked/retried/rewrote", err)
				}
			default:
				unexpectedResponse := response.statusWrites != 0 || response.Body.Len() != 0
				if err == nil || unexpectedResponse || !reflect.DeepEqual(initial, response.Header()) {
					t.Fatal("pre-release rejection altered response", err)
				}
				if mode != "combined headers" && fixture.auth+fixture.budgets != 0 {
					t.Fatal("failed transport reached effects")
				}
			}
		})
	}
	var owner BrowserManagement
	ownerErr := owner.Handle(httptest.NewRecorder(), browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}"))
	if !errors.Is(ownerErr, ErrBrowserManagementUnavailable) {
		t.Fatal("zero owner accepted request")
	}
}

func TestBrowserManagementCapacityHeldThroughActualDelivery(t *testing.T) {
	// Process-wide leak qualification must remain serial, outside synctest.
	defer goleak.VerifyNone(t)
	browser, fixture := newBrowserManagementFixture(t)
	browser.slots = make(chan struct{}, 1)
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	response := &landingDeliveryRecorder{
		continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
		onWrite: func(body []byte) (int, error) {
			close(entered)
			<-release
			return len(body), nil
		},
	}
	request := browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")
	go func() { joined <- browser.Handle(response, request) }()
	<-entered
	second := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	err := browser.Handle(second, browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}"))
	close(release)
	firstErr := <-joined
	invalidOwnership := firstErr != nil || !errors.Is(err, ErrBrowserManagementSaturated)
	unexpectedEffects := second.statusWrites != 0 || fixture.auth != 1 || fixture.budgets != 2
	if invalidOwnership || unexpectedEffects {
		t.Fatal("capacity released before real submission or queued", err, firstErr)
	}
	if err := browser.Handle(second, browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")); err != nil {
		t.Fatal("ownership token was leaked", err)
	}
}

func TestBrowserManagementLatePrepareAndMutationDeliveryRemainClosed(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	correlations := browser.management.correlationIDs
	browser.management.correlationIDs = managementPublicIDGeneratorFunc(func() (publicid.ID, error) {
		fixture.at = fixture.at.Add(time.Minute - 500*time.Millisecond)
		return correlations.NewID()
	})
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	prepareErr := browser.Handle(response, browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}"))
	if !errors.Is(prepareErr, ErrBrowserManagementUnavailable) || response.statusWrites != 0 {
		t.Fatal("late prepare released nearly expired proof", prepareErr)
	}

	browser, fixture = newBrowserManagementFixture(t)
	proof := preparedBrowserProof(t, browser)
	var logs bytes.Buffer
	browser.management.logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	delivery := &landingDeliveryRecorder{
		continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
		onWrite:                    func([]byte) (int, error) { return 0, errors.New("private-writer-diagnostic") },
	}
	request := browserManagementRequest(t, validManagementPath(), `{"reason":"compromised peer"}`)
	request.Header.Set("X-MeshTransit-CSRF", proof)
	deliveryErr := browser.Handle(delivery, request)
	unexpectedMutationEffects := fixture.revoke != 1 || delivery.statusWrites != 1
	if !errors.Is(deliveryErr, ErrBrowserManagementDelivery) || unexpectedMutationEffects {
		t.Fatal("uncertain committed delivery retried/rewrote", deliveryErr)
	}
	for _, secret := range []string{"private-writer-diagnostic", managementTokenFixture, proof} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("resident authority or transport diagnostics leaked into logs")
		}
	}
}

type browserManagementClockFunc func() time.Time

func (clock browserManagementClockFunc) Now() time.Time { return clock() }

func TestBrowserManagementCancellationDuringFinalClockWithholdsResponse(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"prepare", "mutation"} {
		t.Run(operation, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			proof := preparedBrowserProof(t, browser)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			installFinalClock := func() {
				calls := 0
				browser.clock = browserManagementClockFunc(func() time.Time {
					calls++
					if calls == 2 {
						cancel()
					}
					return fixture.at
				})
			}
			path, body := AccountSessionCSRFPreparePath, "{}"
			if operation == "prepare" {
				correlations := browser.management.correlationIDs
				browser.management.correlationIDs = managementPublicIDGeneratorFunc(func() (publicid.ID, error) {
					installFinalClock()
					return correlations.NewID()
				})
			} else {
				path, body = validManagementPath(), `{"reason":"compromised peer"}`
				browser.management.revocations = managementDeviceRevokerFunc(func(
					_ context.Context,
					command revocation.Command,
				) (revocation.Result, error) {
					fixture.revoke++
					installFinalClock()
					return managementResultFixture(t, command), nil
				})
			}
			request := browserManagementRequest(t, path, body).WithContext(ctx)
			if operation == "mutation" {
				request.Header.Set("X-MeshTransit-CSRF", proof)
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := browser.Handle(response, request)
			unexpectedResponse := response.statusWrites != 0 || response.Body.Len() != 0 || len(response.Header()) != 0
			if !errors.Is(err, ErrBrowserManagementUnavailable) || unexpectedResponse {
				t.Fatal("cancellation during final clock released candidate", err)
			}
			if operation == "mutation" && fixture.revoke != 1 {
				t.Fatal("final cancellation rewrote/retried committed authority")
			}
		})
	}
}

func TestBrowserManagementVerifiedHTTPS(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := browser.Handle(w, r); err != nil {
			http.Error(w, "private management rejected", http.StatusForbidden)
		}
	}))
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.ReadTimeout = 3 * time.Second
	server.Config.WriteTimeout = 3 * time.Second
	server.Config.IdleTimeout = 3 * time.Second
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("HTTPS fixture lacks verified test-CA trust")
	}
	if transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HTTPS fixture lacks verified test-CA trust")
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	t.Cleanup(transport.CloseIdleConnections)
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		server.URL+AccountSessionCSRFPreparePath,
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatal(err)
	}
	synthetic := browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")
	request.Host, request.Header = synthetic.Host, synthetic.Header.Clone()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumBrowserManagementResponseBytes+1))
	closeErr := response.Body.Close()
	invalidTransport := readErr != nil || closeErr != nil
	invalidHeaders := response.StatusCode != http.StatusOK || response.Header.Get("Set-Cookie") != "" ||
		response.Header.Get("Cache-Control") != "no-store"
	if invalidTransport || invalidHeaders || len(body) > maximumBrowserManagementResponseBytes {
		t.Fatal("verified HTTPS preparation changed private contract", readErr, closeErr)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil || len(payload) != 2 || payload["csrf_token"] == nil {
		t.Fatal("HTTPS preparation omitted bounded proof", err)
	}
}

func (fixture *browserManagementFixture) Now() time.Time { return fixture.at }

func browserManagementTestOptions(t *testing.T) (BrowserManagementOptions, *browserManagementFixture) {
	t.Helper()
	fixture := &browserManagementFixture{at: time.Date(
		2026,
		time.September,
		16,
		0,
		0,
		0,
		0,
		time.UTC,
	)}
	options := validManagementHandlerOptions(t)
	options.Sessions = managementSessionAuthenticatorFunc(func(
		ctx context.Context,
		token accountsession.Token,
	) (accountsession.Session, error) {
		fixture.auth++
		if ctx.Err() != nil || token.Encoded() != managementTokenFixture {
			t.Error("browser Session authentication lost context or exact cookie")
		}
		if fixture.sessionRevoked {
			return accountsession.Session{}, accountsession.ErrUnauthenticated
		}
		return managementSessionFixture(t), nil
	})
	options.RateLimiter = managementRateLimiterFunc(func(
		ctx context.Context,
		_ ratelimit.Subject,
		policy ratelimit.Policy,
	) (ratelimit.Decision, error) {
		fixture.budgets++
		if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
			t.Error("browser budget lost finite live context")
		}
		return ratelimit.NewDecision(
			true,
			policy.Capacity(),
			policy.Capacity()-1,
			0,
		)
	})
	options.Revocations = managementDeviceRevokerFunc(func(
		_ context.Context,
		command revocation.Command,
	) (revocation.Result, error) {
		fixture.revoke++
		return managementResultFixture(t, command), nil
	})
	options.PolicyPublications = managementPolicyPublisherFunc(func(
		_ context.Context,
		command policypublication.Command,
	) (policypublication.Result, error) {
		fixture.publish++
		return managementPolicyResultFixture(t, command), nil
	})
	explainer, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: managementAccessGraphReaderFunc(func(
			_ context.Context,
			_ accountsession.Session,
			query accessgraph.Query,
			_ time.Time,
		) (accessgraph.Snapshot, error) {
			fixture.explain++
			return managementAccessGraphSnapshot(t, query), nil
		}),
		Clock: accessgraph.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	options.PolicyExplanations = explainer
	snapshot := managementPolicyApprovalSnapshot(t, approval.StatePending)
	options.PolicyApprovalCatalog = &managementPolicyApprovalCatalog{
		get: func(
			_ context.Context,
			_ accountsession.Session,
			_ network.Scope,
			requestID approval.RequestID,
		) (approval.Snapshot, error) {
			fixture.approvalGet++
			if requestID != snapshot.RequestID() {
				return approval.Snapshot{}, approval.ErrRequestNotFound
			}
			return snapshot, nil
		},
		list: func(
			_ context.Context,
			_ accountsession.Session,
			_ network.Scope,
			state approval.State,
			limit int,
			_ approval.RequestID,
		) (approval.CatalogPage, error) {
			fixture.approvalList++
			if state != approval.StatePending || limit != 1 {
				return approval.CatalogPage{}, approval.ErrInvalidCatalogRequest
			}
			return approval.CatalogPage{Items: []approval.Snapshot{snapshot}}, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	logout := managementAccountSessionLogoutFunc(func(ctx context.Context, token accountsession.Token) (bool, error) {
		fixture.logout++
		if ctx.Err() != nil || token.Encoded() != managementTokenFixture || fixture.sessionRevoked {
			t.Error("logout lost live exact cookie authority")
		}
		fixture.sessionRevoked = true
		return true, nil
	})
	session := managementSessionFixture(t)
	workspaceID, ok := session.LoginWorkspaceID()
	if !ok {
		t.Fatal("management Session has no login Workspace")
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := sessioncontext.NewManagementScope(
		networkID, "Production", []authorization.Permission{authorization.PermissionPolicyApprove},
	)
	if err != nil {
		t.Fatal(err)
	}
	scope, err = scope.WithDisplayCode(identity.DisplayCode("000000000202"))
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := sessioncontext.NewService(
		browserManagementScopeReader{result: sessioncontext.ReadResult{
			WorkspaceID: workspaceID, WorkspaceDisplayName: "Primary",
			WorkspaceDisplayCode: identity.DisplayCode("000000000101"), Scopes: []sessioncontext.ManagementScope{scope},
		}},
		fixture,
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := sessioncontext.NewCapabilityService(
		browserManagementCapabilityReader{
			fixture: fixture,
			result: sessioncontext.CapabilityReadResult{
				DeploymentID: session.DeploymentID(), Profile: deployment.ProfileSelfHosted, Revision: 7,
			},
		},
		fixture,
	)
	if err != nil {
		t.Fatal(err)
	}
	return BrowserManagementOptions{Management: handler, Logout: logout, Scopes: scopes, Capabilities: capabilities,
		Origin:       "https://console.example.test",
		DeploymentID: managementSessionFixture(t).DeploymentID(), Clock: fixture,
		Key:           BrowserLoginKey{ID: "browser-session-csrf-v1", Material: bytes.Repeat([]byte{0x54}, 32)},
		ProofLifetime: time.Minute}, fixture
}

type browserManagementCapabilityReader struct {
	fixture *browserManagementFixture
	result  sessioncontext.CapabilityReadResult
}

func (reader browserManagementCapabilityReader) ReadDeploymentCapabilities(
	context.Context,
	accountsession.Session,
	time.Time,
) (sessioncontext.CapabilityReadResult, error) {
	reader.fixture.capabilityReads++
	return reader.result, nil
}

type browserManagementScopeReader struct{ result sessioncontext.ReadResult }

func (reader browserManagementScopeReader) ReadManagementScopes(
	context.Context,
	accountsession.Session,
	network.ID,
	int,
	time.Time,
) (sessioncontext.ReadResult, error) {
	return reader.result, nil
}

type managementAccountSessionLogoutFunc func(context.Context, accountsession.Token) (bool, error)

func (function managementAccountSessionLogoutFunc) Logout(
	ctx context.Context,
	token accountsession.Token,
) (bool, error) {
	return function(ctx, token)
}

func browserManagementRequest(t *testing.T, path, body string) *http.Request {
	t.Helper()
	request := newManagementRequest(
		t,
		http.MethodPost,
		path,
		body,
	)
	request.Header.Del("Authorization")
	request.Host, request.RemoteAddr = "console.example.test", "192.0.2.10:12345"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("X-MeshTransit-Session", "v1")
	request.Header.Set("Cookie", AccountSessionCookieName+"="+managementTokenFixture)
	return request
}

func browserManagementReadRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	request := browserManagementRequest(t, path, "")
	request.Method = http.MethodGet
	request.Body = http.NoBody
	request.ContentLength = 0
	request.Header.Del("Content-Type")
	request.Header.Del("Idempotency-Key")
	request.Header.Del("If-Match")
	return request
}

func TestBrowserManagementPreparationNeverIssuesAuthority(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.auth != 0 || fixture.budgets != 0 || fixture.revoke != 0 ||
		fixture.publish != 0 || fixture.explain != 0 {
		t.Fatal("constructor invoked an application/budget effect")
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	request := browserManagementRequest(t, AccountSessionCSRFPreparePath, "{}")
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.statusWrites != 1 || response.Code != http.StatusOK || fixture.auth != 1 || fixture.budgets != 2 {
		t.Fatal("prepare did not own bounded authenticated shared admission")
	}
	if fixture.revoke != 0 || fixture.publish != 0 || fixture.explain != 0 ||
		response.Header().Get("Set-Cookie") != "" ||
		response.Header().Get("Location") != "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("prepare mutated authority/cookie/navigation")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body) != 2 {
		t.Fatal("prepare exposed more than proof and expiry", err)
	}
	missingProof := body["csrf_token"] == nil || body["expires_at"] == nil
	if missingProof || strings.Contains(response.Body.String(), managementTokenFixture) {
		t.Fatal("prepare omitted proof or exposed bearer")
	}
}
