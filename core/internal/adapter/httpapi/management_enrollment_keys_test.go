package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const enrollmentKeyTestKey = "01890f00-0000-7000-8000-000000000a01"

// enrollmentKeyTestToken is a synthetic secret: the bytes 0 to 31.
var enrollmentKeyTestToken = func() string {
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(secret[:])
}()

func enrollmentKeysTestPath(rest string) string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + networkMemberTestNetwork +
		"/enrollment-keys" + rest
}

type enrollmentKeyStub struct {
	issued  []enrollmentkey.IssueRequest
	lists   int
	revoked []enrollment.CredentialID
	failure error
}

func (stub *enrollmentKeyStub) key(t testing.TB, state enrollmentkey.State) enrollmentkey.Key {
	id, _ := enrollment.ParseCredentialID(enrollmentKeyTestKey)
	issuer, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	created := time.Date(2026, time.October, 16, 8, 0, 0, 0, time.UTC)
	params := enrollmentkey.KeyParams{
		ID: id, IssuedBy: issuer, CreatedAt: created, ExpiresAt: created.Add(24 * time.Hour), State: state,
		DeviceLifetime: enrollment.NeverExpiringDeviceLifetime(), Description: "build server",
	}
	switch state {
	case enrollmentkey.StateUsed:
		params.DeviceID, _ = node.ParseID("01890f00-0000-7000-8000-000000000c01")
		params.DeviceName = "build-1"
	case enrollmentkey.StateRevoked:
		params.RevokedAt = created.Add(time.Hour)
	}
	key, err := enrollmentkey.NewKey(params)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	return key
}

func (stub *enrollmentKeyStub) Issue(_ context.Context, _ accountsession.Session,
	request enrollmentkey.IssueRequest) (enrollmentkey.Issued, error) {
	stub.issued = append(stub.issued, request)
	if stub.failure != nil {
		return enrollmentkey.Issued{}, stub.failure
	}
	token, _ := enrollment.ParseCredentialToken(enrollmentKeyTestToken)
	key := stub.key(&testing.T{}, enrollmentkey.StateActive)
	presentation, _ := enrollment.NewCredentialPresentation(key.ID(), token)
	return enrollmentkey.NewIssued(key, presentation)
}

func (stub *enrollmentKeyStub) List(context.Context, accountsession.Session, network.Scope) ([]enrollmentkey.Key, error) {
	stub.lists++
	if stub.failure != nil {
		return nil, stub.failure
	}
	return []enrollmentkey.Key{stub.key(&testing.T{}, enrollmentkey.StateUsed)}, nil
}

func (stub *enrollmentKeyStub) Revoke(_ context.Context, _ accountsession.Session, _ network.Scope,
	id enrollment.CredentialID, _ publicid.ID) (enrollmentkey.Key, error) {
	stub.revoked = append(stub.revoked, id)
	if stub.failure != nil {
		return enrollmentkey.Key{}, stub.failure
	}
	return stub.key(&testing.T{}, enrollmentkey.StateRevoked), nil
}

func TestParseEnrollmentKeyPath(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		method, path string
		valid        bool
		operation    string
	}{
		{http.MethodGet, enrollmentKeysTestPath(""), true, "enrollment_key_list"},
		{http.MethodPost, enrollmentKeysTestPath("/actions/create"), true, "enrollment_key_create"},
		{http.MethodPost, enrollmentKeysTestPath("/" + enrollmentKeyTestKey + "/actions/revoke"), true,
			"enrollment_key_revoke"},
		{http.MethodGet, enrollmentKeysTestPath("?state=active"), false, ""},
		{http.MethodPost, enrollmentKeysTestPath("/actions/delete"), false, ""},
		{http.MethodPost, enrollmentKeysTestPath("/" + strings.ToUpper(enrollmentKeyTestKey) + "/actions/revoke"),
			false, ""},
		{http.MethodPost, enrollmentKeysTestPath("/" + enrollmentKeyTestKey), false, ""},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseEnrollmentKeyPath(request)
		if ok != test.valid {
			t.Errorf("%s %s: matched = %t, want %t", test.method, test.path, ok, test.valid)
			continue
		}
		if ok && (path.operation() != test.operation || !isEnrollmentKeyOperation(request)) {
			t.Errorf("%s: operation %s admitted %t", test.path, path.operation(), isEnrollmentKeyOperation(request))
		}
	}
	if isEnrollmentKeyOperation(httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		enrollmentKeysTestPath(""), nil)) {
		t.Error("POST to the key list was admitted")
	}
}

func TestEnrollmentKeyHTTPBoundary(t *testing.T) {
	t.Parallel()
	create := enrollmentKeysTestPath("/actions/create")
	revoke := enrollmentKeysTestPath("/" + enrollmentKeyTestKey + "/actions/revoke")
	for _, test := range []struct {
		name, method, path, body string
		failure                  error
		status, calls            int
		want, absent             string
	}{
		{"list", http.MethodGet, enrollmentKeysTestPath(""), "", nil, 200, 1,
			`"device":{"device_id":"01890f00-0000-7000-8000-000000000c01","name":"build-1"}`, enrollmentKeyTestToken},
		{"list forbidden", http.MethodGet, enrollmentKeysTestPath(""), "", enrollmentkey.ErrForbidden, 403, 1,
			"permission_denied", ""},
		{"create never expires", http.MethodPost, create, `{"description":"build server","device_never_expires":true}`,
			nil, 201, 1, `"secret":"`, ""},
		{"create fixed", http.MethodPost, create, `{"device_lifetime_seconds":86400,"key_lifetime_seconds":3600}`,
			nil, 201, 1, `"never_expires":true`, ""},
		{"create both lifetimes", http.MethodPost, create, `{"device_never_expires":true,"device_lifetime_seconds":3600}`,
			nil, 400, 0, "invalid_request", ""},
		{"create no lifetime", http.MethodPost, create, `{}`, nil, 400, 0, "invalid_request", ""},
		{"create never false", http.MethodPost, create, `{"device_never_expires":false}`, nil, 400, 0,
			"invalid_request", ""},
		{"create Device lifetime too long", http.MethodPost, create, `{"device_lifetime_seconds":15552001}`, nil,
			400, 0, "invalid_request", ""},
		{"create key lifetime too long", http.MethodPost, create,
			`{"device_never_expires":true,"key_lifetime_seconds":2592001}`, nil, 400, 0, "invalid_request", ""},
		{"create unknown field", http.MethodPost, create, `{"device_never_expires":true,"uses":2}`, nil, 400, 0,
			"invalid_request", ""},
		{"create limit", http.MethodPost, create, `{"device_never_expires":true}`, enrollmentkey.ErrLimitReached,
			409, 1, "enrollment_key_limit", ""},
		{"revoke", http.MethodPost, revoke, `{}`, nil, 200, 1, `"state":"revoked"`, enrollmentKeyTestToken},
		{"revoke again", http.MethodPost, revoke, `{}`, enrollmentkey.ErrNotActive, 409, 1,
			"enrollment_key_revoked", ""},
		{"revoke used", http.MethodPost, revoke, `{}`, enrollmentkey.ErrUsed, 409, 1, "enrollment_key_used", ""},
		{"revoke unknown", http.MethodPost, revoke, `{}`, enrollmentkey.ErrNotFound, 404, 1,
			"enrollment_key_not_found", ""},
		{"revoke with a body", http.MethodPost, revoke, `{"reason":"x"}`, nil, 400, 0, "invalid_request", ""},
		{"wrong method", http.MethodGet, create, "", nil, 405, 0, "method_not_allowed", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &enrollmentKeyStub{failure: test.failure}
			options.EnrollmentKeys = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, test.method, test.path, test.body)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			calls := len(stub.issued) + stub.lists + len(stub.revoked)
			body := response.Body.String()
			if response.Code != test.status || calls != test.calls || !strings.Contains(body, test.want) ||
				test.absent != "" && strings.Contains(body, test.absent) {
				t.Fatalf("status/calls %d/%d, want %d/%d; %s", response.Code, calls, test.status, test.calls, body)
			}
			if response.Header().Get("Cache-Control") != "no-store" && test.status < 300 {
				t.Fatal("an enrollment key response may be cached")
			}
		})
	}
}

func TestEnrollmentKeyCreateDefaultsTheKeyLifetime(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	stub := &enrollmentKeyStub{}
	options.EnrollmentKeys = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodPost, enrollmentKeysTestPath("/actions/create"),
		`{"device_lifetime_seconds":7200}`)
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || len(stub.issued) != 1 || stub.issued[0].KeyLifetime != 0 ||
		stub.issued[0].DeviceLifetime.Duration() != 2*time.Hour {
		t.Fatalf("create = %d, %+v", response.Code, stub.issued)
	}
	if !strings.Contains(response.Body.String(), `"secret":"mtc1.`+enrollmentKeyTestKey+`.`) {
		t.Fatalf("the secret is not the key's presentation: %s", response.Body)
	}
}

func TestEnrollmentKeysUnavailableWithoutManager(t *testing.T) {
	t.Parallel()
	handler, err := NewManagementHandler(validManagementHandlerOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodGet, enrollmentKeysTestPath(""), "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; %s", response.Code, response.Body)
	}
}

func TestClassifyEnrollmentKeyError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		enrollmentkey.ErrForbidden:     "permission_denied",
		enrollmentkey.ErrNotFound:      "enrollment_key_not_found",
		enrollmentkey.ErrNotActive:     "enrollment_key_revoked",
		enrollmentkey.ErrLimitReached:  "enrollment_key_limit",
		enrollmentkey.ErrUsed:          "enrollment_key_used",
		enrollmentkey.ErrInvalid:       "invalid_request",
		errors.New("database is down"): "temporarily_unavailable",
	} {
		if got := classifyEnrollmentKeyError(err).Code; got != code {
			t.Errorf("%v: code = %q, want %q", err, got, code)
		}
	}
}
