package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network/devicelifetime"
)

func TestParseNetworkDeviceLifetimePath(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/" + aliasRangeNetwork + "/device-lifetime"
	for _, test := range []struct {
		name, method, target string
		matched, update      bool
		allowed              bool
	}{
		{name: "read", method: http.MethodGet, target: base, matched: true, allowed: true},
		{name: "update", method: http.MethodPatch, target: base, matched: true, update: true, allowed: true},
		{name: "post", method: http.MethodPost, target: base, matched: true},
		{name: "delete", method: http.MethodDelete, target: base, matched: true},
		{name: "query", method: http.MethodGet, target: base + "?x=1"},
		{name: "action", method: http.MethodPost, target: base + "/actions/update"},
		{name: "uppercase id", method: http.MethodGet,
			target: "/api/v1/workspaces/" + strings.ToUpper(aliasRangeWorkspace) + "/networks/" + aliasRangeNetwork +
				"/device-lifetime"},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil)
		path, matched := parseNetworkDeviceLifetimePath(request)
		if matched != test.matched || matched && path.update != test.update {
			t.Errorf("%s: matched = %v update = %v", test.name, matched, path.update)
		}
		if isNetworkDeviceLifetimeOperation(request) != test.allowed {
			t.Errorf("%s: operation admitted = %v, want %v", test.name, !test.allowed, test.allowed)
		}
	}
}

func TestParseNetworkDeviceLifetimeBody(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, body string
		valid      bool
		lifetime   time.Duration
		never      bool
	}{
		{name: "one day", body: `{"device_lifetime_seconds":86400}`, valid: true, lifetime: 24 * time.Hour},
		{name: "never", body: `{"never_expires":true}`, valid: true, never: true},
		{name: "never false", body: `{"never_expires":false}`},
		{name: "both", body: `{"device_lifetime_seconds":86400,"never_expires":true}`},
		{name: "null seconds", body: `{"device_lifetime_seconds":null}`},
		{name: "fraction", body: `{"device_lifetime_seconds":3600.5}`},
		{name: "exponent", body: `{"device_lifetime_seconds":36e2}`},
		{name: "negative", body: `{"device_lifetime_seconds":-3600}`},
		{name: "leading zero", body: `{"device_lifetime_seconds":03600}`},
		{name: "string", body: `{"device_lifetime_seconds":"3600"}`},
		{name: "huge", body: `{"device_lifetime_seconds":99999999999999999999}`},
		{name: "unknown key", body: `{"lifetime":3600}`},
		{name: "empty", body: `{}`},
		{name: "trailing", body: `{"never_expires":true} {}`},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		lifetime, never, valid := parseNetworkDeviceLifetimeBody(httptest.NewRecorder(), request)
		if valid != test.valid {
			t.Errorf("%s: valid = %v, want %v", test.name, valid, test.valid)
			continue
		}
		if valid && (lifetime != test.lifetime || never != test.never) {
			t.Errorf("%s: parsed %v/%v", test.name, lifetime, never)
		}
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/", strings.NewReader(`{"never_expires":true}`))
	request.Header.Set("Content-Type", "text/plain")
	if _, _, valid := parseNetworkDeviceLifetimeBody(httptest.NewRecorder(), request); valid {
		t.Fatal("non-JSON content type accepted")
	}
}

func TestClassifyNetworkDeviceLifetimeError(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{devicelifetime.ErrForbidden, http.StatusForbidden, "permission_denied"},
		{devicelifetime.ErrNoInteractiveProfile, http.StatusConflict, "sign_in_unavailable"},
		{devicelifetime.ErrVersionConflict, http.StatusPreconditionFailed, "version_conflict"},
		{devicelifetime.ErrInvalid, http.StatusBadRequest, "invalid_request"},
		{errors.Join(devicelifetime.ErrUnavailable, errors.New("db")), http.StatusServiceUnavailable,
			"temporarily_unavailable"},
	} {
		got := classifyNetworkDeviceLifetimeError(test.err)
		if got.Status != test.status || got.Code != test.code {
			t.Errorf("%v: %d %s", test.err, got.Status, got.Code)
		}
	}
}
