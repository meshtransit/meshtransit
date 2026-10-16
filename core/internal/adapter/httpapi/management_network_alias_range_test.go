package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/network/aliasrange"
)

const (
	aliasRangeWorkspace = "01890f00-0000-7000-8000-000000000101"
	aliasRangeNetwork   = "01890f00-0000-7000-8000-000000000201"
)

func TestParseNetworkAliasRangePath(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/" + aliasRangeNetwork + "/alias-ranges"
	for _, test := range []struct {
		name, method, target string
		matched, update      bool
		allowed              bool
	}{
		{name: "read", method: http.MethodGet, target: base, matched: true, allowed: true},
		{name: "update", method: http.MethodPatch, target: base, matched: true, update: true, allowed: true},
		{name: "post", method: http.MethodPost, target: base, matched: true},
		{name: "put", method: http.MethodPut, target: base, matched: true},
		{name: "old update path", method: http.MethodPost, target: base + "/actions/update"},
		{name: "query", method: http.MethodGet, target: base + "?x=1"},
		{name: "other action", method: http.MethodPost, target: base + "/actions/delete"},
		{name: "uppercase id", method: http.MethodGet,
			target: "/api/v1/workspaces/" + strings.ToUpper(aliasRangeWorkspace) + "/networks/" + aliasRangeNetwork + "/alias-ranges"},
		{name: "not a v7 id", method: http.MethodGet,
			target: "/api/v1/workspaces/01890f00-0000-4000-8000-000000000101/networks/" + aliasRangeNetwork + "/alias-ranges"},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil)
		path, matched := parseNetworkAliasRangePath(request)
		if matched != test.matched || matched && path.update != test.update {
			t.Errorf("%s: matched = %v update = %v", test.name, matched, path.update)
		}
		if isNetworkAliasRangeOperation(request) != test.allowed {
			t.Errorf("%s: operation admitted = %v, want %v", test.name, !test.allowed, test.allowed)
		}
	}
}

func TestParseNetworkAliasRangeBody(t *testing.T) {
	t.Parallel()
	chosen := netip.MustParsePrefix("198.18.42.0/24")
	for _, test := range []struct {
		name, body string
		valid      bool
		ipv4, ipv6 aliasrange.Change
	}{
		{name: "set IPv4, keep IPv6", body: `{"ipv4_prefix":"198.18.42.0/24"}`, valid: true,
			ipv4: aliasrange.Change{Present: true, Prefix: chosen}},
		{name: "clear IPv6", body: `{"ipv6_prefix":null}`, valid: true, ipv6: aliasrange.Change{Present: true}},
		{name: "both", body: `{"ipv4_prefix":null,"ipv6_prefix":"fd02:48de:ec1b:1::2a00/120"}`, valid: true,
			ipv4: aliasrange.Change{Present: true},
			ipv6: aliasrange.Change{Present: true, Prefix: netip.MustParsePrefix("fd02:48de:ec1b:1::2a00/120")}},
		{name: "host bits", body: `{"ipv4_prefix":"198.18.42.1/24"}`},
		{name: "non canonical IPv6", body: `{"ipv6_prefix":"FD02:48de:ec1b:1::2a00/120"}`},
		{name: "number", body: `{"ipv4_prefix":24}`},
		{name: "unknown key", body: `{"ipv4_prefix":null,"family":4}`},
		{name: "trailing value", body: `{"ipv4_prefix":null} {}`},
		{name: "array", body: `[]`},
		{name: "null document", body: `null`},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		ipv4, ipv6, valid := parseNetworkAliasRangeBody(httptest.NewRecorder(), request)
		if valid != test.valid {
			t.Errorf("%s: valid = %v, want %v", test.name, valid, test.valid)
			continue
		}
		if valid && (ipv4 != test.ipv4 || ipv6 != test.ipv6) {
			t.Errorf("%s: changes = %+v %+v", test.name, ipv4, ipv6)
		}
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(`{"ipv4_prefix":null}`))
	request.Header.Set("Content-Type", "text/plain")
	if _, _, valid := parseNetworkAliasRangeBody(httptest.NewRecorder(), request); valid {
		t.Fatal("non-JSON content type accepted")
	}
}

func TestClassifyNetworkAliasRangeError(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{aliasrange.ErrForbidden, http.StatusForbidden, "permission_denied"},
		{aliasrange.ErrOutsideFrame, http.StatusUnprocessableEntity, "alias_range_outside_frame"},
		{aliasrange.ErrInUse, http.StatusConflict, "alias_range_in_use"},
		{aliasrange.ErrVersionConflict, http.StatusPreconditionFailed, "version_conflict"},
		{aliasrange.ErrInvalid, http.StatusBadRequest, "invalid_request"},
		{errors.Join(aliasrange.ErrUnavailable, errors.New("network")), http.StatusServiceUnavailable, "temporarily_unavailable"},
	} {
		got := classifyNetworkAliasRangeError(test.err)
		if got.Status != test.status || got.Code != test.code {
			t.Errorf("%v: %d %s", test.err, got.Status, got.Code)
		}
	}
}
