package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/shared/key"
)

const testInterchangeWorkspace = "01890f00-0000-7000-8000-000000000103"

func TestParseInterchangePath(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + testInterchangeWorkspace + "/interchanges"
	id := "01890f00-0000-7000-8000-000000000501"
	for target, want := range map[string]string{
		base:                                "",
		base + "/actions/create":            "create",
		base + "/" + id + "/actions/update": "update",
		base + "/" + id + "/actions/delete": "delete",
	} {
		path, ok := parseInterchangePath(httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil))
		if !ok || path.action != want {
			t.Errorf("%s: %+v %v", target, path, ok)
		}
	}
	for _, target := range []string{
		base + "/actions/remove", base + "/not-an-id/actions/update", base + "?page=2",
		"/api/v1/workspaces/not-a-workspace/interchanges", base + "/" + id,
	} {
		if _, ok := parseInterchangePath(httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)); ok {
			t.Errorf("%s: matched", target)
		}
	}
	if isInterchangeOperation(httptest.NewRequestWithContext(t.Context(), http.MethodGet, base+"/actions/create", nil)) ||
		!isInterchangeRead(httptest.NewRequestWithContext(t.Context(), http.MethodGet, base, nil)) {
		t.Fatal("methods are not checked")
	}
}

func interchangeRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestParseInterchangeSpec(t *testing.T) {
	t.Parallel()
	relayKey := key.RelayPublic{0x40}.String()
	valid := `{"name":"Office relay","region_code":"office","host_name":"relay.office.example.com",` +
		`"ipv4":"203.0.113.40","ipv6":null,"relay_key":"` + relayKey + `","udp_port":3479,"tls_port":443,` +
		`"stun_port":3478,"network_ids":["01890f00-0000-7000-8000-000000000203","01890f00-0000-7000-8000-000000000201"]}`
	spec, ok := parseInterchangeSpec(httptest.NewRecorder(), interchangeRequest(t, valid))
	if !ok || spec.RegionCode != "office" || len(spec.Networks) != 2 ||
		spec.Networks[0].String() != "01890f00-0000-7000-8000-000000000201" || spec.IPv6.IsValid() {
		t.Fatalf("spec %+v %v", spec, ok)
	}
	for name, body := range map[string]string{
		"unknown field":   strings.Replace(valid, `"name"`, `"extra":1,"name"`, 1),
		"duplicate":       strings.Replace(valid, "000000000201", "000000000203", 1),
		"private address": strings.Replace(valid, "203.0.113.40", "10.0.0.4", 1),
		"bad key":         strings.Replace(valid, relayKey, "mtrelay:00", 1),
		"no networks":     strings.Replace(valid, `"network_ids":[`, `"network_ids":null,"x":[`, 1),
		"trailing":        valid + "{}",
		"non-canonical":   strings.Replace(valid, "203.0.113.40", "203.000.113.40", 1),
	} {
		if _, ok := parseInterchangeSpec(httptest.NewRecorder(), interchangeRequest(t, body)); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClassifyInterchangeError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		interchange.ErrForbidden:       "permission_denied",
		interchange.ErrConflict:        "interchange_conflict",
		interchange.ErrUnknownNetwork:  "interchange_network_unknown",
		interchange.ErrVersionConflict: "version_conflict",
		interchange.ErrUnavailable:     "temporarily_unavailable",
	} {
		if got := classifyInterchangeError(err).Code; got != code {
			t.Errorf("%v: %s, want %s", err, got, code)
		}
	}
}
