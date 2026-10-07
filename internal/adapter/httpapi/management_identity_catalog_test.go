package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseIdentityCatalogPath(t *testing.T) {
	t.Parallel()
	const ws = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101"
	const id = "01890f00-0000-7000-8000-000000000301"
	const net = ws + "/networks/01890f00-0000-7000-8000-000000000201"
	for _, test := range []struct {
		method, path, operation string
		valid                   bool
	}{
		{http.MethodGet, ws + "/identity-groups", "identity_group_list", true},
		{http.MethodPost, ws + "/identity-groups/actions/create", "identity_group_create", true},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?limit=10", "identity_group_members", true},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?after=" + id, "identity_group_members", true},
		{http.MethodPost, ws + "/identity-groups/" + id + "/actions/change-members", "identity_group_change_members", true},
		{http.MethodPost, ws + "/identity-groups/" + id + "/actions/delete", "identity_group_delete", true},
		{http.MethodGet, ws + "/device-tags", "device_tag_list", true},
		{http.MethodPost, ws + "/device-tags/" + id + "/actions/update", "device_tag_update", true},
		{http.MethodGet, net + "/device-tags", "network_device_tags_read", true},
		{http.MethodGet, net + "/device-tags/options", "network_tag_options_read", true},
		{http.MethodPost, net + "/devices/" + id + "/actions/change-tags", "device_tags_change", true},
		{http.MethodGet, ws + "/identity-groups?limit=1", "", false},
		{http.MethodGet, ws + "/device-tags/" + id + "/members", "", false},
		{http.MethodPost, ws + "/device-tags/" + id + "/actions/change-members", "", false},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?limit=501", "", false},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?limit=1&limit=2", "", false},
		{http.MethodGet, ws + "/identity-groups/01890F00-0000-7000-8000-000000000301/members", "", false},
		{http.MethodPost, net + "/devices/" + id + "/actions/revoke", "", false},
		{http.MethodGet, net + "/device-tags?x=1", "", false},
		{http.MethodGet, net + "/device-tags/options?x=1", "", false},
		{http.MethodGet, net + "/device-tags/choices", "", false},
		{http.MethodGet, net + "/device-tags/options/extra", "", false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseIdentityCatalogPath(request)
		if ok != test.valid {
			t.Errorf("%s %s: matched = %t, want %t", test.method, test.path, ok, test.valid)
			continue
		}
		if ok && path.operation() != test.operation {
			t.Errorf("%s %s: operation = %q, want %q", test.method, test.path, path.operation(), test.operation)
		}
		if ok && isIdentityCatalogOperation(request) != (request.Method == path.allowedMethod()) {
			t.Errorf("%s %s: method admission mismatch", test.method, test.path)
		}
	}
}
