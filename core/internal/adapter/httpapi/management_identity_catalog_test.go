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
		matched                 bool
		allow                   string
	}{
		{http.MethodGet, ws + "/identity-groups", "identity_group_list", true, "GET, POST"},
		{http.MethodPost, ws + "/identity-groups", "identity_group_create", true, "GET, POST"},
		{http.MethodPatch, ws + "/identity-groups/" + id, "identity_group_update", true, "PATCH, DELETE"},
		{http.MethodDelete, ws + "/identity-groups/" + id, "identity_group_delete", true, "PATCH, DELETE"},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?limit=10", "identity_group_members", true, "GET, PATCH"},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?after=" + id, "identity_group_members", true, "GET, PATCH"},
		{http.MethodPatch, ws + "/identity-groups/" + id + "/members", "identity_group_change_members", true, "GET, PATCH"},
		{http.MethodGet, ws + "/device-tags", "device_tag_list", true, "GET, POST"},
		{http.MethodPost, ws + "/device-tags", "device_tag_create", true, "GET, POST"},
		{http.MethodPatch, ws + "/device-tags/" + id, "device_tag_update", true, "PATCH, DELETE"},
		{http.MethodDelete, ws + "/device-tags/" + id, "device_tag_delete", true, "PATCH, DELETE"},
		{http.MethodGet, net + "/device-tags", "network_device_tags_read", true, "GET"},
		{http.MethodGet, net + "/assignable-device-tags", "network_tag_options_read", true, "GET"},
		{http.MethodPatch, net + "/devices/" + id + "/tags", "device_tags_change", true, "PATCH"},
		// A known path with another method is matched for a 405, not admitted.
		{http.MethodPut, ws + "/identity-groups/" + id, "", true, "PATCH, DELETE"},
		{http.MethodPost, ws + "/identity-groups/" + id + "/members", "", true, "GET, PATCH"},
		{http.MethodDelete, ws + "/device-tags", "", true, "GET, POST"},
		{http.MethodPost, net + "/devices/" + id + "/tags", "", true, "PATCH"},
		// Old action paths and malformed requests match nothing.
		{http.MethodPost, ws + "/identity-groups/actions/create", "", false, ""},
		{http.MethodPost, ws + "/identity-groups/" + id + "/actions/delete", "", false, ""},
		{http.MethodPost, ws + "/device-tags/" + id + "/actions/update", "", false, ""},
		{http.MethodGet, net + "/device-tags/options", "", false, ""},
		{http.MethodPost, net + "/devices/" + id + "/actions/change-tags", "", false, ""},
		{http.MethodGet, ws + "/identity-groups?limit=1", "", false, ""},
		{http.MethodPatch, ws + "/identity-groups/" + id + "/members?limit=1", "", false, ""},
		{http.MethodGet, ws + "/device-tags/" + id + "/members", "", false, ""},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?limit=501", "", false, ""},
		{http.MethodGet, ws + "/identity-groups/" + id + "/members?limit=1&limit=2", "", false, ""},
		{http.MethodGet, ws + "/identity-groups/01890F00-0000-7000-8000-000000000301/members", "", false, ""},
		{http.MethodPatch, ws + "/identity-groups/not-an-id", "", false, ""},
		{http.MethodGet, net + "/device-tags?x=1", "", false, ""},
		{http.MethodGet, net + "/assignable-device-tags/extra", "", false, ""},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseIdentityCatalogPath(request)
		if ok != test.matched {
			t.Errorf("%s %s: matched = %t, want %t", test.method, test.path, ok, test.matched)
			continue
		}
		if !ok {
			continue
		}
		admitted := test.operation != ""
		if isIdentityCatalogOperation(request) != admitted || path.methods.header() != test.allow ||
			admitted && path.operation() != test.operation {
			t.Errorf("%s %s: operation %q admitted %t allow %q; want %q %t %q", test.method, test.path,
				path.operation(), isIdentityCatalogOperation(request), path.methods.header(),
				test.operation, admitted, test.allow)
		}
	}
}
