package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseDeviceGroupPath(t *testing.T) {
	t.Parallel()
	const scope = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000103/networks/01890f00-0000-7000-8000-000000000203"
	const group = "01890f00-0000-7000-8000-000000000a01"
	const device = "01890f00-0000-7000-8000-000000000701"
	cases := []struct {
		method, target, operation string
		limit                     int
		ok                        bool
		allow                     string
	}{
		{http.MethodGet, scope + "/device-groups", deviceGroupListOperation, 0, true, "GET, POST"},
		{http.MethodPost, scope + "/device-groups", deviceGroupCreateOperation, 0, true, "GET, POST"},
		{http.MethodGet, scope + "/device-groups/" + group + "/members", deviceGroupMembersOperation, 100, true, "GET, PATCH"},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?after=" + device + "&limit=20",
			deviceGroupMembersOperation, 20, true, "GET, PATCH"},
		{http.MethodPatch, scope + "/device-groups/" + group + "/members", deviceGroupChangeOperation, 0, true, "GET, PATCH"},
		{http.MethodPatch, scope + "/device-groups/" + group, deviceGroupUpdateOperation, 0, true, "PATCH, DELETE"},
		{http.MethodDelete, scope + "/device-groups/" + group, deviceGroupDeleteOperation, 0, true, "PATCH, DELETE"},
		{http.MethodGet, scope + "/device-groups?x=1", "", 0, false, ""},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?limit=501", "", 0, false, ""},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?limit=5&limit=6", "", 0, false, ""},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?other=1", "", 0, false, ""},
		{http.MethodPatch, scope + "/device-groups/" + group + "/members?limit=5", "", 0, false, ""},
		{http.MethodPost, scope + "/device-groups/actions/create", "", 0, false, ""},
		{http.MethodPost, scope + "/device-groups/" + group + "/actions/delete", "", 0, false, ""},
		{http.MethodPost, scope + "/device-groups/" + group + "/actions/change-members", "", 0, false, ""},
		{http.MethodDelete, scope + "/device-groups/not-a-uuid", "", 0, false, ""},
		{http.MethodGet, "/api/v1/workspaces/01890f00-0000-7000-8000-000000000103/device-groups", "", 0, false, ""},
	}
	for _, test := range cases {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil)
		path, ok := parseDeviceGroupPath(request)
		if ok != test.ok || (ok && (path.operation() != test.operation || path.limit != test.limit ||
			path.methods.header() != test.allow)) {
			t.Errorf("%s %s: ok=%v operation=%q limit=%d", test.method, test.target, ok, path.operation(), path.limit)
		}
		if ok && !isDeviceGroupOperation(request) {
			t.Errorf("%s %s: method not admitted", test.method, test.target)
		}
	}
	for _, method := range []string{http.MethodDelete, http.MethodPut} {
		request := httptest.NewRequestWithContext(t.Context(), method, scope+"/device-groups", nil)
		if path, ok := parseDeviceGroupPath(request); !ok || isDeviceGroupOperation(request) || path.methods.header() != "GET, POST" {
			t.Fatalf("%s on the list must match for a 405 and not be admitted", method)
		}
	}
}
