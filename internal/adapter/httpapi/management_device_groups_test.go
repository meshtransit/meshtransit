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
	}{
		{http.MethodGet, scope + "/device-groups", deviceGroupListOperation, 0, true},
		{http.MethodPost, scope + "/device-groups/actions/create", deviceGroupCreateOperation, 0, true},
		{http.MethodGet, scope + "/device-groups/" + group + "/members", deviceGroupMembersOperation, 100, true},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?after=" + device + "&limit=20",
			deviceGroupMembersOperation, 20, true},
		{http.MethodPost, scope + "/device-groups/" + group + "/actions/change-members", deviceGroupChangeOperation, 0, true},
		{http.MethodPost, scope + "/device-groups/" + group + "/actions/delete", deviceGroupDeleteOperation, 0, true},
		{http.MethodGet, scope + "/device-groups?x=1", "", 0, false},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?limit=501", "", 0, false},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?limit=5&limit=6", "", 0, false},
		{http.MethodGet, scope + "/device-groups/" + group + "/members?other=1", "", 0, false},
		{http.MethodPost, scope + "/device-groups/" + group + "/actions/rename", "", 0, false},
		{http.MethodPost, scope + "/device-groups/not-a-uuid/actions/delete", "", 0, false},
		{http.MethodGet, "/api/v1/workspaces/01890f00-0000-7000-8000-000000000103/device-groups", "", 0, false},
	}
	for _, test := range cases {
		request := httptest.NewRequest(test.method, test.target, nil)
		path, ok := parseDeviceGroupPath(request)
		if ok != test.ok || (ok && (path.operation() != test.operation || path.limit != test.limit)) {
			t.Errorf("%s %s: ok=%v operation=%q limit=%d", test.method, test.target, ok, path.operation(), path.limit)
		}
		if ok && !isDeviceGroupOperation(request) {
			t.Errorf("%s %s: method not admitted", test.method, test.target)
		}
	}
	wrongMethod := httptest.NewRequest(http.MethodPost, scope+"/device-groups", nil)
	if isDeviceGroupOperation(wrongMethod) {
		t.Fatal("POST to the list must not be admitted")
	}
}
