package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/devicelifecycle"
)

func TestParseDeviceLifecyclePath(t *testing.T) {
	t.Parallel()
	const device = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/" +
		"01890f00-0000-7000-8000-000000000201/devices/01890f00-0000-7000-8000-000000000901"
	const prefix = device + "/actions/"
	for _, test := range []struct {
		method, path, action string
		matched              bool
	}{
		{http.MethodPost, prefix + "suspend", "suspend", true},
		{http.MethodPost, prefix + "resume", "resume", true},
		{http.MethodPost, prefix + "transfer", "transfer", true},
		{http.MethodPost, prefix + "extend", "extend", true},
		{http.MethodPatch, device, "rename", true},
		{http.MethodGet, prefix + "suspend", "", true},
		{http.MethodPut, device, "", true},
		{http.MethodPost, prefix + "rename", "", false},
		{http.MethodPost, prefix + "revoke", "", false},
		{http.MethodPost, prefix + "delete", "", false},
		{http.MethodPost, prefix + "suspend?x=1", "", false},
		{http.MethodPatch, device + "?x=1", "", false},
		{http.MethodPost, strings.Replace(prefix, "01890f00-0000-7000-8000-000000000901",
			"01890F00-0000-7000-8000-000000000901", 1) + "suspend", "", false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseDeviceLifecyclePath(request)
		if ok != test.matched || ok && (path.action != test.action ||
			isDeviceLifecycleOperation(request) != (test.action != "")) {
			t.Errorf("%s %s: %+v matched %t", test.method, test.path, path, ok)
		}
	}
}

func TestParseDeviceLifecycleBody(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		action, body string
		want         devicelifecycle.Action
		valid        bool
	}{
		{"suspend", `{"reason":"Lost laptop"}`, devicelifecycle.ActionSuspend, true},
		{"resume", `{"reason":"Found"}`, devicelifecycle.ActionResume, true},
		{"transfer", `{"to":"workspace","reason":"Server"}`, devicelifecycle.ActionTransferWorkspace, true},
		{"transfer", `{"to":"member","principal_id":"01890f00-0000-7000-8000-000000000402","reason":"Bao"}`,
			devicelifecycle.ActionTransferMember, true},
		{"rename", `{"hostname":"db-primary"}`, devicelifecycle.ActionRename, true},
		{"extend", `{"duration_seconds":86400,"reason":"Owner on leave"}`, devicelifecycle.ActionExtend, true},
		{"extend", `{"duration_seconds":86400}`, "", false},
		{"extend", `{"reason":"x"}`, "", false},
		{"extend", `{"duration_seconds":0,"reason":"x"}`, "", false},
		{"extend", `{"duration_seconds":604801,"reason":"x"}`, "", false},
		{"extend", `{"duration_seconds":3600,"reason":"x","hostname":"a"}`, "", false},
		{"suspend", `{"reason":"x","duration_seconds":3600}`, "", false},
		{"suspend", `{}`, "", false},
		{"suspend", `{"reason":"x","hostname":"a"}`, "", false},
		{"transfer", `{"to":"member","reason":"Bao"}`, "", false},
		{"transfer", `{"to":"workspace","principal_id":"01890f00-0000-7000-8000-000000000402","reason":"x"}`, "", false},
		{"transfer", `{"to":"team","reason":"x"}`, "", false},
		{"rename", `{"hostname":"Bad Name"}`, "", false},
		{"rename", `{"hostname":"db","extra":1}`, "", false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		got, ok := parseDeviceLifecycleBody(httptest.NewRecorder(), request, deviceLifecyclePath{action: test.action})
		if ok != test.valid || (ok && got.Action != test.want) {
			t.Errorf("%s %s: = %+v, %t", test.action, test.body, got, ok)
		}
	}
}
