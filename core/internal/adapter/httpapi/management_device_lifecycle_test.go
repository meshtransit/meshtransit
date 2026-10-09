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
	const prefix = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/" +
		"01890f00-0000-7000-8000-000000000201/devices/01890f00-0000-7000-8000-000000000901/actions/"
	for path, valid := range map[string]bool{
		prefix + "suspend": true, prefix + "resume": true, prefix + "transfer": true, prefix + "rename": true,
		prefix + "revoke": false, prefix + "delete": false, prefix + "suspend?x=1": false,
		strings.Replace(prefix, "01890f00-0000-7000-8000-000000000901", "01890F00-0000-7000-8000-000000000901", 1) +
			"suspend": false,
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
		if _, ok := parseDeviceLifecyclePath(request); ok != valid {
			t.Errorf("%s: matched = %t, want %t", path, ok, valid)
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
