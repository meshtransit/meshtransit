package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The audit export and the enforcement history are resources of their own,
// not words after a collection that holds IDs.
func TestRenamedReadPaths(t *testing.T) {
	t.Parallel()
	const ws = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101"
	const net = ws + "/networks/01890f00-0000-7000-8000-000000000201"
	for _, test := range []struct {
		path        string
		export, log bool
	}{
		{ws + "/audit-exports", true, false},
		{ws + "/audit-exports?format=csv", true, false},
		{ws + "/audit-events/export", false, false},
		{net + "/enforcement-history", false, true},
		{net + "/devices/enforcement-history", false, false},
		{ws + "/networks/not-an-id/enforcement-history", false, false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, test.path, nil)
		_, export := parseAuditEventExportPath(request)
		_, history := parseEnforcementHistoryPath(request)
		if export != test.export || history != test.log {
			t.Errorf("%s: export %t history %t", test.path, export, history)
		}
	}
}
