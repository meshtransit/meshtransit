package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/audit/history"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const auditTestWorkspace = "01890f00-0000-7000-8000-000000000102"

func TestParseAuditEventListPath(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/api/v1/workspaces/" + auditTestWorkspace + "/audit-events":           true,
		"/api/v1/workspaces/" + auditTestWorkspace + "/audit-events/":          false,
		"/api/v1/workspaces/" + auditTestWorkspace + "/audit-events/x":         false,
		"/api/v1/workspaces/01890F00-0000-7000-8000-000000000102/audit-events": false,
		"/api/v1/workspaces/not-a-uuid/audit-events":                           false,
		"/api/v2/workspaces/" + auditTestWorkspace + "/audit-events":           false,
	}
	for target, want := range cases {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if _, got := parseAuditEventListPath(request); got != want {
			t.Errorf("parseAuditEventListPath(%q) = %v, want %v", target, got, want)
		}
	}
	post := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/workspaces/"+auditTestWorkspace+"/audit-events", nil)
	if isAuditEventListRead(post) {
		t.Error("POST must not be an audit history read")
	}
}

func TestParseAuditEventListQuery(t *testing.T) {
	t.Parallel()
	workspaceID, err := workspace.ParseID(auditTestWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	token := history.Cursor{OccurredAt: time.Date(2026, 10, 7, 4, 0, 0, 0, time.UTC),
		EventID: mustParseAuditID(t, "01890f00-0000-7000-8000-000000000301")}.Token()
	query, ok := parseAuditEventListQuery("network_id=01890f00-0000-7000-8000-000000000202"+
		"&since=2026-09-01T00:00:00Z&until=2026-10-07T00:00:00Z&target_kind=share_offer,trust_contract"+
		"&actor_kind=principal&action=share_offer.accepted&result=succeeded&page_size=25&page_token="+token, workspaceID)
	if !ok || !query.NetworkID.IsValid() || len(query.TargetKinds) != 2 || query.PageSize != 25 ||
		query.Cursor == nil || !query.Since.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("parseAuditEventListQuery() = %+v, %v", query, ok)
	}
	for _, raw := range []string{
		"unknown=1",
		"action=",
		"result=ok&result=ok",
		"network_id=01890F00-0000-7000-8000-000000000202",
		"since=yesterday",
		"page_size=101",
		"page_size=05",
		"page_token=abc",
		"target_id=not-a-uuid",
	} {
		if _, ok := parseAuditEventListQuery(raw, workspaceID); ok {
			t.Errorf("parseAuditEventListQuery(%q) accepted", raw)
		}
	}
}

func mustParseAuditID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
