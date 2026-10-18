package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"meshtransit.net/core/internal/domain/site"
)

func TestParseSitePath(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/sites"
	siteID := "01890f00-0000-7000-8000-000000000301"
	deviceID := "01890f00-0000-7000-8000-000000000401"
	for _, test := range []struct {
		method, path, operation string
		matched                 bool
	}{
		{http.MethodGet, base, siteListOperation, true},
		{http.MethodPost, base, siteCreateOperation, true},
		{http.MethodDelete, base, "", true},
		{http.MethodGet, base + "/" + siteID, siteReadOperation, true},
		{http.MethodPatch, base + "/" + siteID, siteUpdateOperation, true},
		{http.MethodDelete, base + "/" + siteID, siteDeleteOperation, true},
		{http.MethodPost, base + "/" + siteID, "", true},
		{http.MethodPut, base + "/" + siteID + "/routers/" + deviceID, siteRouterPutOperation, true},
		{http.MethodDelete, base + "/" + siteID + "/routers/" + deviceID, siteRouterDeleteOperation, true},
		{http.MethodGet, base + "/" + siteID + "/routers/" + deviceID, "", true},
		{http.MethodGet, base + "?limit=1", siteListOperation, true},
		{http.MethodGet, base + "?after=" + siteID + "&limit=10", siteListOperation, true},
		{http.MethodGet, base + "?limit=101", "", false},
		{http.MethodGet, base + "?limit=1&limit=2", "", false},
		{http.MethodGet, base + "?cursor=x", "", false},
		{http.MethodGet, base + "/" + siteID + "?limit=1", "", false},
		{http.MethodGet, base + "/not-an-id", "", false},
		{http.MethodPut, base + "/" + siteID + "/routers", "", false},
		{http.MethodGet, base + "/" + siteID + "/members", "", false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, matched := parseSitePath(request)
		if matched != test.matched || (matched && path.operation != test.operation) {
			t.Errorf("%s %s = %q, %v; want %q, %v", test.method, test.path, path.operation, matched,
				test.operation, test.matched)
		}
	}
}

func TestClassifySiteError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		site.ErrForbidden:         "permission_denied",
		site.ErrNotFound:          "site_not_found",
		site.ErrVersionConflict:   "version_conflict",
		site.ErrNameTaken:         "site_name_taken",
		site.ErrSiteLimit:         "site_limit",
		site.ErrPrefixLimit:       "site_prefix_limit",
		site.ErrRouterLimit:       "site_router_limit",
		site.ErrRouterNotEligible: "router_not_eligible",
		site.ErrRouterNotOffering: "router_not_advertising",
		site.ErrInvalidPrefix:     "site_prefix_invalid",
		errors.New("database"):    "temporarily_unavailable",
	} {
		if got := classifySiteError(err).Code; got != code {
			t.Errorf("classifySiteError(%v) = %q, want %q", err, got, code)
		}
	}
}
