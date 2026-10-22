package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnszone"
)

const dnsZoneBase = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/" +
	"01890f00-0000-7000-8000-000000000201/dns/zones"

func TestParseDNSZonePath(t *testing.T) {
	t.Parallel()
	zone := "/01890f00-0000-7000-8000-000000000301"
	for _, test := range []struct {
		method, target, operation string
		ok                        bool
	}{
		{http.MethodGet, dnsZoneBase, dnsZoneListOperation, true},
		{http.MethodGet, dnsZoneBase + "?limit=20&after=01890f00-0000-7000-8000-000000000301", dnsZoneListOperation, true},
		{http.MethodPost, dnsZoneBase, dnsZoneCreateOperation, true},
		{http.MethodGet, dnsZoneBase + zone, dnsZoneReadOperation, true},
		{http.MethodPatch, dnsZoneBase + zone, dnsZoneUpdateOperation, true},
		{http.MethodDelete, dnsZoneBase + zone, dnsZoneDeleteOperation, true},
		{http.MethodPut, dnsZoneBase + zone, "", true},
		{http.MethodGet, dnsZoneBase + "?limit=101", "", false},
		{http.MethodGet, dnsZoneBase + "?limit=1&limit=2", "", false},
		{http.MethodGet, dnsZoneBase + "?other=1", "", false},
		{http.MethodGet, dnsZoneBase + zone + "?x=1", dnsZoneReadOperation, false},
		{http.MethodGet, dnsZoneBase + "/not-an-id", "", false},
		{http.MethodGet, dnsZoneBase + zone + "/records", "", false},
		{http.MethodGet, strings.Replace(dnsZoneBase, "/dns/zones", "/dns/zone", 1), "", false},
		{http.MethodGet, strings.ToUpper(dnsZoneBase[:5]) + dnsZoneBase[5:], "", false},
	} {
		path, ok := parseDNSZonePath(httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil))
		if ok != test.ok || (ok && path.operation != test.operation) {
			t.Errorf("%s %s = %q, %v; want %q, %v", test.method, test.target, path.operation, ok, test.operation, test.ok)
		}
	}
	if path, _ := parseDNSZonePath(httptest.NewRequestWithContext(t.Context(), http.MethodGet, dnsZoneBase, nil)); path.limit !=
		dnszone.DefaultPage {
		t.Errorf("default page = %d", path.limit)
	}
}

func TestParseDNSZoneDefinition(t *testing.T) {
	t.Parallel()
	parse := func(body string, create bool) (dnszone.Definition, bool) {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, dnsZoneBase, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		return parseDNSZoneDefinition(httptest.NewRecorder(), request, create)
	}
	definition, ok := parse(`{"domain":"corp.internal","failure_mode":"closed","resolvers":[`+
		`{"device_id":"01890f00-0000-7000-8000-000000000401","port":5335},{"address":"1.1.1.1","port":53}],`+
		`"device_groups":["01890f00-0000-7000-8000-000000000501"],"search_position":2,"public_confirmed":false}`, true)
	if !ok || definition.Domain != "corp.internal" || definition.FailureMode != dnszone.FailClosed ||
		len(definition.Resolvers) != 2 || !definition.Resolvers[0].IsDevice() || definition.Resolvers[0].Port != 5335 ||
		definition.Resolvers[1].Address != netip.MustParseAddr("1.1.1.1") || len(definition.Groups) != 1 ||
		definition.SearchPosition == nil || *definition.SearchPosition != 2 {
		t.Fatalf("definition = %+v, %v", definition, ok)
	}
	for name, body := range map[string]string{
		"no domain to create": `{"failure_mode":"open","resolvers":[{"address":"1.1.1.1","port":53}],"device_groups":[]}`,
		"no groups":           `{"domain":"a.lan","failure_mode":"open","resolvers":[{"address":"1.1.1.1","port":53}]}`,
		"both kinds": `{"domain":"a.lan","failure_mode":"open","resolvers":[{"address":"1.1.1.1",` +
			`"device_id":"01890f00-0000-7000-8000-000000000401","port":53}],"device_groups":[]}`,
		"no port":       `{"domain":"a.lan","failure_mode":"open","resolvers":[{"address":"1.1.1.1"}],"device_groups":[]}`,
		"uncanonical":   `{"domain":"a.lan","failure_mode":"open","resolvers":[{"address":"001.1.1.1","port":53}],"device_groups":[]}`,
		"unknown field": `{"domain":"a.lan","failure_mode":"open","resolvers":[],"device_groups":[],"other":1}`,
		"bad group":     `{"domain":"a.lan","failure_mode":"open","resolvers":[{"address":"1.1.1.1","port":53}],"device_groups":["x"]}`,
		"five resolvers": `{"domain":"a.lan","failure_mode":"open","device_groups":[],"resolvers":[` +
			strings.Repeat(`{"address":"1.1.1.1","port":53},`, 4) + `{"address":"1.1.1.1","port":53}]}`,
	} {
		if _, ok := parse(body, true); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if update, ok := parse(`{"failure_mode":"open","resolvers":[{"address":"1.1.1.1","port":53}],`+
		`"device_groups":[]}`, false); !ok || update.Domain != "" {
		t.Errorf("update without a domain = %+v, %v", update, ok)
	}
}

func TestClassifyDNSZoneError(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]string{
		dnszone.ErrForbidden:                                 "forbidden",
		dnszone.ErrNotFound:                                  "dns_zone_not_found",
		dnszone.ErrVersionConflict:                           "version_conflict",
		dnszone.ErrDisabled:                                  "dns_zones_disabled",
		dnszone.ErrRootUnavailable:                           "dns_root_zone_unavailable",
		dnszone.ErrDomainTaken:                               "dns_zone_exists",
		dnszone.ErrZoneLimit:                                 "dns_zone_limit",
		dnszone.ErrSearchLimit:                               "dns_search_limit",
		dnszone.ErrPublicUnconfirmed:                         "dns_zone_public_unconfirmed",
		dnszone.ErrDomainCoversControl:                       "dns_zone_covers_control",
		dnszone.ErrResolverNotEligible:                       "dns_resolver_not_eligible",
		dnszone.ErrResolverPeerLimit:                         "dns_resolver_peer_limit",
		dnszone.ErrGroupNotFound:                             "device_group_not_found",
		dnszone.ErrDomainSpecialUse:                          "dns_zone_special_use",
		dnszone.ErrDomainPublicSuffix:                        "dns_zone_public_suffix",
		dnszone.ErrDomainMeshSuffix:                          "dns_zone_mesh_suffix",
		dnszone.ErrResolverNotInternet:                       "dns_resolver_not_internet",
		dnszone.ErrInvalid:                                   "invalid_request",
		errors.Join(dnszone.ErrUnavailable, errors.New("x")): "temporarily_unavailable",
	} {
		if got := classifyDNSZoneError(err).Code; got != want {
			t.Errorf("%v = %q, want %q", err, got, want)
		}
	}
}
