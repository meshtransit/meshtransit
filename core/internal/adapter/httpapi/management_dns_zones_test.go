package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/ratelimit"
)

const dnsZoneBase = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/" +
	"01890f00-0000-7000-8000-000000000201/dns/zones"

func TestParseDNSZonePath(t *testing.T) {
	t.Parallel()
	zone := "/01890f00-0000-7000-8000-000000000301"
	name := "/01890f00-0000-7000-8000-000000000601"
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
		{http.MethodGet, dnsZoneBase + zone + "/status", dnsZoneStatusOperation, true},
		{http.MethodPost, dnsZoneBase + zone + "/status", "", true},
		{http.MethodGet, dnsZoneBase + zone + "/status?x=1", dnsZoneStatusOperation, false},
		{http.MethodGet, dnsZoneBase + zone + "/status" + name, "", false},
		{http.MethodGet, strings.Replace(dnsZoneBase, "/dns/zones", "/dns/zone", 1), "", false},
		{http.MethodGet, strings.ToUpper(dnsZoneBase[:5]) + dnsZoneBase[5:], "", false},
		{http.MethodDelete, dnsZoneBase + zone + "?with_names=true", dnsZoneDeleteOperation, true},
		{http.MethodDelete, dnsZoneBase + zone + "?with_names=false", dnsZoneDeleteOperation, false},
		{http.MethodPatch, dnsZoneBase + zone + "?with_names=true", dnsZoneUpdateOperation, false},
		{http.MethodGet, dnsZoneBase + zone + "/names", dnsNameListOperation, true},
		{http.MethodGet, dnsZoneBase + zone + "/names?q=wiki&limit=50&after=" + name[1:], dnsNameListOperation, true},
		{http.MethodGet, dnsZoneBase + zone + "/names?after=not-an-id", "", false},
		{http.MethodGet, dnsZoneBase + "?q=wiki", "", false},
		{http.MethodPost, dnsZoneBase + zone + "/names", dnsNameCreateOperation, true},
		{http.MethodGet, dnsZoneBase + zone + "/names" + name, dnsNameReadOperation, true},
		{http.MethodPatch, dnsZoneBase + zone + "/names" + name, dnsNameUpdateOperation, true},
		{http.MethodDelete, dnsZoneBase + zone + "/names" + name, dnsNameDeleteOperation, true},
		{http.MethodPost, dnsZoneBase + zone + "/names/actions/apply", dnsNameApplyOperation, true},
		{http.MethodGet, dnsZoneBase + zone + "/names/actions/apply", "", true},
		{http.MethodPost, dnsZoneBase + zone + "/names/actions/import", "", false},
		{http.MethodGet, dnsZoneBase + zone + "/names/not-an-id", "", false},
		{http.MethodGet, dnsZoneBase + "/not-an-id/names", "", false},
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
		definition, _, ok := parseDNSZoneDefinition(httptest.NewRecorder(), request, create)
		return definition, ok
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
		`"device_groups":[]}`, false); !ok || update.Domain != "" || update.OtherNames != "" {
		t.Errorf("update without a domain = %+v, %v", update, ok)
	}
	nxdomain, ok := parse(`{"domain":"corp.internal","other_names":"nxdomain","resolvers":[],"device_groups":[]}`, true)
	if !ok || nxdomain.OtherNames != dnszone.OtherNXDomain || nxdomain.FailureMode != "" {
		t.Errorf("an nxdomain zone = %+v, %v", nxdomain, ok)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, dnsZoneBase, strings.NewReader(
		`{"domain":"dev.corp.internal","other_names":"host","adopt_names":true,"resolvers":[],"device_groups":[]}`))
	request.Header.Set("Content-Type", "application/json")
	if _, adopt, ok := parseDNSZoneDefinition(httptest.NewRecorder(), request, true); !ok || !adopt {
		t.Errorf("adopt_names on create = %v, %v", adopt, ok)
	}
	if _, ok := parse(`{"other_names":"host","adopt_names":true,"resolvers":[],"device_groups":[]}`, false); ok {
		t.Error("adopt_names on update accepted")
	}
	if _, ok := parse(`{"domain":"a.lan","other_names":"refuse","resolvers":[],"device_groups":[]}`, true); ok {
		t.Error("an unknown kind accepted")
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
		dnszone.ErrNXDomainPublic:                            "dns_zone_other_names_public",
		dnszone.ErrZoneHoldsNames:                            "dns_zone_holds_names",
		dnszone.ErrNameNotFound:                              "dns_name_not_found",
		dnszone.ErrNameTaken:                                 "dns_name_conflict",
		dnszone.ErrNameInOtherZone:                           "dns_name_in_other_zone",
		dnszone.ErrNameLimit:                                 "dns_name_limit",
		dnszone.ErrNameTargetInvalid:                         "dns_name_target_invalid",
		dnszone.ErrShareTargetInvalid:                        "dns_share_target_invalid",
		dnszone.ErrCNAMEAtApex:                               "dns_cname_at_apex",
		dnszone.ErrCNAMELoop:                                 "dns_cname_loop",
		dnszone.ErrInvalid:                                   "invalid_request",
		errors.Join(dnszone.ErrUnavailable, errors.New("x")): "temporarily_unavailable",
	} {
		if got := classifyDNSZoneError(err).Code; got != want {
			t.Errorf("%v = %q, want %q", err, got, want)
		}
	}
}

// countingDNSZones counts the calls that reach the zone service.
type countingDNSZones struct {
	calls int
	// settingsExpected and settingsGroups are the last settings change.
	settingsExpected int64
	settingsGroups   []devicegroup.ID
}

func (zones *countingDNSZones) ReadSettings(context.Context, accountsession.Session, network.Scope) (
	dnszone.Settings, error,
) {
	zones.calls++
	group, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000701")
	return dnszone.Settings{Version: 3, UnmanagedGroups: []dnszone.Group{{ID: group, Name: "Contractors",
		State: "active"}}}, nil
}

func (zones *countingDNSZones) ChangeSettings(_ context.Context, _ accountsession.Session, _ network.Scope,
	expected int64, groups []devicegroup.ID, _ publicid.ID,
) (dnszone.SettingsResult, error) {
	zones.calls++
	zones.settingsExpected, zones.settingsGroups = expected, groups
	return dnszone.SettingsResult{Settings: dnszone.Settings{Version: expected + 1}, Changed: true}, nil
}

func (zones *countingDNSZones) List(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	int) (dnszone.Listing, error) {
	zones.calls++
	return dnszone.Listing{}, nil
}

func (zones *countingDNSZones) Read(context.Context, accountsession.Session, network.Scope,
	dnszone.ID) (dnszone.Reading, error) {
	zones.calls++
	return dnszone.Reading{}, dnszone.ErrNotFound
}

func (zones *countingDNSZones) Create(context.Context, accountsession.Session, network.Scope, dnszone.Definition,
	bool, publicid.ID) (dnszone.Result, error) {
	zones.calls++
	return dnszone.Result{}, dnszone.ErrDisabled
}

func (zones *countingDNSZones) Update(context.Context, accountsession.Session, network.Scope, dnszone.ID, int64,
	dnszone.Definition, publicid.ID) (dnszone.Result, error) {
	zones.calls++
	return dnszone.Result{}, dnszone.ErrDisabled
}

func (zones *countingDNSZones) Delete(context.Context, accountsession.Session, network.Scope, dnszone.ID, int64,
	bool, publicid.ID) (dnszone.Result, error) {
	zones.calls++
	return dnszone.Result{}, dnszone.ErrDisabled
}

func (zones *countingDNSZones) ListNames(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	dnszone.NameID, string, int) (dnszone.NameListing, error) {
	zones.calls++
	return dnszone.NameListing{}, nil
}

func (zones *countingDNSZones) ReadName(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	dnszone.NameID) (dnszone.NameReading, error) {
	zones.calls++
	return dnszone.NameReading{}, dnszone.ErrNameNotFound
}

func (zones *countingDNSZones) CreateName(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	dnszone.NameDefinition, publicid.ID) (dnszone.NameOutcome, error) {
	zones.calls++
	return dnszone.NameOutcome{}, dnszone.ErrDisabled
}

func (zones *countingDNSZones) UpdateName(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	dnszone.NameID, int64, dnszone.NameDefinition, publicid.ID) (dnszone.NameOutcome, error) {
	zones.calls++
	return dnszone.NameOutcome{}, dnszone.ErrDisabled
}

func (zones *countingDNSZones) DeleteName(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	dnszone.NameID, int64, publicid.ID) (dnszone.NameOutcome, error) {
	zones.calls++
	return dnszone.NameOutcome{}, dnszone.ErrDisabled
}

func (zones *countingDNSZones) ApplyNames(context.Context, accountsession.Session, network.Scope, dnszone.ID,
	[]dnszone.NameOperation, publicid.ID) (dnszone.NameResult, error) {
	zones.calls++
	return dnszone.NameResult{}, &dnszone.OperationError{Index: 1, Err: dnszone.ErrNameTaken}
}

// TestDNSZoneWritesAreLimitedPerNetworkAndPerson: every change takes one
// token of the person's own budget for the Network (10, one back each 6 s)
// before it reaches the service; an exhausted budget answers 429; reads
// take none.
func TestDNSZoneWritesAreLimitedPerNetworkAndPerson(t *testing.T) {
	t.Parallel()
	zones := &countingDNSZones{}
	var changes []ratelimit.Subject
	deny := false
	options := validManagementHandlerOptions(t)
	options.DNSZones = zones
	options.RateLimiter = managementRateLimiterFunc(func(_ context.Context, subject ratelimit.Subject,
		policy ratelimit.Policy) (ratelimit.Decision, error) {
		if subject.Kind() != ratelimit.SubjectNetworkChange {
			return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
		}
		if policy.Capacity() != 10 || policy.RefillInterval() != dnsZoneWriteRefill {
			t.Errorf("zone write policy = %d per %s", policy.Capacity(), policy.RefillInterval())
		}
		changes = append(changes, subject)
		if deny {
			return ratelimit.NewDecision(false, policy.Capacity(), 0, dnsZoneWriteRefill)
		}
		return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
	})
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"domain":"corp.internal","failure_mode":"open","resolvers":[{"address":"1.1.1.1","port":53}],` +
		`"device_groups":[]}`
	zone := dnsZoneBase + "/01890f00-0000-7000-8000-000000000301"
	send := func(method, target, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, newManagementRequest(t, method, target, body))
		return recorder
	}
	send(http.MethodGet, dnsZoneBase, "")
	send(http.MethodPost, dnsZoneBase, body)
	send(http.MethodPatch, zone, body)
	send(http.MethodDelete, zone, "")
	if len(changes) != 3 || zones.calls != 4 {
		t.Fatalf("budget taken %d times, service called %d times", len(changes), zones.calls)
	}
	// Name changes take the same budget; name reads take none.
	nameBody := `{"label":"git","kind":"address","addresses":["10.0.5.20"]}`
	send(http.MethodGet, zone+"/names", "")
	send(http.MethodPost, zone+"/names", nameBody)
	applied := send(http.MethodPost, zone+"/names/actions/apply", `{"operations":[`+
		`{"op":"create","label":"wiki","kind":"cname","cname":"corp.atlassian.net"},`+
		`{"op":"delete","dns_name_id":"01890f00-0000-7000-8000-000000000601","version":2}]}`)
	if !strings.Contains(applied.Body.String(), `"operation_index":1`) ||
		!strings.Contains(applied.Body.String(), `"dns_name_conflict"`) {
		t.Fatalf("apply = %d %s", applied.Code, applied.Body.String())
	}
	if len(changes) != 5 || zones.calls != 7 || changes[4].DigestString() != changes[0].DigestString() {
		t.Fatalf("with names: budget taken %d times, service called %d times", len(changes), zones.calls)
	}
	if changes[0].DigestString() != changes[1].DigestString() || changes[1].DigestString() != changes[2].DigestString() {
		t.Fatal("changes of one person to one Network use different budgets")
	}
	deny = true
	limited := send(http.MethodPost, dnsZoneBase, body)
	if limited.Code != http.StatusTooManyRequests || !strings.Contains(limited.Body.String(), `"rate_limited"`) ||
		limited.Header().Get("Retry-After") != "6" || zones.calls != 7 {
		t.Fatalf("limited = %d %s %v; service calls %d", limited.Code, limited.Body.String(), limited.Header(),
			zones.calls)
	}
	// A malformed change is refused before it takes a token.
	if malformed := send(http.MethodPost, dnsZoneBase, `{}`); malformed.Code != http.StatusBadRequest ||
		len(changes) != 6 {
		t.Fatalf("malformed = %d, budget taken %d times", malformed.Code, len(changes))
	}
}

// The Network's DNS settings: GET reads them with their version as ETag,
// PUT replaces the unmanaged Device Groups at the version If-Match names,
// "0" before the first change, and takes a write token (DNS design D5b).
func TestDNSSettingsReadAndReplace(t *testing.T) {
	t.Parallel()
	zones := &countingDNSZones{}
	options := validManagementHandlerOptions(t)
	options.DNSZones = zones
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	settings := strings.TrimSuffix(dnsZoneBase, "/zones") + "/settings"
	send := func(method, ifMatch, body string) *httptest.ResponseRecorder {
		request := newManagementRequest(t, method, settings, body)
		if ifMatch == "" {
			request.Header.Del("If-Match")
		} else {
			request.Header.Set("If-Match", ifMatch)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	read := send(http.MethodGet, "", "")
	if read.Code != http.StatusOK || read.Header().Get("ETag") != `"3"` ||
		!strings.Contains(read.Body.String(), `"unmanaged_device_groups":[{"device_group_id":"01890f00-0000-7000-8000-000000000701","name":"Contractors","state":"active"}]`) {
		t.Fatalf("read = %d %v %s", read.Code, read.Header(), read.Body.String())
	}
	body := `{"unmanaged_device_group_ids":["01890f00-0000-7000-8000-000000000701"]}`
	replaced := send(http.MethodPut, `"0"`, body)
	if replaced.Code != http.StatusOK || replaced.Header().Get("ETag") != `"1"` || zones.settingsExpected != 0 ||
		len(zones.settingsGroups) != 1 || !strings.Contains(replaced.Body.String(), `"changed":true`) {
		t.Fatalf("replace = %d %v %s", replaced.Code, replaced.Header(), replaced.Body.String())
	}
	calls := zones.calls
	for name, failing := range map[string]*httptest.ResponseRecorder{
		"no precondition": send(http.MethodPut, "", body),
		"unknown field":   send(http.MethodPut, `"1"`, `{"unmanaged_device_group_ids":[],"x":1}`),
		"no groups field": send(http.MethodPut, `"1"`, `{}`),
		"not a group id":  send(http.MethodPut, `"1"`, `{"unmanaged_device_group_ids":["x"]}`),
		"wrong method":    send(http.MethodPatch, `"1"`, body),
	} {
		if failing.Code < 400 || failing.Code >= 500 {
			t.Errorf("%s: %d %s", name, failing.Code, failing.Body.String())
		}
	}
	if zones.calls != calls {
		t.Fatalf("refused requests reached the service: %d calls", zones.calls-calls)
	}
}
