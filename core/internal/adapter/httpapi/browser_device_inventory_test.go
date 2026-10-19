package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/publicid"
)

type inventoryTestReader struct {
	scope   network.Scope
	devices []inventory.Device
	record  inventory.Record
	names   map[node.ID]string
	query   inventory.Query
	err     error
	reads   int
}

func (reader *inventoryTestReader) ReadDevices(_ context.Context, _ accountsession.Session,
	_ network.Scope, query inventory.Query,
) (inventory.ReadResult, error) {
	reader.reads++
	reader.query = query
	return inventory.ReadResult{Scope: reader.scope, Revision: 5, Devices: reader.devices,
		WorkspaceCode: "000000000101", NetworkCode: "000000000201"}, reader.err
}

func (reader *inventoryTestReader) ReadDevice(context.Context, accountsession.Session, network.Scope,
	node.ID,
) (inventory.Record, error) {
	reader.reads++
	return reader.record, reader.err
}

func (reader *inventoryTestReader) ReadDeviceNames(_ context.Context, _ accountsession.Session, _ network.Scope,
	ids []node.ID,
) (map[node.ID]string, error) {
	names := map[node.ID]string{}
	for _, id := range ids {
		if name, known := reader.names[id]; known {
			names[id] = name
		}
	}
	return names, reader.err
}

func deviceInventoryTestPath() string {
	return "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/devices"
}

func TestBrowserDeviceInventoryFreshReadAndDeniedRefresh(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	request := browserManagementReadRequest(t, deviceInventoryTestPath()+"?page_size=1")
	scope, ok := parseDeviceInventoryPath(request)
	if !ok {
		t.Fatal("valid exact scope rejected")
	}
	reader := &inventoryTestReader{scope: scope, devices: []inventory.Device{inventoryTestDevice(t)}}
	service, err := inventory.NewService(reader, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Inventory = service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || reader.reads != 1 || fixture.auth != 1 || fixture.budgets != 2 ||
		response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Set-Cookie") != "" ||
		strings.Contains(response.Body.String(), managementTokenFixture) {
		t.Fatal("inventory bypassed private read contract", response.Code)
	}
	if !strings.Contains(response.Body.String(), `"dns_name":"laptop.000000000101.000000000201.mesh.internal"`) {
		t.Fatalf("inventory has no Device DNS name: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(),
		`"advertised_prefixes":["10.40.0.0/16","2001:db8::/32"],"advertised_prefix_count":3`) {
		t.Fatalf("inventory has no Device offer: %s", response.Body.String())
	}
	reader.err = inventory.ErrForbidden
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || reader.reads != 2 || strings.Contains(response.Body.String(), "devices") {
		t.Fatal("denied read retained inventory")
	}
}

func TestBrowserDeviceInventoryRejectsPrivateTransportAndScopeCursor(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	request := browserManagementReadRequest(t, deviceInventoryTestPath())
	scope, _ := parseDeviceInventoryPath(request)
	reader := &inventoryTestReader{scope: scope}
	service, err := inventory.NewService(reader, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Inventory = service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.Method = http.MethodPost },
		func(request *http.Request) { request.Header.Set("Authorization", "Bearer injected") },
		func(request *http.Request) { request.Header.Set("X-MeshTransit-CSRF", "injected") },
		func(request *http.Request) { request.Header.Set("Origin", "https://foreign.example") },
	} {
		request := browserManagementReadRequest(t, deviceInventoryTestPath())
		mutate(request)
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if !errors.Is(browser.Handle(response, request), ErrInvalidBrowserManagement) || reader.reads != 0 {
			t.Fatal("invalid transport reached inventory")
		}
	}
	id, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
	search := inventory.Query{Limit: 10, NamePrefix: "lap", State: inventory.StateActive}
	cursor := inventory.Cursor{AfterHostname: "laptop.example", After: id}
	token, err := encodeDeviceInventoryPageToken(scope, search, cursor)
	if err != nil {
		t.Fatal(err)
	}
	next, err := parseDeviceInventoryQuery("q=lap&state=active&page_token="+token, scope)
	if err != nil || next.Cursor != cursor || next.Limit != 10 {
		t.Fatalf("the token does not continue its own search: %+v, %v", next, err)
	}
	otherRequest := browserManagementReadRequest(t, strings.Replace(deviceInventoryTestPath(), "000000000201", "000000000202", 1))
	otherScope, _ := parseDeviceInventoryPath(otherRequest)
	for name, test := range map[string]struct {
		query string
		scope network.Scope
	}{
		"another Network":   {"q=lap&state=active&page_token=" + token, otherScope},
		"another name":      {"q=lapt&state=active&page_token=" + token, scope},
		"another state":     {"q=lap&page_token=" + token, scope},
		"token, no filters": {"page_token=" + token, scope},
	} {
		if _, err := parseDeviceInventoryQuery(test.query, test.scope); err == nil {
			t.Errorf("%s: a token continued another search", name)
		}
	}
	for _, query := range []string{
		"page_size=01", "page_size=101", "page_size=1&page_size=2", "device.read=true", "page_token=",
		"q=Laptop", "q=lap%25", "q=lap_", "state=online", "state=", "q=lap&q=web",
	} {
		if _, err := parseDeviceInventoryQuery(query, scope); err == nil {
			t.Fatal("invalid inventory query accepted", query)
		}
	}
	if query, err := parseDeviceInventoryQuery("", scope); err != nil || query.Limit != 10 {
		t.Fatalf("default page = %+v, %v", query, err)
	}
}

func TestBrowserDeviceReadAnswersOneDevice(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	path := deviceInventoryTestPath() + "/01890f00-0000-7000-8000-000000000901"
	request := browserManagementReadRequest(t, path)
	scope, id, ok := parseDeviceItemPath(request)
	if !ok || id.String() != "01890f00-0000-7000-8000-000000000901" {
		t.Fatal("valid Device path rejected")
	}
	keyID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a01")
	creator, _ := publicid.Parse("01890f00-0000-7000-8000-000000000011")
	reader := &inventoryTestReader{record: inventory.Record{Scope: scope, Device: inventoryTestDevice(t), Found: true,
		WorkspaceCode: "000000000101", NetworkCode: "000000000201",
		Enrollment: inventory.Enrollment{ByKey: true, KeyID: keyID, KeyDescription: "router",
			KeyCreatedBy: inventory.Member{PrincipalID: creator, DisplayName: "Trang"}}}}
	service, err := inventory.NewService(reader, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Inventory = service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	body := response.Body.String()
	if response.Code != http.StatusOK || reader.reads != 1 || response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(body, `"dns_name":"laptop.000000000101.000000000201.mesh.internal"`) ||
		!strings.Contains(body, `"enrollment":{"kind":"key","key_id":"01890f00-0000-7000-8000-000000000a01",`+
			`"description":"router","created_by":{"principal_id":"01890f00-0000-7000-8000-000000000011",`+
			`"display_name":"Trang"}}`) {
		t.Fatalf("Device read = %d: %s", response.Code, body)
	}
	reader.record = inventory.Record{Scope: scope, WorkspaceCode: "000000000101", NetworkCode: "000000000201"}
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil || response.Code != http.StatusNotFound ||
		!strings.Contains(response.Body.String(), "device_not_found") {
		t.Fatalf("missing Device = %d %s, %v", response.Code, response.Body, err)
	}
	for _, target := range []string{path + "?x=1", path + "/", deviceInventoryTestPath() + "/not-a-device"} {
		request := browserManagementReadRequest(t, target)
		if _, _, ok := parseDeviceItemPath(request); ok {
			t.Errorf("%s matched", target)
		}
	}
	if !isBrowserManagementOperation(request) {
		t.Fatal("the Device read is not routed to browser management")
	}
}

// inventoryTestDevice is one active Device labeled laptop.
func inventoryTestDevice(t *testing.T) inventory.Device {
	t.Helper()
	id, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
	hostname, _ := node.ParseHostname("laptop.example")
	created := time.Date(2026, time.October, 1, 8, 0, 0, 0, time.UTC)
	device, err := inventory.NewDevice(id, hostname, "active", false, 1, created, created, created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	label, _ := node.ParseDNSLabel("laptop")
	if device, err = device.WithDNSLabel(label); err != nil {
		t.Fatal(err)
	}
	offer := []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}
	if device, err = device.WithOffer(offer, 3); err != nil {
		t.Fatal(err)
	}
	return device
}
