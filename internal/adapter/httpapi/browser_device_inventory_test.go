package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/node/inventory"
)

type inventoryTestReader struct {
	scope network.Scope
	err   error
	reads int
}

func (reader *inventoryTestReader) ReadDevices(_ context.Context, _ accountsession.Session,
	_ network.Scope, _ node.ID, _ int, _ time.Time,
) (inventory.ReadResult, error) {
	reader.reads++
	return inventory.ReadResult{Scope: reader.scope, Revision: 5}, reader.err
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
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || reader.reads != 1 || fixture.auth != 1 || fixture.budgets != 2 ||
		response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Set-Cookie") != "" ||
		strings.Contains(response.Body.String(), managementTokenFixture) {
		t.Fatal("inventory bypassed private read contract", response.Code)
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
	token, err := encodeDeviceInventoryPageToken(scope, inventory.Cursor{After: id, Revision: 5})
	if err != nil {
		t.Fatal(err)
	}
	otherRequest := browserManagementReadRequest(t, strings.Replace(deviceInventoryTestPath(), "000000000201", "000000000202", 1))
	otherScope, _ := parseDeviceInventoryPath(otherRequest)
	if _, _, err := parseDeviceInventoryQuery("page_token="+token, otherScope); err == nil {
		t.Fatal("cross-Network cursor accepted")
	}
	staleToken, err := encodeDeviceInventoryPageToken(scope, inventory.Cursor{After: id, Revision: 4})
	if err != nil {
		t.Fatal(err)
	}
	staleRequest := browserManagementReadRequest(t, deviceInventoryTestPath()+"?page_token="+staleToken)
	staleResponse := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(staleResponse, staleRequest); err != nil || staleResponse.Code != http.StatusConflict {
		t.Fatal("stale inventory revision was disclosed", err, staleResponse.Code)
	}
	for _, query := range []string{"page_size=01", "page_size=101", "page_size=1&page_size=2", "device.read=true", "page_token="} {
		if _, _, err := parseDeviceInventoryQuery(query, scope); err == nil {
			t.Fatal("invalid inventory query accepted", query)
		}
	}
}
