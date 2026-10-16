package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type stubReader struct {
	devices []inventory.Device
	record  inventory.Record
	query   inventory.Query
}

func (reader *stubReader) ReadDevices(_ context.Context, _ accountsession.Session, scope network.Scope,
	query inventory.Query,
) (inventory.ReadResult, error) {
	reader.query = query
	code, _ := identity.ParseDisplayCode("000000000101")
	return inventory.ReadResult{Scope: scope, Revision: 3, Devices: reader.devices, WorkspaceCode: code,
		NetworkCode: code}, nil
}

func (reader *stubReader) ReadDevice(context.Context, accountsession.Session, network.Scope, node.ID) (
	inventory.Record, error,
) {
	return reader.record, nil
}

func (reader *stubReader) ReadDeviceNames(_ context.Context, _ accountsession.Session, _ network.Scope,
	ids []node.ID,
) (map[node.ID]string, error) {
	names := map[node.ID]string{}
	for _, id := range ids {
		names[id] = "peer"
	}
	return names, nil
}

func testScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func testDevice(t *testing.T, id, hostname string) inventory.Device {
	t.Helper()
	parsedID, err := node.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	name, err := node.ParseHostname(hostname)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, time.October, 16, 0, 0, 0, 0, time.UTC)
	device, err := inventory.NewDevice(parsedID, name, "active", false, 1, created, created, created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return device
}

var testNow = time.Date(2026, time.October, 16, 10, 0, 0, 0, time.UTC)

func testService(t *testing.T, reader *stubReader) (*inventory.Service, accountsession.Session) {
	t.Helper()
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000601")
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: testNow.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: testNow.Add(time.Hour), AbsoluteExpiresAt: testNow.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := inventory.NewService(reader, fixedClock{now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return service, session
}

func TestQueryIsValid(t *testing.T) {
	t.Parallel()
	device := node.ID{}
	for _, test := range []struct {
		name  string
		query inventory.Query
		valid bool
	}{
		{"first page", inventory.Query{Limit: 10}, true},
		{"prefix", inventory.Query{Limit: 10, NamePrefix: "poc-0.1"}, true},
		{"active", inventory.Query{Limit: 10, State: inventory.StateActive}, true},
		{"inactive", inventory.Query{Limit: 100, State: inventory.StateInactive}, true},
		{"empty page", inventory.Query{}, false},
		{"page too large", inventory.Query{Limit: inventory.MaximumPageSize + 1}, false},
		{"upper case", inventory.Query{Limit: 10, NamePrefix: "Poc"}, false},
		{"LIKE wildcard", inventory.Query{Limit: 10, NamePrefix: "po%"}, false},
		{"LIKE single", inventory.Query{Limit: 10, NamePrefix: "po_"}, false},
		{"unknown state", inventory.Query{Limit: 10, State: "online"}, false},
		{"half cursor", inventory.Query{Limit: 10, Cursor: inventory.Cursor{AfterHostname: "a", After: device}}, false},
	} {
		if test.query.IsValid() != test.valid {
			t.Errorf("%s: valid = %t", test.name, !test.valid)
		}
	}
}

func TestListFollowsNameOrder(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	reader := &stubReader{devices: []inventory.Device{
		testDevice(t, "01890f00-0000-7000-8000-000000000903", "poc-01"),
		testDevice(t, "01890f00-0000-7000-8000-000000000901", "poc-02"),
		testDevice(t, "01890f00-0000-7000-8000-000000000902", "poc-02"),
	}}
	service, session := testService(t, reader)
	page, err := service.List(t.Context(), session, scope, inventory.Query{Limit: 2, NamePrefix: "poc"})
	if err != nil {
		t.Fatal(err)
	}
	next, more := page.Next()
	if len(page.Devices()) != 2 || reader.query.Limit != 3 || !more || next.AfterHostname != "poc-02" ||
		next.After.String() != "01890f00-0000-7000-8000-000000000901" {
		t.Fatalf("page %d devices, asked %d, next %+v", len(page.Devices()), reader.query.Limit, next)
	}

	for name, devices := range map[string][]inventory.Device{
		"out of order": {
			testDevice(t, "01890f00-0000-7000-8000-000000000901", "poc-02"),
			testDevice(t, "01890f00-0000-7000-8000-000000000903", "poc-01"),
		},
		"repeated": {
			testDevice(t, "01890f00-0000-7000-8000-000000000901", "poc-02"),
			testDevice(t, "01890f00-0000-7000-8000-000000000901", "poc-02"),
		},
		"outside the prefix": {testDevice(t, "01890f00-0000-7000-8000-000000000901", "web-01")},
	} {
		reader := &stubReader{devices: devices}
		service, session := testService(t, reader)
		if _, err := service.List(t.Context(), session, scope, inventory.Query{Limit: 10, NamePrefix: "poc"}); !errors.Is(
			err, inventory.ErrInvalidResult) {
			t.Errorf("%s: %v", name, err)
		}
	}

	cursor := inventory.Cursor{AfterHostname: "poc-02", After: next.After}
	reader = &stubReader{devices: []inventory.Device{testDevice(t, "01890f00-0000-7000-8000-000000000901", "poc-02")}}
	service, session = testService(t, reader)
	if _, err := service.List(t.Context(), session, scope, inventory.Query{Limit: 10, Cursor: cursor}); !errors.Is(
		err, inventory.ErrInvalidResult) {
		t.Fatalf("a page repeated the Device it continues after: %v", err)
	}
}

func TestGetChecksTheRecord(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	device := testDevice(t, "01890f00-0000-7000-8000-000000000901", "poc-02")
	code, _ := identity.ParseDisplayCode("000000000101")
	keyID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a01")
	found := inventory.Record{Scope: scope, Device: device, Found: true, WorkspaceCode: code, NetworkCode: code,
		Enrollment: inventory.Enrollment{ByKey: true, KeyID: keyID}}
	for _, test := range []struct {
		name   string
		record inventory.Record
		want   error
	}{
		{"found", found, nil},
		{"missing", inventory.Record{Scope: scope, WorkspaceCode: code, NetworkCode: code}, inventory.ErrNotFound},
		{"another scope", inventory.Record{WorkspaceCode: code, NetworkCode: code, Found: true}, inventory.ErrInvalidResult},
		{"key without ID", inventory.Record{Scope: scope, Device: device, Found: true, WorkspaceCode: code,
			NetworkCode: code, Enrollment: inventory.Enrollment{ByKey: true}}, inventory.ErrInvalidResult},
	} {
		service, session := testService(t, &stubReader{record: test.record})
		record, err := service.Get(t.Context(), session, scope, device.ID())
		if !errors.Is(err, test.want) || test.want == nil && record.Device.ID() != device.ID() {
			t.Errorf("%s: %v", test.name, err)
		}
	}
	other, _ := node.ParseID("01890f00-0000-7000-8000-000000000902")
	service, session := testService(t, &stubReader{record: found})
	if _, err := service.Get(t.Context(), session, scope, other); !errors.Is(err, inventory.ErrInvalidResult) {
		t.Fatalf("storage answered with another Device: %v", err)
	}
}

func TestNamesStaysBounded(t *testing.T) {
	t.Parallel()
	scope := testScope(t)
	service, session := testService(t, &stubReader{})
	id, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
	if names, err := service.Names(t.Context(), session, scope, []node.ID{id}); err != nil || names[id] != "peer" {
		t.Fatalf("Names() = %v, %v", names, err)
	}
	if names, err := service.Names(t.Context(), session, scope, nil); err != nil || len(names) != 0 {
		t.Fatalf("no IDs = %v, %v", names, err)
	}
	if _, err := service.Names(t.Context(), session, scope, make([]node.ID, inventory.MaximumNames+1)); !errors.Is(
		err, inventory.ErrInvalidRequest) {
		t.Fatalf("too many IDs: %v", err)
	}
}
