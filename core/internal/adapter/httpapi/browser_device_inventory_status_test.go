package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/inventory"
)

// countingObservations counts batch loads, so a test can prove the list
// reads delivery records once per page.
type countingObservations struct {
	byID  map[node.ID]distribution.Observation
	err   error
	loads int
	ids   []node.ID
}

func (loader *countingObservations) LoadObservations(_ context.Context, ids []node.ID) (
	[]distribution.Observation, error) {
	loader.loads++
	loader.ids = append([]node.ID(nil), ids...)
	if loader.err != nil {
		return nil, loader.err
	}
	result := make([]distribution.Observation, len(ids))
	for index, id := range ids {
		result[index] = loader.byID[id]
	}
	return result, nil
}

func statusTestDevice(t *testing.T, suffix, hostname, state string) inventory.Device {
	t.Helper()
	id, _ := node.ParseID("01890f00-0000-7000-8000-000000000" + suffix)
	name, _ := node.ParseHostname(hostname)
	created := time.Date(2026, time.October, 1, 8, 0, 0, 0, time.UTC)
	device, err := inventory.NewDevice(id, name, state, false, 1, created, created, created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return device
}

type statusTestCase struct {
	browser      *BrowserManagement
	reader       *distributionTestReader
	observations *countingObservations
}

func deviceListStatusTest(t *testing.T) statusTestCase {
	t.Helper()
	options, fixture := browserManagementTestOptions(t)
	scope, _ := parseDeviceInventoryPath(browserManagementReadRequest(t, deviceInventoryTestPath()))
	online := statusTestDevice(t, "901", "db-01", "active")
	behind := statusTestDevice(t, "902", "web-01", "suspended")
	expired := statusTestDevice(t, "903", "old-01", "expired")
	// Pages come in name order.
	listed := &inventoryTestReader{scope: scope, devices: []inventory.Device{online, expired, behind}}
	devices, err := inventory.NewService(listed, fixture)
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	observation := func(revision int64, live bool) distribution.Observation {
		return distribution.Observation{Known: true, SessionGeneration: 1, NetworkRevision: revision,
			PolicyRevision: 3, DeliveredAt: seen, SeenAt: seen.Add(time.Minute), Online: live}
	}
	reader := &distributionTestReader{target: distribution.Target{Scope: scope, NetworkRevision: 7, PolicyRevision: 3}}
	observations := &countingObservations{byID: map[node.ID]distribution.Observation{
		online.ID(): observation(7, true), behind.ID(): observation(5, true),
	}}
	service, err := distribution.NewService(reader, observations, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Inventory, options.Distribution = devices, service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	return statusTestCase{browser: browser, reader: reader, observations: observations}
}

func TestBrowserDeviceListCarriesStatusInOneBatch(t *testing.T) {
	t.Parallel()
	test := deviceListStatusTest(t)
	response := serveDistributionTest(t, test.browser, deviceInventoryTestPath()+"?include=status")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body)
	}
	if test.reader.reads != 1 || test.observations.loads != 1 || len(test.observations.ids) != 2 {
		t.Fatalf("reads = %d, loads = %d of %d Devices; want one each for the 2 held Devices",
			test.reader.reads, test.observations.loads, len(test.observations.ids))
	}
	var envelope deviceInventoryStatusEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	rows := envelope.Data.Devices
	if len(rows) != 3 || envelope.Data.NetworkRevision == nil || *envelope.Data.NetworkRevision != 7 ||
		!envelope.Data.ObservationsAvailable {
		t.Fatalf("envelope = %s", response.Body)
	}
	if rows[0].Status == nil || rows[0].Status.Status != "in_sync" || !rows[0].Status.Online ||
		rows[0].Status.LastSeenAt == nil || rows[0].Hostname != "db-01" {
		t.Fatalf("online row = %+v", rows[0].Status)
	}
	if rows[2].Status == nil || rows[2].Status.Status != "behind" || *rows[2].Status.DeliveredNetworkRevision != 5 {
		t.Fatalf("behind row = %+v", rows[2].Status)
	}
	if rows[1].Status != nil || !strings.Contains(response.Body.String(), `"state":"expired","is_ephemeral":false`) {
		t.Fatalf("expired row carries a status: %s", response.Body)
	}
}

func TestBrowserDeviceListWithoutIncludeKeepsItsShape(t *testing.T) {
	t.Parallel()
	test := deviceListStatusTest(t)
	response := serveDistributionTest(t, test.browser, deviceInventoryTestPath())
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"status"`) ||
		test.reader.reads != 0 || test.observations.loads != 0 {
		t.Fatalf("plain list = %d %s (reads %d)", response.Code, response.Body, test.reader.reads)
	}
}

func TestBrowserDeviceListStatusFailsSoftAndClosed(t *testing.T) {
	t.Parallel()
	test := deviceListStatusTest(t)
	test.observations.err = errors.New("redis down")
	response := serveDistributionTest(t, test.browser, deviceInventoryTestPath()+"?include=status")
	var envelope deviceInventoryStatusEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || response.Code != http.StatusOK ||
		envelope.Data.ObservationsAvailable || envelope.Data.Devices[0].Status == nil ||
		envelope.Data.Devices[0].Status.Status != "unknown" || envelope.Data.Devices[0].Status.Online {
		t.Fatalf("without deliveries = %d %s", response.Code, response.Body)
	}
	test.reader.err = distribution.ErrUnavailable
	response = serveDistributionTest(t, test.browser, deviceInventoryTestPath()+"?include=status")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"network_revision":null`) ||
		strings.Contains(response.Body.String(), `"status":{`) {
		t.Fatalf("without revisions = %d %s", response.Code, response.Body)
	}
	test.reader.err = distribution.ErrForbidden
	response = serveDistributionTest(t, test.browser, deviceInventoryTestPath()+"?include=status")
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "db-01") {
		t.Fatalf("denied status = %d %s", response.Code, response.Body)
	}
}

func TestBrowserDeviceListRejectsUnknownInclude(t *testing.T) {
	t.Parallel()
	test := deviceListStatusTest(t)
	for _, query := range []string{"?include=peers", "?include=status&include=status", "?include="} {
		if response := serveDistributionTest(t, test.browser, deviceInventoryTestPath()+query); response.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d", query, response.Code)
		}
	}
}

var _ SessionDeviceDistribution = (*distribution.Service)(nil)

// Keep the fake reader signature in step with the domain interface.
var _ distribution.Reader = (*distributionTestReader)(nil)

// fakePageDistribution answers ReadPage with a fixed page, to prove the
// handler refuses a page that does not match its rows.
type fakePageDistribution struct {
	page distribution.Page
	err  error
}

func (fake fakePageDistribution) ReadDevice(context.Context, accountsession.Session, network.Scope,
	node.ID) (distribution.Report, error) {
	return distribution.Report{}, distribution.ErrUnavailable
}

func (fake fakePageDistribution) ReadPage(context.Context, accountsession.Session, network.Scope,
	[]distribution.TargetDevice) (distribution.Page, error) {
	return fake.page, fake.err
}

func deviceListWith(t *testing.T, states []string, reader SessionDeviceDistribution) (*BrowserManagement, *inventoryTestReader) {
	t.Helper()
	options, fixture := browserManagementTestOptions(t)
	scope, _ := parseDeviceInventoryPath(browserManagementReadRequest(t, deviceInventoryTestPath()))
	devices := make([]inventory.Device, len(states))
	for index, state := range states {
		devices[index] = statusTestDevice(t, fmt.Sprintf("9%02d", index+1), fmt.Sprintf("host-%02d", index+1), state)
	}
	listed := &inventoryTestReader{scope: scope, devices: devices}
	service, err := inventory.NewService(listed, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Inventory = service
	if reader != nil {
		options.Distribution = reader
	}
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	return browser, listed
}

func TestBrowserDeviceListStatusReadsNothingForAPageWithoutPolicy(t *testing.T) {
	t.Parallel()
	browser, _ := deviceListWith(t, []string{"expired", "revoked"},
		fakePageDistribution{err: errors.New("must not be called")})
	response := serveDistributionTest(t, browser, deviceInventoryTestPath()+"?include=status&state=inactive")
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"network_revision":null`) ||
		strings.Count(body, `"status":null`) != 2 {
		t.Fatalf("inactive page = %d %s", response.Code, body)
	}
}

func TestBrowserDeviceListStatusRefusesAPageThatDoesNotMatch(t *testing.T) {
	t.Parallel()
	scope, _ := parseDeviceInventoryPath(browserManagementReadRequest(t, deviceInventoryTestPath()))
	other, _ := node.ParseID("01890f00-0000-7000-8000-000000000999")
	for name, fake := range map[string]fakePageDistribution{
		"short":         {page: distribution.Page{Scope: scope, NetworkRevision: 1}},
		"another ID":    {page: distribution.Page{Scope: scope, NetworkRevision: 1, Devices: []distribution.Device{{ID: other}}}},
		"foreign scope": {page: distribution.Page{NetworkRevision: 1, Devices: []distribution.Device{{ID: other}}}},
		"bad evidence":  {err: distribution.ErrInvalidResult},
		"bad request":   {err: distribution.ErrInvalidRequest},
	} {
		browser, _ := deviceListWith(t, []string{"active"}, fake)
		response := serveDistributionTest(t, browser, deviceInventoryTestPath()+"?include=status")
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "host-01") {
			t.Fatalf("%s: %d %s", name, response.Code, response.Body)
		}
	}
}

func TestBrowserDeviceListStatusWithoutADistributionReader(t *testing.T) {
	t.Parallel()
	browser, _ := deviceListWith(t, []string{"active"}, nil)
	response := serveDistributionTest(t, browser, deviceInventoryTestPath()+"?include=status")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":null`) {
		t.Fatalf("no reader = %d %s", response.Code, response.Body)
	}
}

func TestBrowserDeviceListStatusKeepsTheSearch(t *testing.T) {
	t.Parallel()
	browser, listed := deviceListWith(t, []string{"active"}, fakePageDistribution{err: distribution.ErrUnavailable})
	response := serveDistributionTest(t, browser, deviceInventoryTestPath()+"?include=status&q=host&state=active&page_size=5")
	// The inventory reads one row past the page to know whether another follows.
	if response.Code != http.StatusOK || listed.query.NamePrefix != "host" || listed.query.State != "active" ||
		listed.query.Limit != 6 {
		t.Fatalf("search = %d %+v", response.Code, listed.query)
	}
}
