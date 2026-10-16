package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/shared/policydigest"
)

type distributionTestReader struct {
	target distribution.Target
	err    error
	reads  int
}

func (reader *distributionTestReader) ReadTarget(_ context.Context, _ accountsession.Session,
	_ network.Scope, _ node.ID,
) (distribution.Target, error) {
	reader.reads++
	return reader.target, reader.err
}

type distributionTestObservations struct{ observations []distribution.Observation }

func (loader distributionTestObservations) LoadObservations(_ context.Context, ids []node.ID) (
	[]distribution.Observation, error) {
	return loader.observations[:len(ids)], nil
}

const distributionTestDevice = "01890f00-0000-7000-8000-000000000301"

func deviceDetailTestPath(kind string) string {
	return deviceInventoryTestPath() + "/" + distributionTestDevice + "/" + kind
}

// distributionTestBrowser serves one active Device whose report reaches a
// Device of the Network directly, another through the sgp relay, and a
// shared Device of another Network directly.
func distributionTestBrowser(t *testing.T, reportedAt time.Time) (*BrowserManagement, *distributionTestReader) {
	t.Helper()
	options, fixture := browserManagementTestOptions(t)
	scope, _ := parseDeviceInventoryPath(browserManagementReadRequest(t, deviceInventoryTestPath()))
	device, _ := node.ParseID(distributionTestDevice)
	direct, _ := node.ParseID("01890f00-0000-7000-8000-000000000302")
	relayed, _ := node.ParseID("01890f00-0000-7000-8000-000000000303")
	shared, _ := node.ParseID("01890f00-0000-7000-8000-000000000304")
	reader := &distributionTestReader{target: distribution.Target{Scope: scope, NetworkRevision: 7, PolicyRevision: 3,
		Devices: []distribution.TargetDevice{{ID: device, Hostname: "poc-01", State: "active"}}}}
	delivered := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	digest, grants, err := policydigest.Compute(nil)
	if err != nil {
		t.Fatal(err)
	}
	filter := distribution.FilterSummary{Digest: digest, Grants: grants}
	observations := distributionTestObservations{observations: []distribution.Observation{{
		Known: true, SessionGeneration: 1, NetworkRevision: 7, PolicyRevision: 3,
		DeliveredAt: delivered, SeenAt: delivered.Add(time.Minute), Online: true,
		Filter: filter, Enforced: filter, AppliedAt: delivered, ReportedAt: delivered.Add(time.Second),
		Paths: &distribution.PathReport{ReportedAt: reportedAt, Interval: time.Minute, Peers: []distribution.PeerPath{
			{PeerID: direct, Kind: distribution.PathDirect, DirectBytes: 90},
			{PeerID: relayed, Kind: distribution.PathRelay, RelayRegion: 1, RelayCode: "sgp",
				RelayReason: distribution.RelayNoResponse, RelayBytes: 30},
			{PeerID: shared, External: true, Kind: distribution.PathDirect, DirectBytes: 10},
		}},
	}}}
	service, err := distribution.NewService(reader, observations, fixture)
	if err != nil {
		t.Fatal(err)
	}
	names := &inventoryTestReader{scope: scope, names: map[node.ID]string{direct: "web-01", relayed: "db-01"}}
	devices, err := inventory.NewService(names, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Distribution, options.Inventory = service, devices
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	return browser, reader
}

func serveDistributionTest(t *testing.T, browser *BrowserManagement, target string) *continuationStatusRecorder {
	t.Helper()
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, browserManagementReadRequest(t, target)); err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	return response
}

func TestBrowserDeviceStatusReportsOneDevice(t *testing.T) {
	t.Parallel()
	browser, reader := distributionTestBrowser(t, time.UnixMilli(1_800_000_000_000))
	response := serveDistributionTest(t, browser, deviceDetailTestPath("status"))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status = %d: %s", response.Code, response.Body)
	}
	var envelope deviceStatusEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	device, paths := envelope.Data.Device, envelope.Data.Device.Paths
	if envelope.Data.NetworkRevision != 7 || device.Status != "in_sync" || device.Enforcement.Status != "enforced" ||
		paths == nil || paths.ReportedPeers != 3 || paths.Direct != 2 || paths.Unknown != 0 || paths.Limited ||
		len(paths.Relays) != 1 || paths.Relays[0].Peers != 1 || *paths.Relays[0].RelayCode != "sgp" {
		t.Fatalf("status = %s", response.Body)
	}
	if strings.Contains(response.Body.String(), "01890f00-0000-7000-8000-000000000302") {
		t.Fatal("the status lists peers; they are read page by page")
	}
	reader.target.Devices = nil
	if response := serveDistributionTest(t, browser, deviceDetailTestPath("status")); response.Code != http.StatusNotFound ||
		!strings.Contains(response.Body.String(), "device_not_connectable") {
		t.Fatalf("removed Device = %d %s", response.Code, response.Body)
	}
	reader.err = distribution.ErrForbidden
	if response := serveDistributionTest(t, browser, deviceDetailTestPath("status")); response.Code != http.StatusForbidden {
		t.Fatalf("denied read = %d", response.Code)
	}
}

func TestBrowserDevicePeersPageTheReport(t *testing.T) {
	t.Parallel()
	reportedAt := time.UnixMilli(1_800_000_000_000)
	browser, _ := distributionTestBrowser(t, reportedAt)
	var first devicePeersEnvelope
	response := serveDistributionTest(t, browser, deviceDetailTestPath("peers")+"?page_size=2")
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &first) != nil {
		t.Fatalf("first page = %d %s", response.Code, response.Body)
	}
	peers := first.Data.Peers
	if first.Data.ReportedPeers != 3 || len(peers) != 2 || first.NextPageToken == "" ||
		peers[0].Name == nil || *peers[0].Name != "web-01" || peers[1].Name == nil || *peers[1].Name != "db-01" ||
		*peers[1].RelayCode != "sgp" {
		t.Fatalf("first page = %s", response.Body)
	}
	var second devicePeersEnvelope
	response = serveDistributionTest(t, browser, deviceDetailTestPath("peers")+"?page_size=2&page_token="+
		first.NextPageToken)
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &second) != nil ||
		len(second.Data.Peers) != 1 || !second.Data.Peers[0].External || second.Data.Peers[0].PeerID != nil ||
		second.Data.Peers[0].Name != nil || second.NextPageToken != "" {
		t.Fatalf("second page = %s", response.Body)
	}
	var relayed devicePeersEnvelope
	response = serveDistributionTest(t, browser, deviceDetailTestPath("peers")+"?path=relay")
	if json.Unmarshal(response.Body.Bytes(), &relayed) != nil || len(relayed.Data.Peers) != 1 ||
		*relayed.Data.Peers[0].Name != "db-01" {
		t.Fatalf("relayed peers = %s", response.Body)
	}

	newer, _ := distributionTestBrowser(t, reportedAt.Add(time.Minute))
	if response := serveDistributionTest(t, newer, deviceDetailTestPath("peers")+"?page_size=2&page_token="+
		first.NextPageToken); response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "device_paths_changed") {
		t.Fatalf("a token of an older report = %d %s", response.Code, response.Body)
	}
}

func TestDeviceDetailPathsAndPeerQueries(t *testing.T) {
	t.Parallel()
	device, _ := node.ParseID(distributionTestDevice)
	for target, valid := range map[string]bool{
		deviceDetailTestPath("status"):                     true,
		deviceDetailTestPath("peers"):                      true,
		deviceDetailTestPath("peers") + "?path=x":          true,
		deviceDetailTestPath("status") + "?x=1":            false,
		deviceDetailTestPath("tags"):                       false,
		deviceInventoryTestPath() + "/distribution":        false,
		deviceInventoryTestPath() + "/not-a-device/status": false,
	} {
		if _, ok := parseDeviceDetailPath(browserManagementReadRequest(t, target)); ok != valid {
			t.Errorf("%s: matched %t", target, ok)
		}
	}
	for _, query := range []string{
		"path=sideways", "page_size=0", "page_size=101", "page_size=01", "path=direct&path=relay", "page_token=x",
		"other=1",
	} {
		if _, err := parseDevicePeerQuery(query, device); err == nil {
			t.Errorf("%s accepted", query)
		}
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"device_id":"01890f00-0000-7000-8000-000000000302",` +
		`"path":"","offset":2,"reported_at":"2027-01-15T08:00:00Z"}`))
	if _, err := parseDevicePeerQuery("page_token="+token, device); err == nil {
		t.Fatal("a token of another Device was accepted")
	}
	if !isBrowserManagementOperation(browserManagementReadRequest(t, deviceDetailTestPath("peers")+"?page_size=2")) {
		t.Fatal("the peer page is not routed to browser management")
	}
}

func TestDevicePeerItemHidesExternalPeers(t *testing.T) {
	t.Parallel()
	shared, _ := node.ParseID("01890f90-0000-7000-8000-0000000000c2")
	item := newDevicePathPeerItem(distribution.PeerPath{PeerID: shared, External: true, Kind: distribution.PathDirect,
		DirectBytes: 90}, map[node.ID]string{shared: "secret-name"})
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"peer_id":null,"name":null,"external":true,"path":"direct","relay_region":null,"relay_code":null,` +
		`"relay_reason":null,"direct_bytes":90,"relay_bytes":0}`
	if string(encoded) != want {
		t.Fatalf("peer JSON\n got %s\nwant %s", encoded, want)
	}
	if newDevicePathSummary(nil) != nil {
		t.Fatal("no report must leave paths out")
	}
}

func TestDeviceConnectivityItem(t *testing.T) {
	t.Parallel()
	reportedAt := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	item := newDeviceConnectivityItem(&distribution.Connectivity{ReportedAt: reportedAt, IPv6Global: true,
		NAT: &distribution.NATClass{Mapping: distribution.NATMappingEndpointIndependent,
			Filtering: distribution.NATFilteringAddressDependent, Allocation: distribution.NATAllocationPreserving},
		PortMapping: &distribution.PortMapping{Protocol: distribution.PortMappingProtocolPCP,
			State: distribution.PortMappingMapped, ExpiresAt: reportedAt.Add(time.Hour)}})
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"reported_at":"2026-10-10T12:00:00Z","nat":{"mapping":"endpoint_independent",` +
		`"filtering":"address_dependent","allocation":"preserving","sequential_step":0,"observed_at":null},` +
		`"ipv6_global":true,"ipv6_stun":false,"port_mapping":{"protocol":"pcp","state":"mapped",` +
		`"expires_at":"2026-10-10T13:00:00Z"}}`
	if string(encoded) != want {
		t.Fatalf("connectivity JSON\n got %s\nwant %s", encoded, want)
	}
	if newDeviceConnectivityItem(nil) != nil {
		t.Fatal("no report must leave connectivity out")
	}
	bare, _ := json.Marshal(newDeviceConnectivityItem(&distribution.Connectivity{ReportedAt: reportedAt}))
	if string(bare) != `{"reported_at":"2026-10-10T12:00:00Z","nat":null,"ipv6_global":false,"ipv6_stun":false,"port_mapping":null}` {
		t.Fatalf("bare connectivity JSON %s", bare)
	}
}

func TestDeviceDistributionItemShowsAPeerLimit(t *testing.T) {
	t.Parallel()
	id, err := node.ParseID("01890f90-0000-7000-8000-0000000000c2")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	observation := distribution.Observation{Known: true, SessionGeneration: 1, NetworkRevision: 4, PolicyRevision: 2,
		DeliveredAt: at, SeenAt: at, Online: true}
	device := distribution.Device{ID: id, Hostname: "edge", State: "active", Status: distribution.StatusInSync,
		Observation: observation}
	if item := newDeviceDistributionItem(device); item.PeerLimit != nil {
		t.Fatalf("an unlimited map shows a peer limit: %+v", item.PeerLimit)
	}
	device.Observation.PeerLimit = distribution.PeerLimit{Sent: 10_000, Authorized: 80_000}
	encoded, err := json.Marshal(newDeviceDistributionItem(device).PeerLimit)
	if err != nil || string(encoded) != `{"sent":10000,"authorized":80000}` {
		t.Fatalf("peer limit JSON = %s, %v", encoded, err)
	}
}
