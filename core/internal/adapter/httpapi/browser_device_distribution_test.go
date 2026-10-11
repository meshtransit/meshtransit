package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/policydigest"
)

type distributionTestReader struct {
	target distribution.Target
	err    error
	reads  int
}

func (reader *distributionTestReader) ReadDistribution(_ context.Context, _ accountsession.Session,
	_ network.Scope, _ node.ID, _ int, _ time.Time,
) (distribution.Target, error) {
	reader.reads++
	return reader.target, reader.err
}

type distributionTestObservations struct{ observations []distribution.Observation }

func (loader distributionTestObservations) LoadObservations(_ context.Context, ids []node.ID) (
	[]distribution.Observation, error) {
	return loader.observations[:len(ids)], nil
}

func deviceDistributionTestPath() string {
	return deviceInventoryTestPath() + "/distribution"
}

func TestBrowserDeviceDistributionReportsStatusPerDevice(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	request := browserManagementReadRequest(t, deviceDistributionTestPath()+"?page_size=1")
	scope, ok := parseDeviceDistributionPath(request)
	if !ok {
		t.Fatal("valid exact scope rejected")
	}
	if _, inventoryMatched := parseDeviceInventoryPath(request); inventoryMatched {
		t.Fatal("distribution path matched the inventory route")
	}
	first, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	second, _ := node.ParseID("01890f00-0000-7000-8000-000000000302")
	reader := &distributionTestReader{target: distribution.Target{Scope: scope, NetworkRevision: 7, PolicyRevision: 3,
		Devices: []distribution.TargetDevice{
			{ID: first, Hostname: "poc-01", State: "active"},
			{ID: second, Hostname: "poc-02", State: "active"},
		}}}
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
	}}}
	service, err := distribution.NewService(reader, observations, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Distribution = service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || reader.reads != 1 || fixture.auth != 1 || fixture.budgets != 2 ||
		response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Set-Cookie") != "" {
		t.Fatal("distribution bypassed the private read contract", response.Code)
	}
	var envelope deviceDistributionEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data := envelope.Data
	if data.NetworkRevision != 7 || data.PolicyRevision != 3 || !data.ObservationsAvailable ||
		len(data.Devices) != 1 || data.Devices[0].Status != "in_sync" || !data.Devices[0].Online ||
		data.Devices[0].DeliveredNetworkRevision == nil || *data.Devices[0].DeliveredNetworkRevision != 7 ||
		envelope.NextPageToken == "" {
		t.Fatalf("distribution page = %+v next=%q", data, envelope.NextPageToken)
	}
	enforcement := data.Devices[0].Enforcement
	if enforcement.Status != "enforced" || enforcement.DeliveredDigest == nil ||
		*enforcement.DeliveredDigest != digest.String() || enforcement.EnforcedDigest == nil ||
		*enforcement.EnforcedDigest != digest.String() || enforcement.ReportedAt == nil {
		t.Fatalf("enforcement = %+v", enforcement)
	}

	reader.err = distribution.ErrForbidden
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "poc-01") {
		t.Fatal("denied read disclosed distribution")
	}
}

func TestBrowserDeviceDistributionRejectsTransportAndForeignCursor(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	request := browserManagementReadRequest(t, deviceDistributionTestPath())
	scope, _ := parseDeviceDistributionPath(request)
	reader := &distributionTestReader{target: distribution.Target{Scope: scope, NetworkRevision: 1}}
	service, err := distribution.NewService(reader, distributionTestObservations{}, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.Distribution = service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.Method = http.MethodPost },
		func(request *http.Request) { request.Header.Set("Authorization", "Bearer injected") },
		func(request *http.Request) { request.Header.Set("Origin", "https://foreign.example") },
	} {
		request := browserManagementReadRequest(t, deviceDistributionTestPath())
		mutate(request)
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if !errors.Is(browser.Handle(response, request), ErrInvalidBrowserManagement) || reader.reads != 0 {
			t.Fatal("invalid transport reached distribution")
		}
	}
	id, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
	token, err := encodeDeviceDistributionPageToken(scope, id)
	if err != nil {
		t.Fatal(err)
	}
	if limit, after, err := parseDeviceDistributionQuery("page_token="+token, scope); err != nil || after != id ||
		limit != 50 {
		t.Fatalf("own cursor = %d %v %v", limit, after, err)
	}
	otherRequest := browserManagementReadRequest(t,
		strings.Replace(deviceDistributionTestPath(), "000000000201", "000000000202", 1))
	otherScope, _ := parseDeviceDistributionPath(otherRequest)
	if _, _, err := parseDeviceDistributionQuery("page_token="+token, otherScope); err == nil {
		t.Fatal("cross-Network cursor accepted")
	}
	for _, query := range []string{"page_size=01", "page_size=101", "page_size=1&page_size=2", "status=all", "page_token="} {
		if _, _, err := parseDeviceDistributionQuery(query, scope); err == nil {
			t.Fatal("invalid distribution query accepted", query)
		}
	}
	// Without the dependency the route is not served at all.
	options.Distribution = nil
	plain, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if !errors.Is(plain.Handle(response, browserManagementReadRequest(t, deviceDistributionTestPath())),
		ErrInvalidBrowserManagement) {
		t.Fatal("distribution served without its dependency")
	}
}

func TestDevicePathsItemHidesExternalPeers(t *testing.T) {
	t.Parallel()
	local, err := node.ParseID("01890f90-0000-7000-8000-0000000000c1")
	if err != nil {
		t.Fatal(err)
	}
	shared, err := node.ParseID("01890f90-0000-7000-8000-0000000000c2")
	if err != nil {
		t.Fatal(err)
	}
	reportedAt := time.UnixMilli(1_800_000_000_000)
	item := newDevicePathsItem(&distribution.PathReport{ReportedAt: reportedAt, Interval: time.Minute,
		Peers: []distribution.PeerPath{
			{PeerID: local, Kind: distribution.PathRelay, RelayRegion: 1, RelayCode: "sgp",
				RelayReason: distribution.RelayNoResponse, RelayBytes: 30},
			{PeerID: shared, External: true, Kind: distribution.PathDirect, DirectBytes: 90},
		}})
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"reported_at":"` + reportedAt.UTC().Format(time.RFC3339Nano) + `","interval_seconds":60,"peers":[` +
		`{"peer_id":"01890f90-0000-7000-8000-0000000000c1","external":false,"path":"relay","relay_region":1,` +
		`"relay_code":"sgp","relay_reason":"no_response","direct_bytes":0,"relay_bytes":30},` +
		`{"peer_id":null,"external":true,"path":"direct","relay_region":null,"relay_code":null,"relay_reason":null,` +
		`"direct_bytes":90,"relay_bytes":0}]}`
	if string(encoded) != want {
		t.Fatalf("paths JSON\n got %s\nwant %s", encoded, want)
	}
	if newDevicePathsItem(nil) != nil {
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
