package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/inventory"
)

// statusDNSZones reads one root zone with a resolver Device and an Internet
// resolver.
type statusDNSZones struct {
	countingDNSZones
	zone dnszone.Zone
}

func (zones *statusDNSZones) Read(context.Context, accountsession.Session, network.Scope,
	dnszone.ID) (dnszone.Reading, error) {
	zones.calls++
	return dnszone.Reading{Zone: zones.zone}, nil
}

type fakeDNSZoneStatus struct {
	suffix    string
	resolvers []netip.AddrPort
	receivers distribution.DNSZoneReceivers
	err       error
}

func (status *fakeDNSZoneStatus) LoadDNSZoneApplication(_ context.Context, _ network.ID, suffix string,
	_ time.Time, receivers distribution.DNSZoneReceivers) (distribution.DNSZoneApplication, error) {
	status.suffix, status.receivers = suffix, receivers
	return distribution.DNSZoneApplication{Enforced: 4, UserOff: 1, Offline: 2}, status.err
}

// fakeZoneReceivers keeps every Device but the first it is asked about.
type fakeZoneReceivers struct {
	zoneID dnszone.ID
	scope  network.Scope
}

func (receivers *fakeZoneReceivers) ZoneReceivers(_ context.Context, _ accountsession.Session, scope network.Scope,
	zoneID dnszone.ID, devices []node.ID) (map[node.ID]struct{}, error) {
	receivers.zoneID, receivers.scope = zoneID, scope
	kept := make(map[node.ID]struct{})
	for _, device := range devices[1:] {
		kept[device] = struct{}{}
	}
	return kept, nil
}

func (status *fakeDNSZoneStatus) CountResolverHealth(_ context.Context, _ network.ID, resolvers []netip.AddrPort,
	_ time.Time) ([]distribution.ResolverHealthCount, error) {
	status.resolvers = resolvers
	counts := make([]distribution.ResolverHealthCount, len(resolvers))
	for index, resolver := range resolvers {
		counts[index] = distribution.ResolverHealthCount{Resolver: resolver, OK: 3 + index, Refusing: 1}
	}
	return counts, nil
}

type fakeResolverDevices struct {
	addresses []netip.Addr
	err       error
}

func (devices fakeResolverDevices) Get(context.Context, accountsession.Session, network.Scope,
	node.ID) (inventory.Record, error) {
	return inventory.Record{Found: devices.err == nil, Addresses: devices.addresses}, devices.err
}

// A zone's status counts the Devices that hold it and, per resolver, the
// Devices that see it in each state; a resolver Device is counted at the
// mesh IPv4 address its consumers ask.
func TestReadDNSZoneStatus(t *testing.T) {
	t.Parallel()
	deviceID, err := node.ParseID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatal(err)
	}
	zones := &statusDNSZones{zone: dnszone.Zone{Domain: dnszone.Root, Resolvers: []dnszone.ZoneResolver{
		{Resolver: dnszone.Resolver{DeviceID: deviceID, Port: 5335}},
		{Resolver: dnszone.Resolver{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}},
	}}}
	type body struct {
		Data struct {
			Available bool                    `json:"available"`
			Devices   dnsZoneApplicationBody  `json:"devices"`
			Resolvers []dnsResolverHealthBody `json:"resolvers"`
		} `json:"data"`
	}
	read := func(status DNSZoneStatusCounter, devices DNSResolverDeviceReader, receivers ...DNSZoneReceiverReader) (
		int, body,
	) {
		t.Helper()
		options := validManagementHandlerOptions(t)
		options.DNSZones, options.DNSZoneStatus, options.DNSResolverDevices = zones, status, devices
		if len(receivers) == 1 {
			options.DNSZoneReceivers = receivers[0]
		}
		handler, err := NewManagementHandler(options)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, newManagementRequest(t, http.MethodGet,
			dnsZoneBase+"/01890f00-0000-7000-8000-000000000301/status", ""))
		var decoded body
		if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("status %d %s", recorder.Code, recorder.Body.String())
		}
		return recorder.Code, decoded
	}
	status := &fakeDNSZoneStatus{}
	code, got := read(status, fakeResolverDevices{addresses: []netip.Addr{
		netip.MustParseAddr("fd07::9"), netip.MustParseAddr("100.64.0.9"),
	}})
	want := []netip.AddrPort{netip.MustParseAddrPort("100.64.0.9:5335"), netip.MustParseAddrPort("1.1.1.1:53")}
	if code != http.StatusOK || !got.Data.Available || status.suffix != "." || !slices.Equal(status.resolvers, want) ||
		got.Data.Devices != (dnsZoneApplicationBody{Enforced: 4, UserOff: 1, Offline: 2, Total: 7}) {
		t.Fatalf("status %d %+v; suffix %q resolvers %v", code, got.Data, status.suffix, status.resolvers)
	}
	if len(got.Data.Resolvers) != 2 || got.Data.Resolvers[0].DeviceID != deviceID.String() ||
		got.Data.Resolvers[0].Address != "100.64.0.9" || !got.Data.Resolvers[0].Counted || got.Data.Resolvers[0].OK != 3 ||
		got.Data.Resolvers[1].Address != "1.1.1.1" || got.Data.Resolvers[1].OK != 4 || got.Data.Resolvers[1].Refusing != 1 {
		t.Fatalf("resolvers %+v", got.Data.Resolvers)
	}
	// A resolver Device the caller may not read is listed, not counted.
	_, got = read(&fakeDNSZoneStatus{}, fakeResolverDevices{err: inventory.ErrForbidden})
	if !got.Data.Available || got.Data.Resolvers[0].Counted || got.Data.Resolvers[0].Address != "" ||
		!got.Data.Resolvers[1].Counted {
		t.Fatalf("without the Device: %+v", got.Data.Resolvers)
	}
	// Counts that cannot be read leave the zone answering, unavailable.
	code, got = read(&fakeDNSZoneStatus{err: errors.New("redis down")}, fakeResolverDevices{})
	if code != http.StatusOK || got.Data.Available || got.Data.Devices.Total != 0 || got.Data.Resolvers[1].Counted {
		t.Fatalf("index down: %d %+v", code, got.Data)
	}
	code, got = read(nil, nil)
	if code != http.StatusOK || got.Data.Available {
		t.Fatalf("no counter: %d %+v", code, got.Data)
	}
	// Without a receiver reader the index counts alone; with one, the
	// count asks it, for this zone in this Network (TD-CORE-87).
	if status.receivers != nil {
		t.Fatal("receivers without a reader")
	}
	reader := &fakeZoneReceivers{}
	status = &fakeDNSZoneStatus{}
	_, _ = read(status, fakeResolverDevices{}, reader)
	if status.receivers == nil {
		t.Fatal("no receivers with a reader")
	}
	kept, err := status.receivers(t.Context(), []node.ID{deviceID, deviceID})
	if err != nil || len(kept) != 1 || reader.zoneID != zones.zone.ID || !reader.scope.IsValid() {
		t.Fatalf("receivers %v %v; zone %v scope %v", kept, err, reader.zoneID, reader.scope)
	}
}
