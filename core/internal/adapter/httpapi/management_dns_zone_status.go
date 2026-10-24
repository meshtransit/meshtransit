package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/publicid"
)

// DNSZoneStatusCounter counts, from the Network's DNS index, the Devices that
// hold a zone by how they apply it, and the Devices that see each resolver
// in each state (DNS design D1b §8, §9).
type DNSZoneStatusCounter interface {
	LoadDNSZoneApplication(ctx context.Context, networkID network.ID, suffix string,
		now time.Time, receivers distribution.DNSZoneReceivers) (distribution.DNSZoneApplication, error)
	CountResolverHealth(ctx context.Context, networkID network.ID, resolvers []netip.AddrPort,
		now time.Time) ([]distribution.ResolverHealthCount, error)
}

// DNSZoneReceiverReader answers, under the caller's network.read, which of
// up to distribution.DNSZoneReceiversBatch Devices a zone is still sent to.
type DNSZoneReceiverReader interface {
	ZoneReceivers(ctx context.Context, session accountsession.Session, scope network.Scope,
		zoneID dnszone.ID, devices []node.ID) (map[node.ID]struct{}, error)
}

// DNSResolverDeviceReader reads a resolver Device under the caller's
// device.read, for the mesh address its consumers ask.
type DNSResolverDeviceReader interface {
	Get(context.Context, accountsession.Session, network.Scope, node.ID) (inventory.Record, error)
}

// dnsZoneApplicationBody counts the Devices that hold the zone and report
// what they apply (clients with dns.root1).
type dnsZoneApplicationBody struct {
	Enforced    int `json:"enforced"`
	Applying    int `json:"applying"`
	Mismatch    int `json:"mismatch"`
	NotReported int `json:"not_reported"`
	Unknown     int `json:"unknown"`
	UserOff     int `json:"user_off"`
	ApplyFailed int `json:"apply_failed"`
	Offline     int `json:"offline"`
	Total       int `json:"total"`
}

// dnsResolverHealthBody counts the Devices that see one resolver of the zone
// in each state; Counted is false for a resolver Device whose address the
// caller may not read, and the counts are then zero.
type dnsResolverHealthBody struct {
	DeviceID string `json:"device_id,omitempty"`
	Address  string `json:"address,omitempty"`
	Port     uint16 `json:"port"`
	Counted  bool   `json:"counted"`
	OK       int    `json:"ok"`
	Broken   int    `json:"broken"`
	Stopped  int    `json:"stopped"`
	Refusing int    `json:"refusing"`
	Idle     int    `json:"idle"`
}

// readDNSZoneStatus answers how the Devices that hold one zone apply it and
// see its resolvers. Reading the zone authorizes it; the counts come from
// the DNS index, never from every Device's record. Counts that cannot be
// read leave Available false and the zone still answers.
func (handler *ManagementHandler) readDNSZoneStatus(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path dnsZonePath, session accountsession.Session,
	fail func(managementError) string) string {
	reading, err := handler.dnsZones.Read(ctx, session, path.scope, path.zoneID)
	if err != nil {
		return fail(classifyDNSZoneError(err))
	}
	var output struct {
		Data struct {
			ZoneID     string                  `json:"dns_zone_id"`
			Available  bool                    `json:"available"`
			ObservedAt time.Time               `json:"observed_at"`
			Devices    dnsZoneApplicationBody  `json:"devices"`
			Resolvers  []dnsResolverHealthBody `json:"resolvers"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	now := time.Now().UTC()
	output.Data.ZoneID, output.Data.ObservedAt, output.CorrelationID = reading.Zone.ID.String(), now,
		correlationID.String()
	output.Data.Resolvers = make([]dnsResolverHealthBody, 0, len(reading.Zone.Resolvers))
	var addresses []netip.AddrPort
	var counted []int
	for _, resolver := range reading.Zone.Resolvers {
		body := dnsResolverHealthBody{Port: resolver.Port}
		address := resolver.Address
		if resolver.IsDevice() {
			body.DeviceID = resolver.DeviceID.String()
			address = handler.resolverDeviceAddress(ctx, session, path.scope, resolver.DeviceID)
		}
		if address.IsValid() {
			body.Address = address.String()
			addresses = append(addresses, netip.AddrPortFrom(address, resolver.Port))
			counted = append(counted, len(output.Data.Resolvers))
		}
		output.Data.Resolvers = append(output.Data.Resolvers, body)
	}
	if !nilContinuationDependency(handler.dnsZoneStatus) {
		networkID := path.scope.NetworkID()
		var receivers distribution.DNSZoneReceivers
		var receiversErr error
		if !nilContinuationDependency(handler.dnsZoneReceivers) {
			receivers = func(ctx context.Context, devices []node.ID) (map[node.ID]struct{}, error) {
				kept, err := handler.dnsZoneReceivers.ZoneReceivers(ctx, session, path.scope, reading.Zone.ID,
					devices)
				receiversErr = err
				return kept, err
			}
		}
		application, applicationErr := handler.dnsZoneStatus.LoadDNSZoneApplication(ctx, networkID,
			reading.Zone.Domain.String(), now, receivers)
		if receiversErr != nil {
			// The counts stand, with Devices the zone may no longer reach.
			handler.logger.WarnContext(ctx, "dns zone receivers unavailable",
				"correlation_id", correlationID.String(), "error", receiversErr)
		}
		health, healthErr := handler.dnsZoneStatus.CountResolverHealth(ctx, networkID, addresses, now)
		if applicationErr == nil && healthErr == nil && len(health) == len(addresses) {
			output.Data.Available = true
			output.Data.Devices = newDNSZoneApplicationBody(application)
			for index, count := range health {
				row := &output.Data.Resolvers[counted[index]]
				row.Counted, row.OK, row.Broken, row.Stopped, row.Refusing, row.Idle = true, count.OK,
					count.Broken, count.Stopped, count.Refusing, count.Idle
			}
		} else {
			handler.logger.WarnContext(ctx, "dns zone status unavailable",
				"correlation_id", correlationID.String(), "application_error", applicationErr,
				"health_error", healthErr)
		}
	}
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

// resolverDeviceAddress returns the mesh IPv4 address a resolver Device is
// asked on, the address Core sends its consumers; invalid when the caller
// may not read the Device or it holds none.
func (handler *ManagementHandler) resolverDeviceAddress(ctx context.Context, session accountsession.Session,
	scope network.Scope, deviceID node.ID) netip.Addr {
	if nilContinuationDependency(handler.dnsResolverDevices) {
		return netip.Addr{}
	}
	record, err := handler.dnsResolverDevices.Get(ctx, session, scope, deviceID)
	if err != nil || !record.Found {
		return netip.Addr{}
	}
	for _, address := range record.Addresses {
		if address.Is4() {
			return address
		}
	}
	return netip.Addr{}
}

func newDNSZoneApplicationBody(counts distribution.DNSZoneApplication) dnsZoneApplicationBody {
	return dnsZoneApplicationBody{
		Enforced: counts.Enforced, Applying: counts.Applying, Mismatch: counts.Mismatch,
		NotReported: counts.NotReported, Unknown: counts.Unknown, UserOff: counts.UserOff,
		ApplyFailed: counts.ApplyFailed, Offline: counts.Offline, Total: counts.Total(),
	}
}
