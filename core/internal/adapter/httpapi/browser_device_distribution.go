package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/workspace"
)

// SessionDeviceDistribution requires current exact-scope device.read for
// every Device's policy distribution status (R1-65), and for the status of
// one page of the Device list (D-1).
type SessionDeviceDistribution interface {
	ReadDevice(context.Context, accountsession.Session, network.Scope, node.ID) (distribution.Report, error)
	ReadPage(context.Context, accountsession.Session, network.Scope, []distribution.TargetDevice) (distribution.Page, error)
}

// deviceDetailRead is a read below one Device: "status" or "peers".
type deviceDetailRead struct {
	scope    network.Scope
	deviceID node.ID
	kind     string
}

// parseDeviceDetailPath matches GET
// /api/v1/workspaces/{ws}/networks/{net}/devices/{device}/{status|peers}.
// Only the peers take a query.
func parseDeviceDetailPath(request *http.Request) (deviceDetailRead, bool) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.RawPath != "" {
		return deviceDetailRead{}, false
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 10 || parts[0] != "" || parts[1] != "api" || parts[2] != "v1" ||
		parts[3] != "workspaces" || parts[5] != "networks" || parts[7] != "devices" ||
		(parts[9] != "status" && parts[9] != "peers") {
		return deviceDetailRead{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(parts[4])
	networkID, networkErr := network.ParseID(parts[6])
	deviceID, deviceErr := node.ParseID(parts[8])
	scope, err := network.NewScope(workspaceID, networkID)
	valid := workspaceErr == nil && networkErr == nil && deviceErr == nil && err == nil &&
		workspaceID.String() == parts[4] && networkID.String() == parts[6] && deviceID.String() == parts[8] &&
		(parts[9] == "peers" || request.URL.RawQuery == "")
	return deviceDetailRead{scope: scope, deviceID: deviceID, kind: parts[9]}, valid
}

// isDevicePeerRead admits the peer page, which takes a query.
func isDevicePeerRead(request *http.Request) bool {
	read, ok := parseDeviceDetailPath(request)
	return ok && read.kind == "peers"
}

// devicePeerQuery is one page of the peers a Device reported.
type devicePeerQuery struct {
	path   distribution.PathKind
	limit  int
	offset int
	// reportedAt is the report a continuation token belongs to.
	reportedAt time.Time
}

// devicePeerPageToken continues a page of one path report.
type devicePeerPageToken struct {
	Version    int       `json:"v"`
	DeviceID   string    `json:"device_id"`
	Path       string    `json:"path"`
	Offset     int       `json:"offset"`
	ReportedAt time.Time `json:"reported_at"`
}

// parseDevicePeerQuery reads path (direct, relay or unknown), page_size
// (1-100, 10 by default) and page_token, each once.
func parseDevicePeerQuery(raw string, deviceID node.ID) (devicePeerQuery, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return devicePeerQuery{}, distribution.ErrInvalidRequest
	}
	for key, entries := range values {
		if (key != "path" && key != "page_size" && key != "page_token") || len(entries) != 1 || entries[0] == "" {
			return devicePeerQuery{}, distribution.ErrInvalidRequest
		}
	}
	query := devicePeerQuery{limit: defaultDeviceInventoryPage, path: distribution.PathKind(values.Get("path"))}
	switch query.path {
	case "", distribution.PathDirect, distribution.PathRelay, distribution.PathUnknown:
	default:
		return devicePeerQuery{}, distribution.ErrInvalidRequest
	}
	if value := values.Get("page_size"); value != "" {
		query.limit, err = strconv.Atoi(value)
		if err != nil || strconv.Itoa(query.limit) != value || query.limit < 1 || query.limit > inventory.MaximumNames {
			return devicePeerQuery{}, distribution.ErrInvalidRequest
		}
	}
	if encoded := values.Get("page_token"); encoded != "" {
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if len(encoded) > 512 || err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
			return devicePeerQuery{}, distribution.ErrInvalidRequest
		}
		var wire devicePeerPageToken
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
			wire.DeviceID != deviceID.String() || wire.Path != string(query.path) || wire.Offset < 1 ||
			wire.Offset >= distribution.MaximumPathPeers || wire.ReportedAt.IsZero() {
			return devicePeerQuery{}, distribution.ErrInvalidRequest
		}
		query.offset, query.reportedAt = wire.Offset, wire.ReportedAt
	}
	return query, nil
}

type deviceDistributionItem struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	State    string `json:"state"`
	// Status is in_sync, behind, offline, never_connected or unknown.
	Status                   string     `json:"status"`
	Online                   bool       `json:"online"`
	DeliveredNetworkRevision *int64     `json:"delivered_network_revision"`
	DeliveredPolicyRevision  *int64     `json:"delivered_policy_revision"`
	DeliveredAt              *time.Time `json:"delivered_at"`
	LastSeenAt               *time.Time `json:"last_seen_at"`
	// Enforcement compares the Device's own report with the delivered packet
	// filter (R1-69).
	Enforcement deviceEnforcementItem `json:"enforcement"`
	// Paths sums up the Device's latest report of how its traffic reaches
	// its peers (MTCP path statistics); absent when it has none. The peers
	// themselves are read page by page.
	Paths *devicePathSummary `json:"paths,omitempty"`
	// Connectivity is the Device's NAT classification, IPv6 reachability
	// and gateway port mapping from its latest endpoint report; absent when
	// it sent none.
	Connectivity *deviceConnectivityItem `json:"connectivity,omitempty"`
	// PeerLimit is present when the Device's last map was cut to the peer
	// limit: it carried Sent of the Authorized peers its policy allows.
	PeerLimit *devicePeerLimitItem `json:"peer_limit,omitempty"`
	// Router is present for a subnet router: whether it forwards into the
	// served routes it was delivered, and its current Site health.
	Router *deviceRouterItem `json:"router,omitempty"`
	// SubnetRoutes is the router the Device uses for each Site it reaches,
	// as it last reported (within three minutes).
	SubnetRoutes []deviceSiteRouteItem `json:"subnet_routes,omitempty"`
	// Exit is the exit node the Device sends its Internet traffic through,
	// as it last reported (within three minutes).
	Exit *deviceExitItem `json:"exit,omitempty"`
	// Platform is what the Device's client runs on, from its latest
	// session; null when unknown.
	Platform *devicePlatformItem `json:"platform"`
	// PublicAddresses are the Device's addresses on the Internet from its
	// latest endpoint report; empty when unknown.
	PublicAddresses []devicePublicAddressItem `json:"public_addresses"`
}

// CountryLookup places an address in the country it is registered in, as
// an ISO 3166-1 alpha-2 code (geoip.Countries).
type CountryLookup interface {
	Country(netip.Addr) (string, bool)
}

// devicePlatformItem is what a Device's client says it runs on: os as Go
// names it (darwin, linux, windows, android, ios, freebsd).
type devicePlatformItem struct {
	OS            string  `json:"os"`
	OSVersion     *string `json:"os_version"`
	Arch          *string `json:"arch"`
	ClientVersion *string `json:"client_version"`
}

// devicePublicAddressItem is one public address and the country it is
// registered in; Country is null when unknown.
type devicePublicAddressItem struct {
	Address string  `json:"address"`
	Country *string `json:"country"`
}

func newDevicePlatformItem(platform *distribution.Platform) *devicePlatformItem {
	if platform == nil {
		return nil
	}
	optional := func(text string) *string {
		if text == "" {
			return nil
		}
		return &text
	}
	return &devicePlatformItem{OS: platform.OS, OSVersion: optional(platform.OSVersion),
		Arch: optional(platform.Arch), ClientVersion: optional(platform.ClientVersion)}
}

// newDevicePublicAddresses lists a report's public addresses, placed in
// countries when a lookup is set; never nil.
func newDevicePublicAddresses(report *distribution.Connectivity, countries CountryLookup) []devicePublicAddressItem {
	items := []devicePublicAddressItem{}
	if report == nil {
		return items
	}
	for _, address := range report.PublicAddresses {
		item := devicePublicAddressItem{Address: address.String()}
		if countries != nil {
			if country, found := countries.Country(address); found {
				item.Country = &country
			}
		}
		items = append(items, item)
	}
	return items
}

// deviceExitItem is the Exit Pool a Device uses and its exit node: Via is
// primary, local_failover, sticky (kept although Core elected another) or
// none (no exit node can serve; ExitNodeID is null).
type deviceExitItem struct {
	ExitPoolID string  `json:"exit_pool_id"`
	ExitNodeID *string `json:"exit_node_device_id"`
	Via        string  `json:"via"`
}

type deviceSiteRouteItem struct {
	SiteID   string  `json:"site_id"`
	RouterID *string `json:"router_device_id"`
	Via      string  `json:"via"`
}

type deviceRouterItem struct {
	// RouteEnforcement is enforced, applying, mismatch, not_reported or
	// unknown, as for the packet filter, over the route digest.
	RouteEnforcement     string  `json:"route_enforcement"`
	DeliveredRouteDigest *string `json:"delivered_route_digest"`
	DeliveredRoutes      *int    `json:"delivered_routes"`
	EnforcedRouteDigest  *string `json:"enforced_route_digest"`
	EnforcedRoutes       *int    `json:"enforced_routes"`
	// Sites is the router's current health of each Site it serves; empty
	// when it reported none in the last 30 seconds.
	Sites []deviceSiteHealthItem `json:"sites"`
	// HealthReportedAt is when Core received that health.
	HealthReportedAt *time.Time `json:"health_reported_at"`
}

type deviceSiteHealthItem struct {
	SiteID string `json:"site_id"`
	State  string `json:"state"`
	Code   string `json:"code"`
}

// newDeviceRouterItem describes a router; nil for a Device that was never
// delivered served routes and reports no Site health.
func newDeviceRouterItem(device distribution.Device) *deviceRouterItem {
	observation := device.Observation
	if !observation.Known || (observation.Routes.IsZero() && observation.RouteHealthAt.IsZero()) {
		return nil
	}
	item := &deviceRouterItem{RouteEnforcement: string(device.RouteEnforcement), Sites: []deviceSiteHealthItem{}}
	if item.RouteEnforcement == "" {
		item.RouteEnforcement = string(distribution.EnforcementUnknown)
	}
	if routes := observation.Routes; !routes.IsZero() {
		digest, entries := routes.Digest.String(), routes.Entries
		item.DeliveredRouteDigest, item.DeliveredRoutes = &digest, &entries
	}
	if routes := observation.EnforcedRoutes; !routes.IsZero() {
		digest, entries := routes.Digest.String(), routes.Entries
		item.EnforcedRouteDigest, item.EnforcedRoutes = &digest, &entries
	}
	for _, site := range device.RouteHealth {
		item.Sites = append(item.Sites, deviceSiteHealthItem{SiteID: site.Ref, State: site.State, Code: site.Code})
	}
	if len(device.RouteHealth) > 0 {
		at := observation.RouteHealthAt.UTC()
		item.HealthReportedAt = &at
	}
	return item
}

type devicePeerLimitItem struct {
	Sent       int `json:"sent"`
	Authorized int `json:"authorized"`
}

type deviceConnectivityItem struct {
	ReportedAt  time.Time          `json:"reported_at"`
	NAT         *deviceNATItem     `json:"nat"`
	IPv6Global  bool               `json:"ipv6_global"`
	IPv6STUN    bool               `json:"ipv6_stun"`
	PortMapping *devicePortMapItem `json:"port_mapping"`
}

type deviceNATItem struct {
	Mapping        string     `json:"mapping"`
	Filtering      string     `json:"filtering"`
	Allocation     string     `json:"allocation"`
	SequentialStep int        `json:"sequential_step"`
	ObservedAt     *time.Time `json:"observed_at"`
}

type devicePortMapItem struct {
	Protocol  string     `json:"protocol"`
	State     string     `json:"state"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func newDeviceConnectivityItem(report *distribution.Connectivity) *deviceConnectivityItem {
	if report == nil {
		return nil
	}
	optional := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		utc := t.UTC()
		return &utc
	}
	item := &deviceConnectivityItem{ReportedAt: report.ReportedAt.UTC(), IPv6Global: report.IPv6Global,
		IPv6STUN: report.IPv6STUN}
	if nat := report.NAT; nat != nil {
		item.NAT = &deviceNATItem{Mapping: string(nat.Mapping), Filtering: string(nat.Filtering),
			Allocation: string(nat.Allocation), SequentialStep: int(nat.SequentialStep), ObservedAt: optional(nat.ObservedAt)}
	}
	if mapping := report.PortMapping; mapping != nil {
		item.PortMapping = &devicePortMapItem{Protocol: string(mapping.Protocol), State: string(mapping.State),
			ExpiresAt: optional(mapping.ExpiresAt)}
	}
	return item
}

// devicePathSummary counts a path report's peers by how they are reached.
type devicePathSummary struct {
	ReportedAt      time.Time          `json:"reported_at"`
	IntervalSeconds int64              `json:"interval_seconds"`
	ReportedPeers   int                `json:"reported_peers"`
	Direct          int                `json:"direct"`
	Relays          []deviceRelayCount `json:"relays"`
	Unknown         int                `json:"unknown"`
	// Limited is true when the report holds the busiest peers only.
	Limited bool `json:"limited"`
}

type deviceRelayCount struct {
	RelayRegion *int    `json:"relay_region"`
	RelayCode   *string `json:"relay_code"`
	Peers       int     `json:"peers"`
}

func newDevicePathSummary(report *distribution.PathReport) *devicePathSummary {
	if report == nil {
		return nil
	}
	summary := &devicePathSummary{ReportedAt: report.ReportedAt.UTC(),
		IntervalSeconds: int64(report.Interval / time.Second), ReportedPeers: len(report.Peers),
		Relays: []deviceRelayCount{}, Limited: len(report.Peers) >= distribution.MaximumPathPeers}
	relays := map[string]int{}
	for _, peer := range report.Peers {
		switch peer.Kind {
		case distribution.PathDirect:
			summary.Direct++
		case distribution.PathRelay:
			key := peer.RelayCode + "/" + strconv.Itoa(peer.RelayRegion)
			index, seen := relays[key]
			if !seen {
				index = len(summary.Relays)
				relays[key] = index
				entry := deviceRelayCount{}
				if peer.RelayRegion > 0 {
					region := peer.RelayRegion
					entry.RelayRegion = &region
				}
				if peer.RelayCode != "" {
					code := peer.RelayCode
					entry.RelayCode = &code
				}
				summary.Relays = append(summary.Relays, entry)
			}
			summary.Relays[index].Peers++
		default:
			summary.Unknown++
		}
	}
	return summary
}

// devicePathPeerItem is one peer a Device reached. A peer of the same Network
// carries its ID and name; a peer of another Network (a share) is marked
// external and carries neither.
type devicePathPeerItem struct {
	PeerID      *string `json:"peer_id"`
	Name        *string `json:"name"`
	External    bool    `json:"external"`
	Path        string  `json:"path"`
	RelayRegion *int    `json:"relay_region"`
	RelayCode   *string `json:"relay_code"`
	RelayReason *string `json:"relay_reason"`
	DirectBytes uint64  `json:"direct_bytes"`
	RelayBytes  uint64  `json:"relay_bytes"`
}

func newDevicePathPeerItem(peer distribution.PeerPath, names map[node.ID]string) devicePathPeerItem {
	entry := devicePathPeerItem{External: peer.External, Path: string(peer.Kind),
		DirectBytes: peer.DirectBytes, RelayBytes: peer.RelayBytes}
	if !peer.External {
		id := peer.PeerID.String()
		entry.PeerID = &id
		if name, named := names[peer.PeerID]; named {
			entry.Name = &name
		}
	}
	if peer.Kind == distribution.PathRelay {
		if peer.RelayRegion > 0 {
			region := peer.RelayRegion
			entry.RelayRegion = &region
		}
		if peer.RelayCode != "" {
			code := peer.RelayCode
			entry.RelayCode = &code
		}
		if peer.RelayReason != "" {
			reason := string(peer.RelayReason)
			entry.RelayReason = &reason
		}
	}
	return entry
}

type deviceEnforcementItem struct {
	// Status is enforced, applying, mismatch, not_reported or unknown.
	Status          string     `json:"status"`
	DeliveredDigest *string    `json:"delivered_digest"`
	DeliveredGrants *int       `json:"delivered_grants"`
	EnforcedDigest  *string    `json:"enforced_digest"`
	EnforcedGrants  *int       `json:"enforced_grants"`
	AppliedAt       *time.Time `json:"applied_at"`
	ReportedAt      *time.Time `json:"reported_at"`
}

func newDeviceEnforcementItem(status distribution.Enforcement,
	observation distribution.Observation) deviceEnforcementItem {
	item := deviceEnforcementItem{Status: string(status)}
	if status == "" {
		item.Status = string(distribution.EnforcementUnknown)
	}
	if !observation.Known {
		return item
	}
	if filter := observation.Filter; !filter.IsZero() {
		digest, grants := filter.Digest.String(), filter.Grants
		item.DeliveredDigest, item.DeliveredGrants = &digest, &grants
	}
	if enforced := observation.Enforced; !enforced.IsZero() {
		digest, grants := enforced.Digest.String(), enforced.Grants
		appliedAt, reportedAt := observation.AppliedAt.UTC(), observation.ReportedAt.UTC()
		item.EnforcedDigest, item.EnforcedGrants = &digest, &grants
		item.AppliedAt, item.ReportedAt = &appliedAt, &reportedAt
	}
	return item
}

func newDeviceDistributionItem(device distribution.Device, countries CountryLookup) deviceDistributionItem {
	item := deviceDistributionItem{ID: device.ID.String(), Hostname: device.Hostname, State: device.State,
		Status: string(device.Status), Online: device.Observation.Online,
		Enforcement:     deviceEnforcementItem{Status: string(distribution.EnforcementUnknown)},
		PublicAddresses: []devicePublicAddressItem{}}
	if device.Status == distribution.StatusUnknown {
		item.Online = false
		return item
	}
	item.Enforcement = newDeviceEnforcementItem(device.Enforcement, device.Observation)
	if observation := device.Observation; observation.Known {
		networkRevision, policyRevision := observation.NetworkRevision, observation.PolicyRevision
		deliveredAt, seenAt := observation.DeliveredAt.UTC(), observation.SeenAt.UTC()
		item.DeliveredNetworkRevision, item.DeliveredPolicyRevision = &networkRevision, &policyRevision
		item.DeliveredAt, item.LastSeenAt = &deliveredAt, &seenAt
		item.Paths = newDevicePathSummary(observation.Paths)
		item.Connectivity = newDeviceConnectivityItem(observation.Connectivity)
		item.Platform = newDevicePlatformItem(observation.Platform)
		item.PublicAddresses = newDevicePublicAddresses(observation.Connectivity, countries)
		if limit := observation.PeerLimit; limit.IsValid() {
			item.PeerLimit = &devicePeerLimitItem{Sent: limit.Sent, Authorized: limit.Authorized}
		}
		item.Router = newDeviceRouterItem(device)
		for _, site := range device.RouteSelection {
			route := deviceSiteRouteItem{SiteID: site.Ref, Via: site.Via}
			if site.Router != "" {
				router := site.Router
				route.RouterID = &router
			}
			item.SubnetRoutes = append(item.SubnetRoutes, route)
		}
		if exit := device.ExitSelection; exit != nil {
			item.Exit = &deviceExitItem{ExitPoolID: exit.Pool, Via: exit.Via}
			if exit.Node != "" {
				exitNode := exit.Node
				item.Exit.ExitNodeID = &exitNode
			}
		}
	}
	return item
}

func classifyDeviceDistributionError(err error) managementError {
	switch {
	case errors.Is(err, distribution.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "device_distribution_forbidden",
			Message: "Policy distribution status is unavailable for this scope"}
	case errors.Is(err, distribution.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "device_not_connectable",
			Message: "The Device is not an active or suspended Device of this Network"}
	case errors.Is(err, distribution.ErrInvalidRequest):
		return *invalidManagementRequest()
	case errors.Is(err, distribution.ErrUnavailable), errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return managementError{Status: http.StatusServiceUnavailable, Code: "device_distribution_unavailable",
			Message: "Policy distribution status is temporarily unavailable", Retryable: true}
	default:
		return internalManagementError()
	}
}

type deviceStatusEnvelope struct {
	Data struct {
		WorkspaceID           string                 `json:"workspace_id"`
		NetworkID             string                 `json:"network_id"`
		NetworkRevision       int64                  `json:"network_revision"`
		PolicyRevision        int64                  `json:"policy_revision"`
		ObservationsAvailable bool                   `json:"observations_available"`
		Device                deviceDistributionItem `json:"device"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

type devicePeersEnvelope struct {
	Data struct {
		DeviceID        string               `json:"device_id"`
		ReportedAt      *time.Time           `json:"reported_at"`
		IntervalSeconds int64                `json:"interval_seconds"`
		ReportedPeers   int                  `json:"reported_peers"`
		Limited         bool                 `json:"limited"`
		Peers           []devicePathPeerItem `json:"peers"`
	} `json:"data"`
	NextPageToken string `json:"next_page_token,omitempty"`
	CorrelationID string `json:"correlation_id"`
}

// readDeviceDetail answers one Device's delivery status, or one page of the
// peers it reported.
func (browser *BrowserManagement) readDeviceDetail(ctx context.Context, response *browserManagementResponse,
	request *http.Request, admission *browserManagementAdmission, read deviceDetailRead,
) error {
	session, fail, correlationID, ok, err := browser.beginDeviceRead(ctx, response, request, admission)
	if !ok {
		return err
	}
	var query devicePeerQuery
	if read.kind == "peers" {
		if query, err = parseDevicePeerQuery(request.URL.RawQuery, read.deviceID); err != nil {
			fail(*invalidManagementRequest())
			return nil
		}
	}
	report, err := browser.distribution.ReadDevice(ctx, session, read.scope, read.deviceID)
	if err != nil {
		fail(classifyDeviceDistributionError(err))
		return nil
	}
	if report.Scope != read.scope || report.Device.ID != read.deviceID {
		fail(internalManagementError())
		return nil
	}
	if read.kind == "status" {
		var envelope deviceStatusEnvelope
		envelope.Data.WorkspaceID = read.scope.WorkspaceID().String()
		envelope.Data.NetworkID = read.scope.NetworkID().String()
		envelope.Data.NetworkRevision, envelope.Data.PolicyRevision = report.NetworkRevision, report.PolicyRevision
		envelope.Data.ObservationsAvailable = report.ObservationsAvailable
		envelope.Data.Device = newDeviceDistributionItem(report.Device, browser.management.countries)
		envelope.CorrelationID = correlationID
		writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, envelope)
		return nil
	}
	return browser.writeDevicePeers(ctx, response, session, read, query, report, fail, correlationID)
}

func (browser *BrowserManagement) writeDevicePeers(ctx context.Context, response *browserManagementResponse,
	session accountsession.Session, read deviceDetailRead, query devicePeerQuery, report distribution.Report,
	fail func(managementError), correlationID string,
) error {
	var envelope devicePeersEnvelope
	envelope.Data.DeviceID, envelope.Data.Peers, envelope.CorrelationID = read.deviceID.String(),
		[]devicePathPeerItem{}, correlationID
	paths := report.Device.Observation.Paths
	if !report.ObservationsAvailable || !report.Device.Observation.Known || paths == nil {
		if query.offset > 0 {
			fail(devicePathsChanged())
			return nil
		}
		writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, envelope)
		return nil
	}
	if query.offset > 0 && !paths.ReportedAt.Equal(query.reportedAt) {
		fail(devicePathsChanged())
		return nil
	}
	matching := make([]distribution.PeerPath, 0, len(paths.Peers))
	for _, peer := range paths.Peers {
		if query.path == "" || peer.Kind == query.path {
			matching = append(matching, peer)
		}
	}
	start := min(query.offset, len(matching))
	end := min(start+query.limit, len(matching))
	page := matching[start:end]
	ids := make([]node.ID, 0, len(page))
	for _, peer := range page {
		if !peer.External {
			ids = append(ids, peer.PeerID)
		}
	}
	names, err := browser.inventory.Names(ctx, session, read.scope, ids)
	if err != nil {
		fail(classifyDeviceInventoryError(err))
		return nil
	}
	reportedAt := paths.ReportedAt.UTC()
	envelope.Data.ReportedAt, envelope.Data.IntervalSeconds = &reportedAt, int64(paths.Interval/time.Second)
	envelope.Data.ReportedPeers, envelope.Data.Limited = len(paths.Peers), len(paths.Peers) >= distribution.MaximumPathPeers
	for _, peer := range page {
		envelope.Data.Peers = append(envelope.Data.Peers, newDevicePathPeerItem(peer, names))
	}
	if end < len(matching) {
		payload, err := json.Marshal(devicePeerPageToken{Version: 1, DeviceID: read.deviceID.String(),
			Path: string(query.path), Offset: end, ReportedAt: paths.ReportedAt})
		if err != nil {
			return ErrBrowserManagementUnavailable
		}
		envelope.NextPageToken = base64.RawURLEncoding.EncodeToString(payload)
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, envelope)
	return nil
}

func devicePathsChanged() managementError {
	return managementError{Status: http.StatusConflict, Code: "device_paths_changed",
		Message: "The Device sent a newer path report. Reload the first page."}
}
