package mobile

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"meshtransit.net/client/internal/daemon"
)

// statusSchemaVersion versions the status JSON. A field is only added in a
// version; renaming or removing one needs a new APIVersion.
const statusSchemaVersion = 1

// status is the JSON the app reads from StatusJSON. Every field comes from
// state the daemon already holds; it carries no keys, tokens or endpoints.
type status struct {
	SchemaVersion int    `json:"schemaVersion"`
	Running       bool   `json:"running"`
	State         string `json:"state"`
	DataPlane     string `json:"dataPlane"`
	DNS           string `json:"dns"`
	ControlTrust  string `json:"controlTrust"`
	// ControlKey is the fingerprint of the pinned Core key, once trusted.
	ControlKey     string   `json:"controlFingerprint,omitempty"`
	Registration   string   `json:"registration"`
	ControlSession string   `json:"controlSession"`
	ProfileID      string   `json:"profileId,omitempty"`
	ProfileCount   int      `json:"profileCount"`
	NetworkName    string   `json:"networkName,omitempty"`
	NetmapRevision uint64   `json:"netmapRevision"`
	SelfAddresses  []string `json:"selfAddresses"`
	// DeviceExpiresAt is the Device's expiry (RFC 3339); omitted before a
	// map arrives and for a Device that never expires.
	DeviceExpiresAt string `json:"deviceExpiresAt,omitempty"`
	// DeviceExpiry is unknown, never, ok, soon (14 days or less), imminent
	// (a day or less) or expired.
	DeviceExpiry string     `json:"deviceExpiry"`
	PeerCount    int        `json:"peerCount"`
	Paths        pathCounts `json:"paths"`
	Version      string     `json:"version"`
	// SubnetRoutes is what the device does with the Sites Core grants, and
	// Sites the router each one goes through.
	SubnetRoutes subnetRoutes `json:"subnetRoutes"`
	Sites        []siteRoute  `json:"sites"`
	// Exit is the Exit Pool in use; absent when none is chosen.
	Exit *exitStatus `json:"exit,omitempty"`
}

// exitStatus is the Exit Pool the device sends its Internet traffic
// through.
type exitStatus struct {
	// Use is the app's setting (SetExitNode); Pool the pool's name, empty
	// while Core grants none of that name.
	Use  string `json:"use"`
	Pool string `json:"pool,omitempty"`
	// Node is the exit node's Device name, without the DNS suffix; empty
	// while none carries the traffic, which is then dropped.
	Node string `json:"node,omitempty"`
	Via  string `json:"via"`
	// Routing is whether the VPN interface carries the Internet.
	Routing bool `json:"routing"`
	// Pending are exit nodes, and PendingPool a pool, waiting for the
	// person's approval (ApproveExitNodes takes their IDs).
	Pending     []pendingExitNode `json:"pending,omitempty"`
	PendingPool string            `json:"pendingPool,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// pendingExitNode is one exit node waiting for approval.
type pendingExitNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// subnetRoutes counts the granted subnet routes on the VPN interface and
// those refused (by the settings, or overlapping an attached network).
type subnetRoutes struct {
	// Accepted is the app's setting (SetSubnetRoutes).
	Accepted      bool   `json:"accepted"`
	Requested     int    `json:"requested"`
	Installed     int    `json:"installed"`
	Refused       int    `json:"refused"`
	LocalConflict bool   `json:"localConflict"`
	Error         string `json:"error,omitempty"`
}

// siteRoute is one granted Site and the router its traffic goes to: via
// primary (Core's choice), local_failover or none (not served).
type siteRoute struct {
	Site string `json:"site"`
	// Name is the Site's display name; empty from an older Core.
	Name string `json:"name,omitempty"`
	// Prefixes are the Site's granted prefixes, which name it here.
	Prefixes []string `json:"prefixes"`
	// Router is the router's Device name, without the DNS suffix.
	Router string `json:"router,omitempty"`
	Via    string `json:"via"`
}

// pathCounts counts the current map's peers by packet path.
type pathCounts struct {
	Direct  int `json:"direct"`
	Relay   int `json:"relay"`
	Pending int `json:"pending"`
}

// newStatus maps the daemon status to the app's JSON model.
func newStatus(running bool, current daemon.Status) status {
	addresses := slices.Clone(current.SelfAddresses)
	if addresses == nil {
		addresses = []string{}
	}
	return status{
		SchemaVersion:   statusSchemaVersion,
		Running:         running,
		State:           current.State,
		DataPlane:       current.DataPlane,
		DNS:             current.DNS,
		ControlTrust:    current.ControlTrust,
		ControlKey:      current.ControlFingerprint,
		Registration:    current.Registration,
		ControlSession:  current.ControlSession,
		ProfileID:       current.ActiveProfileID,
		ProfileCount:    current.ProfileCount,
		NetworkName:     current.NetworkName,
		NetmapRevision:  current.NetmapRevision,
		SelfAddresses:   addresses,
		DeviceExpiresAt: deviceExpiresAt(current),
		DeviceExpiry:    deviceExpiry(current),
		PeerCount:       current.PeerCount,
		Paths: pathCounts{
			Direct:  current.PeerPaths.DirectCount,
			Relay:   current.PeerPaths.RelayCount,
			Pending: current.PeerPaths.PendingCount,
		},
		Version: current.Build.Version,
		SubnetRoutes: subnetRoutes{
			Requested: current.SubnetRoutes.Requested, Installed: current.SubnetRoutes.Installed,
			Refused: current.SubnetRoutes.RefusedTotal, LocalConflict: current.SubnetRoutes.LocalConflict,
			Error: current.SubnetRoutes.Error,
		},
		Sites: siteRoutes(current.RouteSites),
		Exit:  exitStatusOf(current),
	}
}

func exitStatusOf(current daemon.Status) *exitStatus {
	view := current.Exit
	if view == nil {
		return nil
	}
	node, _, _ := strings.Cut(view.ExitNodeName, ".")
	exit := &exitStatus{
		Use: view.Use, Pool: view.PoolName, Node: node, Via: view.Via, Routing: current.ExitRoute.Routing,
		PendingPool: view.PendingPool, Error: current.ExitRoute.Error,
	}
	for index, id := range view.Pending {
		name := ""
		if index < len(view.PendingNames) {
			name, _, _ = strings.Cut(view.PendingNames[index], ".")
		}
		exit.Pending = append(exit.Pending, pendingExitNode{ID: id, Name: name})
	}
	return exit
}

func siteRoutes(views []daemon.RouteSiteView) []siteRoute {
	sites := make([]siteRoute, 0, len(views))
	for _, view := range views {
		prefixes := make([]string, 0, len(view.Prefixes))
		for _, prefix := range view.Prefixes {
			prefixes = append(prefixes, prefix.String())
		}
		router, _, _ := strings.Cut(view.RouterName, ".")
		sites = append(sites, siteRoute{
			Site: view.Ref, Name: view.Name, Prefixes: prefixes, Router: router, Via: view.Via,
		})
	}
	return sites
}

func (value status) marshal() (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func deviceExpiresAt(current daemon.Status) string {
	if current.DeviceExpiresAt.IsZero() || current.DeviceExpiry == daemon.DeviceExpiryNever {
		return ""
	}
	return current.DeviceExpiresAt.UTC().Format(time.RFC3339)
}

func deviceExpiry(current daemon.Status) string {
	if current.DeviceExpiry == "" {
		return daemon.DeviceExpiryUnknown
	}
	return current.DeviceExpiry
}
