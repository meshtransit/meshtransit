package mobile

import (
	"encoding/json"
	"slices"

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
	ControlKey     string     `json:"controlFingerprint,omitempty"`
	Registration   string     `json:"registration"`
	ControlSession string     `json:"controlSession"`
	ProfileID      string     `json:"profileId,omitempty"`
	ProfileCount   int        `json:"profileCount"`
	NetworkName    string     `json:"networkName,omitempty"`
	NetmapRevision uint64     `json:"netmapRevision"`
	SelfAddresses  []string   `json:"selfAddresses"`
	PeerCount      int        `json:"peerCount"`
	Paths          pathCounts `json:"paths"`
	Version        string     `json:"version"`
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
		SchemaVersion:  statusSchemaVersion,
		Running:        running,
		State:          current.State,
		DataPlane:      current.DataPlane,
		DNS:            current.DNS,
		ControlTrust:   current.ControlTrust,
		ControlKey:     current.ControlFingerprint,
		Registration:   current.Registration,
		ControlSession: current.ControlSession,
		ProfileID:      current.ActiveProfileID,
		ProfileCount:   current.ProfileCount,
		NetworkName:    current.NetworkName,
		NetmapRevision: current.NetmapRevision,
		SelfAddresses:  addresses,
		PeerCount:      current.PeerCount,
		Paths: pathCounts{
			Direct:  current.PeerPaths.DirectCount,
			Relay:   current.PeerPaths.RelayCount,
			Pending: current.PeerPaths.PendingCount,
		},
		Version: current.Build.Version,
	}
}

func (value status) marshal() (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
