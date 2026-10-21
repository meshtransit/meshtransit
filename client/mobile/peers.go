package mobile

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/peerprobe"
)

// The connection test (MeshTransit docs: peer-connection-test.md): the
// peers of the current map, and one round trip to a peer at a time. The app
// takes a sample a second and computes the latency, jitter and loss itself.

// maxListedPeers bounds PeersJSON: a Network may hold 100,000 Devices, and
// the app lists and searches the first ones.
const maxListedPeers = 1000

// peerList is the JSON of PeersJSON.
type peerList struct {
	Peers []listedPeer `json:"peers"`
	// Total counts every peer; Truncated reports that Peers holds fewer.
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

// listedPeer is one peer of the current map.
type listedPeer struct {
	// ID is the Device's stable ID, which PingPeer takes.
	ID string `json:"id"`
	// Name is the Device name without the DNS suffix.
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	// Online is online, offline or unknown.
	Online string `json:"online"`
	// Path is direct, relay, pending (no path yet) or inactive (not held
	// while idle); Relay is the relay region's code while relayed.
	Path  string `json:"path"`
	Relay string `json:"relay,omitempty"`
	// Measurable is whether PingPeer can measure the Device.
	Measurable bool `json:"measurable"`
}

// peerPing is the JSON of PingPeer: one sample.
type peerPing struct {
	// Answered is false for a PING the peer did not answer in time: a lost
	// sample, not an error.
	Answered        bool   `json:"answered"`
	RoundTripMicros int64  `json:"roundTripMicros"`
	Path            string `json:"path,omitempty"`
	Relay           string `json:"relay,omitempty"`
}

// PeersJSON returns the current map's peers: online ones first, then by
// name, at most maxListedPeers. It is empty while no map is applied.
func (engine *Engine) PeersJSON() (value string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		views, peersErr := engine.service.Peers(ctx)
		if peersErr != nil {
			return peersErr
		}
		value, peersErr = marshalJSON(newPeerList(views))
		return peersErr
	})
	return value, err
}

// PingPeer measures one round trip to the Device with the given ID, a peer
// in the current map. It takes up to about four seconds: it waits up to a
// second since the Device's last sample, through the relay up to 1.25 s for
// a PING to carry it, then up to two for the answer. It fails while the VPN
// is not running, for an ID not in the map or a Device that cannot be
// measured, and while another sample of the same Device is being taken.
func (engine *Engine) PingPeer(deviceID string) (value string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		ping, pingErr := engine.service.PingPeer(ctx, strings.TrimSpace(deviceID))
		sample, pingErr := newPeerPing(ping, pingErr)
		if pingErr != nil {
			return pingErr
		}
		value, pingErr = marshalJSON(sample)
		return pingErr
	})
	return value, err
}

func newPeerList(views []daemon.PeerView) peerList {
	sorted := daemon.SortedPeers(views)
	list := peerList{Total: len(sorted), Truncated: len(sorted) > maxListedPeers}
	list.Peers = make([]listedPeer, 0, min(len(sorted), maxListedPeers))
	for _, view := range sorted[:min(len(sorted), maxListedPeers)] {
		name, _, _ := strings.Cut(view.Name, ".")
		addresses := slices.Clone(view.Addresses)
		if addresses == nil {
			addresses = []string{}
		}
		list.Peers = append(list.Peers, listedPeer{
			ID: view.DeviceID, Name: name, Addresses: addresses, Online: onlineOf(view),
			Path: view.Path, Relay: view.RelayRegion, Measurable: view.Measurable,
		})
	}
	return list
}

func onlineOf(view daemon.PeerView) string {
	switch {
	case !view.OnlineKnown:
		return "unknown"
	case view.Online:
		return "online"
	default:
		return "offline"
	}
}

// newPeerPing turns a lost sample into an answer and keeps other failures:
// the VPN not running, a Device not in the map, a sample already being taken.
func newPeerPing(ping daemon.PeerPing, err error) (peerPing, error) {
	if peerprobe.Unanswered(err) {
		return peerPing{Answered: false}, nil
	}
	if err != nil {
		return peerPing{}, err
	}
	return peerPing{
		Answered: true, RoundTripMicros: ping.RoundTrip.Microseconds(), Path: ping.Path, Relay: ping.RelayRegion,
	}, nil
}

func marshalJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
