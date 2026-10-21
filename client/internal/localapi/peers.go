package localapi

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/peerprobe"
)

// The connection test (MeshTransit docs: peer-connection-test.md): the
// peers of the current map, and one round trip to a peer at a time. The app
// takes a sample a second and computes the latency, jitter and loss itself.

const (
	// maxListedPeers bounds GET /v1/peers: a Network may hold 100,000
	// Devices, and the apps list and search the first ones.
	maxListedPeers = 1000
	// maxDeviceIDBytes bounds the Device ID in a ping's path.
	maxDeviceIDBytes = 128
)

// peersResponse is GET /v1/peers.
type peersResponse struct {
	APIVersion string       `json:"api_version"`
	Peers      []peerStatus `json:"peers"`
	// Total counts every peer; Truncated reports that Peers holds fewer.
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

// peerStatus is one peer of the current map. It carries no keys and no
// endpoints.
type peerStatus struct {
	// ID is the Device's stable ID, which the ping takes.
	ID string `json:"id"`
	// Name is the Device name without the DNS suffix; DNSName is all of it.
	Name      string   `json:"name"`
	DNSName   string   `json:"dns_name"`
	Addresses []string `json:"addresses"`
	// Online is online, offline or unknown.
	Online string `json:"online"`
	// Path is direct, relay, pending (no path yet) or inactive (not held
	// while idle); RelayRegion is the relay region's code while relayed.
	Path        string `json:"path"`
	RelayRegion string `json:"relay_region,omitempty"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	// Measurable is whether the ping can measure the Device.
	Measurable bool `json:"measurable"`
}

// peerPingResponse is POST /v1/peers/{id}/ping: one sample.
type peerPingResponse struct {
	APIVersion string `json:"api_version"`
	// Answered is false for a PING the peer did not answer in time: a lost
	// sample, not an error.
	Answered        bool   `json:"answered"`
	RoundTripMicros int64  `json:"round_trip_micros"`
	Path            string `json:"path,omitempty"`
	RelayRegion     string `json:"relay_region,omitempty"`
}

func (s *Server) handlePeers(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		s.writeMethodNotAllowed(writer, http.MethodGet)
		return
	}
	views, err := s.service.Peers(request.Context())
	if err != nil {
		s.writeServiceError(writer, err)
		return
	}
	sorted := daemon.SortedPeers(views)
	listed := sorted[:min(len(sorted), maxListedPeers)]
	response := peersResponse{
		APIVersion: apiVersion,
		Peers:      make([]peerStatus, 0, len(listed)),
		Total:      len(sorted),
		Truncated:  len(sorted) > len(listed),
	}
	for _, view := range listed {
		response.Peers = append(response.Peers, newPeerStatus(view))
	}
	s.writeJSON(writer, http.StatusOK, response)
}

func newPeerStatus(view daemon.PeerView) peerStatus {
	name, _, _ := strings.Cut(view.Name, ".")
	addresses := slices.Clone(view.Addresses)
	if addresses == nil {
		addresses = []string{}
	}
	online := "unknown"
	if view.OnlineKnown {
		online = "offline"
		if view.Online {
			online = "online"
		}
	}
	return peerStatus{
		ID: view.DeviceID, Name: name, DNSName: view.Name, Addresses: addresses, Online: online,
		Path: view.Path, RelayRegion: view.RelayRegion, RxBytes: view.RxBytes, TxBytes: view.TxBytes,
		Measurable: view.Measurable,
	}
}

// handlePeerPing takes one sample: up to about four seconds, within the
// server's write timeout. A lost sample is an answer, not an error.
func (s *Server) handlePeerPing(writer http.ResponseWriter, request *http.Request) {
	if !s.acceptEmptyPost(writer, request) {
		return
	}
	deviceID := request.PathValue("id")
	if deviceID == "" || len(deviceID) > maxDeviceIDBytes ||
		strings.IndexFunc(deviceID, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		s.writeError(writer, http.StatusBadRequest, "invalid_device_id", "the device ID is invalid")
		return
	}
	ping, err := s.service.PingPeer(request.Context(), deviceID)
	switch {
	case peerprobe.Unanswered(err):
		s.writeJSON(writer, http.StatusOK, peerPingResponse{APIVersion: apiVersion})
	case errors.Is(err, daemon.ErrPeerNotFound):
		s.writeError(writer, http.StatusNotFound, "peer_not_found", "the device is not in this node's map")
	case errors.Is(err, daemon.ErrPeerTestUnavailable):
		s.writeError(writer, http.StatusConflict, "peer_test_unavailable", "the connection test needs a running session")
	case errors.Is(err, daemon.ErrPeerNotMeasurable):
		s.writeError(writer, http.StatusConflict, "peer_not_measurable", "the device cannot be measured")
	case errors.Is(err, peerprobe.ErrMeasurementBusy):
		s.writeError(writer, http.StatusTooManyRequests, "measurement_busy", "another measurement is running; try again")
	case errors.Is(err, peerprobe.ErrNoRelay):
		s.writeError(writer, http.StatusServiceUnavailable, "no_relay", "no direct path and no relay to measure through")
	case err != nil:
		s.writeServiceError(writer, err)
	default:
		s.writeJSON(writer, http.StatusOK, peerPingResponse{
			APIVersion: apiVersion, Answered: true, RoundTripMicros: ping.RoundTrip.Microseconds(),
			Path: ping.Path, RelayRegion: ping.RelayRegion,
		})
	}
}
