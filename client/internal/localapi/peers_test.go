package localapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/peerprobe"
)

// peerService answers the connection test; the rest of service is unused.
type peerService struct {
	service
	views []daemon.PeerView
	ping  daemon.PeerPing
	err   error
	asked string
}

func (p *peerService) Peers(context.Context) ([]daemon.PeerView, error) { return p.views, p.err }

func (p *peerService) PingPeer(_ context.Context, deviceID string) (daemon.PeerPing, error) {
	p.asked = deviceID
	return p.ping, p.err
}

func newPeerServer(t *testing.T, fake *peerService) *Server {
	t.Helper()
	server, err := New(fake, slog.New(slog.DiscardHandler), Options{AllowedUIDs: []uint32{testUID}})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestPeersListsOnlineDevicesFirstWithoutTheSuffix(t *testing.T) {
	t.Parallel()
	server := newPeerServer(t, &peerService{views: []daemon.PeerView{
		{DeviceID: "d3", Name: "zeta.mesh.example", OnlineKnown: true, Online: false, Path: "inactive"},
		{
			DeviceID: "d1", Name: "Beta.mesh.example", OnlineKnown: true, Online: true, Path: "relay",
			RelayRegion: "sgp", Measurable: true, Addresses: []string{"100.64.0.2"},
		},
		{DeviceID: "d2", Name: "alpha.mesh.example", Path: "pending"},
	}})
	response := performRequest(t, server, http.MethodGet, "/v1/peers", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body)
	}
	list := decodeResponse[peersResponse](t, response)
	if list.Total != 3 || list.Truncated || len(list.Peers) != 3 {
		t.Fatalf("list = %+v", list)
	}
	first := list.Peers[0]
	if first.ID != "d1" || first.Name != "Beta" || first.DNSName != "Beta.mesh.example" || first.Online != "online" ||
		first.Path != "relay" || first.RelayRegion != "sgp" || !first.Measurable || len(first.Addresses) != 1 {
		t.Fatalf("first peer = %+v", first)
	}
	if list.Peers[1].ID != "d2" || list.Peers[1].Online != "unknown" || list.Peers[1].Addresses == nil {
		t.Fatalf("second peer = %+v", list.Peers[1])
	}
	if list.Peers[2].Online != "offline" {
		t.Fatalf("third peer = %+v", list.Peers[2])
	}
}

func TestPeersListsAtMostAThousand(t *testing.T) {
	t.Parallel()
	views := make([]daemon.PeerView, maxListedPeers+5)
	for index := range views {
		views[index] = daemon.PeerView{DeviceID: fmt.Sprintf("d%05d", index), Name: fmt.Sprintf("n%05d.x", index)}
	}
	list := decodeResponse[peersResponse](t, performRequest(t, newPeerServer(t, &peerService{views: views}),
		http.MethodGet, "/v1/peers", "", nil))
	if list.Total != len(views) || !list.Truncated || len(list.Peers) != maxListedPeers {
		t.Fatalf("total %d, truncated %v, listed %d", list.Total, list.Truncated, len(list.Peers))
	}
}

func TestPeerPingAnswersASampleOrWhyNot(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		ping     daemon.PeerPing
		err      error
		status   int
		code     string
		answered bool
	}{
		{
			name: "answered", ping: daemon.PeerPing{RoundTrip: 12345 * time.Microsecond, Path: "relay", RelayRegion: "sgp"},
			status: http.StatusOK, answered: true,
		},
		{name: "lost", err: peerprobe.ErrNoAnswer, status: http.StatusOK},
		{name: "lost to a map change", err: peerprobe.ErrInactive, status: http.StatusOK},
		{name: "not in the map", err: daemon.ErrPeerNotFound, status: http.StatusNotFound, code: "peer_not_found"},
		{
			name: "not running", err: daemon.ErrPeerTestUnavailable, status: http.StatusConflict,
			code: "peer_test_unavailable",
		},
		{
			name: "not measurable", err: daemon.ErrPeerNotMeasurable, status: http.StatusConflict,
			code: "peer_not_measurable",
		},
		{name: "busy", err: peerprobe.ErrMeasurementBusy, status: http.StatusTooManyRequests, code: "measurement_busy"},
		{name: "no relay", err: peerprobe.ErrNoRelay, status: http.StatusServiceUnavailable, code: "no_relay"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fake := &peerService{ping: test.ping, err: test.err}
			response := performRequest(t, newPeerServer(t, fake), http.MethodPost, "/v1/peers/dev-1/ping", "", nil)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body)
			}
			if fake.asked != "dev-1" {
				t.Fatalf("pinged %q", fake.asked)
			}
			if test.code != "" {
				if body := decodeResponse[errorResponse](t, response); body.Code != test.code {
					t.Fatalf("code = %q, want %q", body.Code, test.code)
				}
				return
			}
			sample := decodeResponse[peerPingResponse](t, response)
			if sample.Answered != test.answered {
				t.Fatalf("sample = %+v", sample)
			}
			if test.answered && (sample.RoundTripMicros != 12345 || sample.Path != "relay" || sample.RelayRegion != "sgp") {
				t.Fatalf("sample = %+v", sample)
			}
		})
	}
}

func TestPeerPingRefusesBadRequests(t *testing.T) {
	t.Parallel()
	fake := &peerService{}
	server := newPeerServer(t, fake)
	for _, test := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/v1/peers/dev-1/ping", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/peers/dev-1/ping", "{}", http.StatusBadRequest},
		{http.MethodPost, "/v1/peers/" + strings.Repeat("x", maxDeviceIDBytes+1) + "/ping", "", http.StatusBadRequest},
		{http.MethodPost, "/v1/peers/%20dev/ping", "", http.StatusBadRequest},
		{http.MethodPost, "/v1/peers", "", http.StatusMethodNotAllowed},
	} {
		response := performRequest(t, server, test.method, test.path, "", []byte(test.body))
		if response.Code != test.status {
			t.Errorf("%s %s = %d, want %d", test.method, test.path, response.Code, test.status)
		}
	}
	if fake.asked != "" {
		t.Fatalf("a bad request pinged %q", fake.asked)
	}
}

func TestPeersWithoutAMapIsAnEmptyList(t *testing.T) {
	t.Parallel()
	response := performRequest(t, newPeerServer(t, &peerService{}), http.MethodGet, "/v1/peers", "", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"peers":[]`) {
		t.Fatalf("empty map = %d: %s", response.Code, response.Body)
	}
}

func TestPeerPingKeepsTheIDInItsSegment(t *testing.T) {
	t.Parallel()
	fake := &peerService{err: daemon.ErrPeerNotFound}
	server := newPeerServer(t, fake)
	// An encoded slash stays in the ID: the lookup fails, nothing else is
	// reached.
	response := performRequest(t, server, http.MethodPost, "/v1/peers/a%2Fb/ping", "", nil)
	if response.Code != http.StatusNotFound || fake.asked != "a/b" {
		t.Fatalf("encoded slash = %d, pinged %q", response.Code, fake.asked)
	}
	fake.asked = ""
	if response := performRequest(t, server, http.MethodPost, "/v1/peers/a%0Ab/ping", "", nil); response.Code !=
		http.StatusBadRequest || fake.asked != "" {
		t.Fatalf("control character = %d, pinged %q", response.Code, fake.asked)
	}
}
