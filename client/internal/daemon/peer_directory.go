package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/peerprobe"
)

// The peers of the current map and on-demand round trips to them, for the
// apps' connection test (MeshTransit docs: peer-connection-test.md).

// Peer paths in PeerView.Path and PeerPing.Path.
const (
	PeerPathDirect = "direct"
	PeerPathRelay  = "relay"
	// PeerPathPending is a peer WireGuard holds that has no path yet.
	PeerPathPending = "pending"
	// PeerPathInactive is a peer WireGuard does not hold (lazy peers).
	PeerPathInactive = "inactive"
)

var (
	// ErrPeerNotFound reports a Device that is not a peer in the current map.
	ErrPeerNotFound = errors.New("daemon: no such peer in the current map")
	// ErrPeerTestUnavailable reports no running session to measure from.
	ErrPeerTestUnavailable = errors.New("daemon: the connection test needs a running session")
	// ErrPeerNotMeasurable reports a peer the map gives no discovery key:
	// this node exchanges no disco messages with it, so it cannot ping it.
	ErrPeerNotMeasurable = errors.New("daemon: the peer cannot be measured")
)

// PeerView is one peer of the current map, as the apps show it. It carries
// no keys and no endpoints.
type PeerView struct {
	// DeviceID is the peer Device's stable ID, which PingPeer takes.
	DeviceID string
	// Name is the Device's name in the map, its DNS name.
	Name        string
	Addresses   []string
	OnlineKnown bool
	Online      bool
	// Path is direct, relay, pending or inactive; RelayRegion is the relay
	// region's code while relayed.
	Path        string
	RelayRegion string
	RxBytes     uint64
	TxBytes     uint64
	// Measurable is whether PingPeer can measure the peer: the map gives it
	// a discovery key.
	Measurable bool
}

// PeerPing is one round trip to a peer.
type PeerPing struct {
	RoundTrip time.Duration
	// Path is direct or relay; RelayRegion is the relay region's code when
	// relayed, empty when unknown.
	Path        string
	RelayRegion string
}

// roundTripMeasurer is the session's peer-probe runtime.
type roundTripMeasurer interface {
	MeasureRoundTrip(ctx context.Context, peerID uint64) (peerprobe.RoundTrip, error)
}

// peerDirectory is an immutable summary of one map's peers.
type peerDirectory struct {
	peers      []directoryPeer
	byDevice   map[string]int
	byAddress  map[netip.Addr]int
	relayCodes map[int]string
}

type directoryPeer struct {
	id        uint64
	homeRelay int
	view      PeerView
}

func newPeerDirectory(snapshot networkmap.Snapshot) *peerDirectory {
	directory := &peerDirectory{
		peers:      make([]directoryPeer, 0, len(snapshot.Peers)),
		byDevice:   make(map[string]int, len(snapshot.Peers)),
		byAddress:  make(map[netip.Addr]int, len(snapshot.Peers)),
		relayCodes: make(map[int]string, len(snapshot.Relays)),
	}
	for id, region := range snapshot.Relays {
		directory.relayCodes[id] = region.Code
	}
	for _, peer := range snapshot.Peers {
		if peer.StableID == "" {
			continue
		}
		if _, duplicate := directory.byDevice[peer.StableID]; duplicate {
			continue
		}
		addresses := make([]string, 0, len(peer.Addresses))
		for _, prefix := range peer.Addresses {
			addresses = append(addresses, prefix.Addr().String())
			directory.byAddress[prefix.Addr()] = len(directory.peers)
		}
		directory.byDevice[peer.StableID] = len(directory.peers)
		directory.peers = append(directory.peers, directoryPeer{
			id:        peer.ID,
			homeRelay: peer.HomeRelay,
			view: PeerView{
				DeviceID: peer.StableID, Name: peer.Name, Addresses: addresses,
				OnlineKnown: peer.OnlineKnown, Online: peer.OnlineKnown && peer.Online,
				Measurable: peer.DiscoveryKey != "",
			},
		})
	}
	return directory
}

// peerViews joins the directory with the data plane's per-peer paths.
func peerViews(directory *peerDirectory, stats []dataplane.PeerPathStat) []PeerView {
	if directory == nil {
		return []PeerView{}
	}
	byID := make(map[uint64]dataplane.PeerPathStat, len(stats))
	for _, stat := range stats {
		byID[stat.PeerID] = stat
	}
	views := make([]PeerView, 0, len(directory.peers))
	for _, peer := range directory.peers {
		view := peer.view
		view.Addresses = slices.Clone(view.Addresses)
		stat, held := byID[peer.id]
		view.Path, view.RelayRegion = pathOf(stat, held, directory.relayCodes)
		view.RxBytes, view.TxBytes = stat.RxBytes, stat.TxBytes
		views = append(views, view)
	}
	return views
}

func pathOf(stat dataplane.PeerPathStat, held bool, relayCodes map[int]string) (string, string) {
	if !held {
		return PeerPathInactive, ""
	}
	switch stat.Path {
	case dataplane.PeerPathDirectUDP:
		return PeerPathDirect, ""
	case dataplane.PeerPathRelayed:
		return PeerPathRelay, relayCodes[stat.RelayRegion]
	case dataplane.PeerPathUnknown:
		return PeerPathPending, ""
	default:
		return PeerPathPending, ""
	}
}

// SortedPeers returns views as the apps list them: online peers first, then
// those whose state is unknown, then offline ones, each by the first label
// of the name, then ID. The
// keys are made once: a Network may hold 100,000 Devices.
func SortedPeers(views []PeerView) []PeerView {
	type keyed struct {
		rank int
		name string
		view PeerView
	}
	sorted := make([]keyed, len(views))
	for index, view := range views {
		label, _, _ := strings.Cut(view.Name, ".")
		sorted[index] = keyed{rank: onlineRank(view), name: strings.ToLower(label), view: view}
	}
	slices.SortFunc(sorted, func(a, b keyed) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(a.name, b.name),
			cmp.Compare(a.view.DeviceID, b.view.DeviceID))
	})
	result := make([]PeerView, len(sorted))
	for index, entry := range sorted {
		result[index] = entry.view
	}
	return result
}

func onlineRank(view PeerView) int {
	switch {
	case view.OnlineKnown && view.Online:
		return 0
	case !view.OnlineKnown:
		return 1
	default:
		return 2
	}
}

// peerSession is the session state the connection test reads.
type peerSession struct {
	mu        sync.RWMutex
	directory *peerDirectory
	measurer  roundTripMeasurer
}

func (p *peerSession) setDirectory(directory *peerDirectory) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.directory = directory
}

func (p *peerSession) setMeasurer(measurer roundTripMeasurer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.measurer = measurer
}

func (p *peerSession) read() (*peerDirectory, roundTripMeasurer) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.directory, p.measurer
}

// Peers lists the current map's peers with their paths; empty without a map.
func (s *Service) Peers(ctx context.Context) ([]PeerView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory, _ := s.peerSession.read()
	return peerViews(directory, s.peerPathStats()), nil
}

// PeerAt returns the current map's Device at a mesh address, without its
// path, which only the data plane knows and costs a walk of every peer.
func (s *Service) PeerAt(address netip.Addr) (PeerView, bool) {
	directory, _ := s.peerSession.read()
	if directory == nil {
		return PeerView{}, false
	}
	index, ok := directory.byAddress[address.Unmap()]
	if !ok {
		return PeerView{}, false
	}
	view := directory.peers[index].view
	view.Addresses = slices.Clone(view.Addresses)
	return view, true
}

// PingPeer measures one round trip to the Device, a peer in the current map.
func (s *Service) PingPeer(ctx context.Context, deviceID string) (PeerPing, error) {
	if err := ctx.Err(); err != nil {
		return PeerPing{}, err
	}
	directory, measurer := s.peerSession.read()
	if directory == nil || measurer == nil {
		return PeerPing{}, ErrPeerTestUnavailable
	}
	index, found := directory.byDevice[deviceID]
	if !found {
		return PeerPing{}, ErrPeerNotFound
	}
	peer := directory.peers[index]
	if !peer.view.Measurable {
		return PeerPing{}, ErrPeerNotMeasurable
	}
	roundTrip, err := measurer.MeasureRoundTrip(ctx, peer.id)
	if err != nil {
		return PeerPing{}, fmt.Errorf("measuring the round trip to %s: %w", deviceID, err)
	}
	ping := PeerPing{RoundTrip: roundTrip.Duration, Path: PeerPathDirect}
	if roundTrip.Relayed {
		// A relay PING goes to the peer's home relay region. Reading the data
		// plane's paths instead would walk every peer for each sample.
		ping.Path, ping.RelayRegion = PeerPathRelay, directory.relayCodes[peer.homeRelay]
	}
	return ping, nil
}

// peerPathStats reads the data plane's per-peer paths, when it reports them.
func (s *Service) peerPathStats() []dataplane.PeerPathStat {
	statsPlane, supported := s.dataPlane.(pathStatsDataPlane)
	if !supported {
		return nil
	}
	s.dataPlaneMu.Lock()
	defer s.dataPlaneMu.Unlock()
	return statsPlane.PeerPathStats()
}
