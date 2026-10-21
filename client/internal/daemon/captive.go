package daemon

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/underlay"
)

// Captive portal detection while the host uses an exit node (exit node
// design §17.3): the relays of the last map, kept on disk so a host that
// starts behind a portal knows where to probe, and what was found, for
// status and to hold the exit choice.

const (
	captiveRelaysFile = "captive-relays.json"
	// maxCaptiveRelays bounds the relay addresses kept.
	maxCaptiveRelays = 8
)

// CaptiveView is what status shows of a captive portal: its state (none,
// suspected, portal, or open while root holds a window open), the sign-in
// page the network named, and since when; for an open window, when it ends
// and the interface it opens.
type CaptiveView struct {
	State     string
	URL       string
	Since     time.Time
	Until     time.Time
	Interface string
}

// captiveStateOpen is the state of a window root holds open.
const captiveStateOpen = "open"

// captiveCloseAfter is how long the tunnel must be back before meshd asks
// the helper to close a window: a portal may take several steps (exit node
// design §17.4).
const captiveCloseAfter = 15 * time.Second

// captiveWindowFollow is what meshd follows of a window root opened.
type captiveWindowFollow struct {
	id    string
	until time.Time
	iface string
	// downSeen: the tunnel was down during the window; upSince is since
	// when it is back.
	downSeen bool
	upSince  time.Time
	// portalFor is the sign-in page portals were found for.
	portalFor string
	portals   [2]netip.AddrPort
}

// captiveRelays are the relay addresses to probe and one relay's name.
type captiveRelays struct {
	Addresses []netip.Addr `json:"addresses"`
	Name      string       `json:"name,omitempty"`
}

// captiveTracker holds the relays, the detector's last state and the
// window root opened.
type captiveTracker struct {
	mu     sync.Mutex
	dir    string
	relays captiveRelays
	state  captive.State
	window captiveWindowFollow
	// exitAnswered reports the exit node in use answered after a time.
	exitAnswered func(time.Time) bool
}

// newCaptiveTracker reads the relays kept in dir, none when it has none.
func newCaptiveTracker(dir string) *captiveTracker {
	tracker := &captiveTracker{dir: dir, state: captive.State{Verdict: captive.VerdictNone}}
	if dir == "" {
		return tracker
	}
	encoded, err := os.ReadFile(filepath.Join(dir, captiveRelaysFile)) //nolint:gosec // G304: the daemon's state dir
	if err != nil || len(encoded) > 4<<10 {
		return tracker
	}
	var kept captiveRelays
	if json.Unmarshal(encoded, &kept) == nil && len(kept.Addresses) <= maxCaptiveRelays && len(kept.Name) <= 253 {
		tracker.relays = kept
	}
	return tracker
}

// noteRelays keeps the relays of a map, on disk when they changed.
func (t *captiveTracker) noteRelays(regions map[int]networkmap.RelayRegion) {
	var relays captiveRelays
	ids := make([]int, 0, len(regions))
	for id := range regions {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		for _, node := range regions[id].Nodes {
			for _, text := range []string{node.IPv4, node.IPv6} {
				if address, err := netip.ParseAddr(text); err == nil && len(relays.Addresses) < maxCaptiveRelays {
					relays.Addresses = append(relays.Addresses, address)
				}
			}
			if relays.Name == "" {
				relays.Name = node.HostName
			}
		}
	}
	if len(relays.Addresses) == 0 {
		return // a map without relays forgets nothing
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if slices.Equal(relays.Addresses, t.relays.Addresses) && relays.Name == t.relays.Name {
		return
	}
	t.relays = relays
	if t.dir == "" {
		return
	}
	if encoded, err := json.Marshal(relays); err == nil {
		_ = writeFileAtomically(filepath.Join(t.dir, captiveRelaysFile), encoded) // kept in memory when it cannot be written
	}
}

func (t *captiveTracker) relaysSnapshot() captiveRelays {
	t.mu.Lock()
	defer t.mu.Unlock()
	return captiveRelays{Addresses: slices.Clone(t.relays.Addresses), Name: t.relays.Name}
}

func (t *captiveTracker) setState(state captive.State) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = state
}

// held reports a portal suspected or found: the exit choice stays as it is,
// as the network under it, not the exit node, is at fault.
func (t *captiveTracker) held() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state.Verdict == captive.VerdictSuspected || t.state.Verdict == captive.VerdictPortal ||
		t.window.id != ""
}

func (t *captiveTracker) view() CaptiveView {
	if t == nil {
		return CaptiveView{State: string(captive.VerdictNone)}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	view := CaptiveView{State: string(t.state.Verdict), URL: t.state.URL, Since: t.state.Since}
	if t.window.id != "" {
		view.State, view.Until, view.Interface = captiveStateOpen, t.window.until, t.window.iface
	}
	return view
}

// setExitAnswered sets how the tracker learns that the exit node in use
// answered: from the session's failover.
func (t *captiveTracker) setExitAnswered(answered func(time.Time) bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.exitAnswered = answered
}

// followWindow follows the window the helper reported open until until, and
// returns the window to ask the helper to close (empty for none) and
// whether one is open. up is whether the control session is synchronized:
// once the tunnel was down during a window and is back, with the exit node
// answering or the control session, for captiveCloseAfter, the window has
// done its work. A window opened while the tunnel works stays: root knows
// better.
func (t *captiveTracker) followWindow(window netadmin.CaptiveWindow, until, now time.Time, up bool) (string, bool) {
	t.mu.Lock()
	answered := t.exitAnswered
	t.mu.Unlock()
	// Asked outside the lock: the failover asks held() under its own.
	if !up && answered != nil && window.ID != "" {
		up = answered(now.Add(-failoverAliveWithin))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if window.ID == "" || !now.Before(until) {
		t.window = captiveWindowFollow{}
		return "", false
	}
	if window.ID != t.window.id {
		t.window = captiveWindowFollow{id: window.ID}
	}
	t.window.until, t.window.iface = until, window.Interface
	switch {
	case !up:
		t.window.downSeen, t.window.upSince = true, time.Time{}
	case !t.window.downSeen:
	case t.window.upSince.IsZero():
		t.window.upSince = now
	case now.Sub(t.window.upSince) >= captiveCloseAfter:
		return t.window.id, true
	}
	return "", true
}

// portalWanted is the sign-in page whose portal to let through, when a
// window is open and the page is not resolved yet; empty otherwise.
func (t *captiveTracker) portalWanted() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.window.id == "" || t.state.URL == t.window.portalFor {
		return ""
	}
	return t.state.URL
}

// setPortals keeps the portals found for the sign-in page url.
func (t *captiveTracker) setPortals(url string, portals [2]netip.AddrPort) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.window.id != "" {
		t.window.portalFor, t.window.portals = url, portals
	}
}

// portals are the portals to let through the open window.
func (t *captiveTracker) portals() [2]netip.AddrPort {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.window.portals
}

// newCaptiveDetector checks the network from the client's own sockets.
func (s *Service) newCaptiveDetector() *captive.Detector {
	return captive.NewDetector(captive.Config{
		Inputs: func() captive.Inputs {
			relays := s.captive.relaysSnapshot()
			return captive.Inputs{
				ExitWanted: underlay.IsExitChosen(),
				ControlUp:  s.getSyncStatus().state == ControlSessionSynchronized,
				Relays:     relays.Addresses, RelayName: relays.Name,
			}
		},
		Checker: captive.NewProber(underlay.Control),
		APIURIs: captive.APIURIs,
		Resolve: func(ctx context.Context, name string) ([]netip.Addr, error) {
			return underlay.Resolver().LookupNetIP(ctx, "ip", name)
		},
		Clock: s.clock,
		OnChange: func(state captive.State) {
			s.captive.setState(state)
			if s.logger != nil {
				s.logger.Info("captive portal state changed", "state", state.Verdict, "sign_in", state.URL)
			}
		},
	})
}

// captiveView is the captive portal for status.
func (s *Service) captiveView() CaptiveView { return s.captive.view() }

// Following a captive portal window.
const (
	// captiveFollowEvery is how often meshd looks at the window.
	captiveFollowEvery = time.Second
	// captiveRecheckEvery is how often meshd asks the helper again while a
	// portal is suspected or a window open: the window opens and ends in
	// the helper, which tells meshd only when asked.
	captiveRecheckEvery = 2 * time.Second
	// portalLookupTimeout bounds finding a sign-in page's address.
	portalLookupTimeout = 2 * time.Second
)

// captiveDataPlane is the data plane's part in a captive portal window.
type captiveDataPlane interface {
	SetCaptiveRequest(portals [2]netip.AddrPort, closeWindow string)
	RecheckExitRoute()
}

// captiveDNS sends names to the network's resolvers during a window.
type captiveDNS interface {
	SetCaptiveWindow(open bool)
}

// runCaptiveWindow follows a captive portal window root opens until ctx
// ends: names go to the network's resolvers while it is open, the helper
// lets the portal meshd found through, and closes the window once the
// tunnel is back (exit node design §17.4, §17.5).
func (s *Service) runCaptiveWindow(ctx context.Context) {
	ticker := time.NewTicker(captiveFollowEvery)
	defer ticker.Stop()
	var rechecked time.Time
	open := false
	for {
		select {
		case <-ctx.Done():
			s.setCaptiveDNS(false)
			return
		case <-ticker.C:
		}
		status := s.exitRouteStatus()
		now := s.clock()
		closeWindow, nowOpen := s.captive.followWindow(status.Captive, status.CaptiveUntil, now,
			s.getSyncStatus().state == ControlSessionSynchronized)
		if nowOpen != open {
			open = nowOpen
			s.setCaptiveDNS(open)
			if s.logger != nil {
				s.logger.Info("captive portal window", "open", open, "interface", status.Captive.Interface)
			}
		}
		if url := s.captive.portalWanted(); url != "" {
			s.captive.setPortals(url, findPortals(ctx, url))
		}
		s.withCaptiveDataPlane(func(plane captiveDataPlane) {
			plane.SetCaptiveRequest(s.captive.portals(), closeWindow)
			if s.captive.held() && now.Sub(rechecked) >= captiveRecheckEvery {
				rechecked = now
				plane.RecheckExitRoute()
			}
		})
	}
}

// CheckCaptiveWindow asks the helper at once about a window root just
// opened or closed, so names follow it without waiting.
func (s *Service) CheckCaptiveWindow() {
	s.withCaptiveDataPlane(func(plane captiveDataPlane) { plane.RecheckExitRoute() })
}

func (s *Service) withCaptiveDataPlane(use func(captiveDataPlane)) {
	if s == nil || s.dataPlane == nil || !s.enableExits {
		return
	}
	s.dataPlaneMu.Lock()
	defer s.dataPlaneMu.Unlock()
	if plane, ok := s.dataPlane.(captiveDataPlane); ok {
		use(plane)
	}
}

func (s *Service) setCaptiveDNS(open bool) {
	if resolver, ok := s.dns.(captiveDNS); ok {
		resolver.SetCaptiveWindow(open)
	}
}

// findPortals finds the portal of a sign-in page on a port of its own (the
// window opens 80 and 443 to everyone), by the network's resolver for a
// name: one IPv4 and one IPv6 address the helper may let through.
func findPortals(ctx context.Context, url string) [2]netip.AddrPort {
	var portals [2]netip.AddrPort
	host, port, ok := captive.PortalEndpoint(url)
	if !ok {
		return portals
	}
	addresses := []netip.Addr{}
	if address, err := netip.ParseAddr(host); err == nil {
		addresses = append(addresses, address)
	} else {
		lookup, cancel := context.WithTimeout(ctx, portalLookupTimeout)
		defer cancel()
		addresses, _ = underlay.Resolver().LookupNetIP(lookup, "ip", host)
	}
	for _, address := range addresses {
		portal := netip.AddrPortFrom(address.Unmap(), port)
		slot := 0
		if portal.Addr().Is6() {
			slot = 1
		}
		if !portals[slot].IsValid() && netadmin.CaptivePortalAllowed(portal) {
			portals[slot] = portal
		}
	}
	return portals
}

// writeFileAtomically replaces path with data, readable by its owner only.
func writeFileAtomically(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
