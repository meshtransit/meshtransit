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
// suspected, portal), the sign-in page the network named, and since when.
type CaptiveView struct {
	State string
	URL   string
	Since time.Time
}

// captiveRelays are the relay addresses to probe and one relay's name.
type captiveRelays struct {
	Addresses []netip.Addr `json:"addresses"`
	Name      string       `json:"name,omitempty"`
}

// captiveTracker holds the relays and the detector's last state.
type captiveTracker struct {
	mu     sync.Mutex
	dir    string
	relays captiveRelays
	state  captive.State
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
	return t.state.Verdict == captive.VerdictSuspected || t.state.Verdict == captive.VerdictPortal
}

func (t *captiveTracker) view() CaptiveView {
	if t == nil {
		return CaptiveView{State: string(captive.VerdictNone)}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return CaptiveView{State: string(t.state.Verdict), URL: t.state.URL, Since: t.state.Since}
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
