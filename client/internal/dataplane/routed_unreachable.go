package dataplane

import (
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/packetmeta"
)

const (
	// unreachablePerSecond bounds the answers for one Site (mtcp-v1 §7.6),
	// so a scan of an unserved Site cannot turn into an ICMP flood.
	unreachablePerSecond = 10
	// maximumUnreachableSites bounds the limiter's state: a map holds at
	// most 1,024 Sites.
	maximumUnreachableSites = 1024
)

// unreachableAnswerer answers packets to a Site that cannot be reached with
// an ICMP host unreachable written back into the TUN, at most
// unreachablePerSecond per Site.
type unreachableAnswerer struct {
	clock   func() time.Time
	mu      sync.Mutex
	windows map[string]unreachableWindow
	// answered and limited count answers written and packets over the limit.
	answered, limited atomic.Uint64
}

type unreachableWindow struct {
	start time.Time
	count int
}

func newUnreachableAnswerer(clock func() time.Time) *unreachableAnswerer {
	return &unreachableAnswerer{clock: clock, windows: map[string]unreachableWindow{}}
}

// allow reports whether one more answer for site fits its limit.
func (a *unreachableAnswerer) allow(site string) bool {
	now := a.clock()
	a.mu.Lock()
	defer a.mu.Unlock()
	window, known := a.windows[site]
	if !known && len(a.windows) >= maximumUnreachableSites {
		// Only Sites answered within the last second are kept; a full
		// table never resets the others' limits.
		maps.DeleteFunc(a.windows, func(_ string, other unreachableWindow) bool { return expired(other, now) })
		if len(a.windows) >= maximumUnreachableSites {
			a.limited.Add(1)
			return false
		}
	}
	if !known || expired(window, now) {
		window = unreachableWindow{start: now}
	}
	if window.count >= unreachablePerSecond {
		a.limited.Add(1)
		return false
	}
	window.count++
	a.windows[site] = window
	return true
}

func expired(window unreachableWindow, now time.Time) bool {
	return now.Sub(window.start) >= time.Second || now.Before(window.start)
}

// answer writes the unreachable answer to a packet the filter denied when
// it was for a Site that cannot be reached; other packets stay dropped
// silently.
func (d *observedTUN) answerUnreachable(packet []byte, offset int) {
	if d.filter == nil || d.filter.unreachable == nil {
		return
	}
	site, unreachable := d.filter.routedUnreachable(packet)
	if !unreachable {
		return
	}
	// Only a packet that may be answered spends the Site's budget.
	answer, err := packetmeta.Unreachable(packet)
	if err != nil || !d.filter.unreachable.allow(site) {
		return
	}
	buffer := make([]byte, offset+len(answer))
	copy(buffer[offset:], answer)
	if _, err := d.Device.Write([][]byte{buffer}, offset); err == nil {
		d.filter.unreachable.answered.Add(1)
	}
}
