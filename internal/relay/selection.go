package relay

import (
	"errors"
	"slices"
	"time"
)

const (
	maxSelectionRegions       = 1_024
	maxSelectionLatency       = 10 * time.Second
	minimumRelayImprovement   = 10 * time.Millisecond
	relayImprovementPercent   = 20
	missesBeforeRelayFailover = 2
	selectionLatencyRetention = 5*time.Minute + 10*time.Second
)

var errInvalidSelection = errors.New("relay: invalid home selection input")

// RegionLatency is one recent, authenticated reachability sample for a
// control-authorized relay region.
type RegionLatency struct {
	RegionID int
	Latency  time.Duration
}

// HomeSelection is the currently selected rendezvous region.
type HomeSelection struct {
	RegionID int
	Changed  bool
}

type latencyState struct {
	latency  time.Duration
	observed time.Time
}

// HomeSelector keeps relay choice stable while reacting to materially better
// or repeatedly unreachable regions. It is owned by one control session and
// is intentionally not safe for concurrent use.
type HomeSelector struct {
	usable            map[int]struct{}
	latencies         map[int]latencyState
	current           int
	lastControl       int
	hasControl        bool
	consecutiveMisses int
	lastObservation   time.Time
}

// NewHomeSelector creates an empty control-session selector.
func NewHomeSelector() *HomeSelector {
	return &HomeSelector{
		usable:    make(map[int]struct{}),
		latencies: make(map[int]latencyState),
	}
}

// Reconcile applies the latest signed topology. A newly changed usable
// control preference is authoritative; otherwise an existing usable choice is
// retained. The lowest usable region is the deterministic cold-start fallback.
func (s *HomeSelector) Reconcile(
	controlPreferred int,
	usableRegions []int,
) (HomeSelection, error) {
	if s == nil {
		return HomeSelection{}, errors.New("relay: home selector is not initialized")
	}
	usable, ordered, err := normalizeUsableRegions(usableRegions)
	if err != nil {
		return HomeSelection{}, err
	}
	previous := s.current
	s.usable = usable
	for regionID := range s.latencies {
		if _, exists := usable[regionID]; !exists {
			delete(s.latencies, regionID)
		}
	}

	controlChanged := !s.hasControl || controlPreferred != s.lastControl
	s.hasControl = true
	s.lastControl = controlPreferred
	if controlChanged && controlPreferred > 0 {
		if _, exists := usable[controlPreferred]; exists {
			s.current = controlPreferred
			s.consecutiveMisses = 0
		}
	}
	if _, exists := usable[s.current]; !exists {
		s.current = 0
		if len(ordered) != 0 {
			s.current = ordered[0]
		}
		s.consecutiveMisses = 0
	}

	return HomeSelection{
		RegionID: s.current,
		Changed:  s.current != previous,
	}, nil
}

// Observe incorporates one bounded probe batch. Latency uses a 75/25 moving
// average. A live home changes only for both a 10 ms and 20 percent gain; two
// partial rounds must miss it before reachability failover.
func (s *HomeSelector) Observe(
	now time.Time,
	samples []RegionLatency,
) (HomeSelection, error) {
	if s == nil {
		return HomeSelection{}, errors.New("relay: home selector is not initialized")
	}
	if now.IsZero() || (!s.lastObservation.IsZero() && now.Before(s.lastObservation)) ||
		len(samples) > maxSelectionRegions {
		return HomeSelection{}, errInvalidSelection
	}
	seen := make(map[int]struct{}, len(samples))
	for _, sample := range samples {
		if sample.RegionID <= 0 || sample.Latency <= 0 ||
			sample.Latency > maxSelectionLatency {
			return HomeSelection{}, errInvalidSelection
		}
		if _, usable := s.usable[sample.RegionID]; !usable {
			return HomeSelection{}, errInvalidSelection
		}
		if _, exists := seen[sample.RegionID]; exists {
			return HomeSelection{}, errInvalidSelection
		}
		seen[sample.RegionID] = struct{}{}
	}
	s.lastObservation = now
	for regionID, state := range s.latencies {
		if !state.observed.Add(selectionLatencyRetention).After(now) {
			delete(s.latencies, regionID)
		}
	}
	previous := s.current
	currentObserved := false
	bestObserved := 0
	for _, sample := range samples {
		state, exists := s.latencies[sample.RegionID]
		if exists {
			state.latency = (state.latency*3 + sample.Latency) / 4
		} else {
			state.latency = sample.Latency
		}
		state.observed = now
		s.latencies[sample.RegionID] = state
		if sample.RegionID == s.current {
			currentObserved = true
		}
		if bestObserved == 0 || s.better(sample.RegionID, bestObserved) {
			bestObserved = sample.RegionID
		}
	}

	if s.current == 0 || len(samples) == 0 {
		return HomeSelection{RegionID: s.current}, nil
	}
	if !currentObserved {
		s.consecutiveMisses++
		if s.consecutiveMisses >= missesBeforeRelayFailover && bestObserved != 0 {
			s.current = bestObserved
			s.consecutiveMisses = 0
		}
	} else {
		s.consecutiveMisses = 0
		if bestObserved != 0 && bestObserved != s.current &&
			s.materiallyBetter(bestObserved, s.current) {
			s.current = bestObserved
		}
	}

	return HomeSelection{
		RegionID: s.current,
		Changed:  s.current != previous,
	}, nil
}

// Reset clears all session-owned selection evidence.
func (s *HomeSelector) Reset() HomeSelection {
	if s == nil {
		return HomeSelection{}
	}
	previous := s.current
	clear(s.usable)
	clear(s.latencies)
	s.current = 0
	s.lastControl = 0
	s.hasControl = false
	s.consecutiveMisses = 0
	s.lastObservation = time.Time{}

	return HomeSelection{Changed: previous != 0}
}

func (s *HomeSelector) better(left, right int) bool {
	leftLatency := s.latencies[left].latency
	rightLatency := s.latencies[right].latency
	if leftLatency != rightLatency {
		return leftLatency < rightLatency
	}

	return left < right
}

func (s *HomeSelector) materiallyBetter(candidate, current int) bool {
	candidateLatency := s.latencies[candidate].latency
	currentLatency := s.latencies[current].latency
	if candidateLatency >= currentLatency ||
		currentLatency-candidateLatency < minimumRelayImprovement {
		return false
	}

	return candidateLatency*100 <= currentLatency*(100-relayImprovementPercent)
}

func normalizeUsableRegions(regions []int) (map[int]struct{}, []int, error) {
	if len(regions) > maxSelectionRegions {
		return nil, nil, errInvalidSelection
	}
	ordered := slices.Clone(regions)
	slices.Sort(ordered)
	usable := make(map[int]struct{}, len(ordered))
	for index, regionID := range ordered {
		if regionID <= 0 || (index > 0 && ordered[index-1] == regionID) {
			return nil, nil, errInvalidSelection
		}
		usable[regionID] = struct{}{}
	}

	return usable, ordered, nil
}
