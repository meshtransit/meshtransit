package pathdiscovery

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
)

const (
	maxPathPeers             = 256
	maxPathCandidatesPerPeer = 128
	defaultPathTrust         = 6500 * time.Millisecond
	pathPreferencePercent    = 5
	pathSwitchPercent        = 10
	minimumPathDifference    = 2 * time.Millisecond
)

var (
	// ErrPathSelectionInactive means no validated generation is active.
	ErrPathSelectionInactive = errors.New("pathdiscovery: path selector is inactive")
	// ErrInvalidPathSnapshot means candidate authority is malformed or exceeds
	// the data-plane limits.
	ErrInvalidPathSnapshot = errors.New("pathdiscovery: invalid path snapshot")
	// ErrInvalidPathObservation means an observation is malformed, stale, or
	// not authorized by the active snapshot.
	ErrInvalidPathObservation = errors.New("pathdiscovery: invalid path observation")
	// ErrPathTimeRegression means selection time moved backwards.
	ErrPathTimeRegression = errors.New("pathdiscovery: path time moved backwards")
)

// PathSelection is the current authenticated direct path for one peer. The
// zero value means that no fresh path has been proven.
type PathSelection struct {
	PeerID                uint64
	Generation            ProbeGeneration
	RemoteEndpoint        netip.AddrPort
	ObservedLocalEndpoint netip.AddrPort
	RoundTrip             time.Duration
	ConfirmedAt           time.Time
	ExpiresAt             time.Time
}

// IsValid reports whether the selection is a complete authenticated path.
func (s PathSelection) IsValid() bool {
	return s.PeerID != 0 && s.Generation.IsValid() &&
		validateEndpoint(s.RemoteEndpoint) == nil &&
		validateEndpoint(s.ObservedLocalEndpoint) == nil &&
		s.RoundTrip >= 0 && s.RoundTrip < defaultProbeLifetime &&
		!s.ConfirmedAt.IsZero() && s.ExpiresAt.After(s.ConfirmedAt)
}

// PathChange reports a selected endpoint transition. Metadata-only refreshes
// of the same endpoint do not produce a change.
type PathChange struct {
	PeerID   uint64
	Previous PathSelection
	Current  PathSelection
}

// PathSelectionResult contains endpoint transitions and the exact earliest
// time at which any retained proof must be expired.
type PathSelectionResult struct {
	Changes   []PathChange
	ExpiresAt time.Time
}

type pathCandidateState struct {
	observedLocal netip.AddrPort
	roundTrip     time.Duration
	confirmedAt   time.Time
	expiresAt     time.Time
}

type peerPathState struct {
	nodeKey      string
	discoveryKey string
	candidates   map[netip.AddrPort]pathCandidateState
	selected     netip.AddrPort
}

// PathSelector owns bounded authenticated path evidence independently from
// the compatibility protocol and tunnel engine. All methods are concurrency
// safe.
type PathSelector struct {
	mu         sync.Mutex
	trust      time.Duration
	active     ProbeGeneration
	latest     ProbeGeneration
	advancedAt time.Time
	peers      map[uint64]*peerPathState
}

// NewPathSelector creates an inactive selector with a short direct-path trust
// window. Callers must schedule Expire at each returned ExpiresAt value.
func NewPathSelector() *PathSelector {
	return newPathSelector(defaultPathTrust)
}

func newPathSelector(trust time.Duration) *PathSelector {
	if trust <= 0 {
		panic("pathdiscovery: path trust duration must be positive")
	}

	return &PathSelector{trust: trust}
}

// Activate atomically replaces candidate authority for a generation. An exact
// repeated generation preserves evidence only when its peer topology is also
// identical. Every other valid generation starts without trusted paths.
func (s *PathSelector) Activate(
	snapshot networkmap.Snapshot,
	generation ProbeGeneration,
) (PathSelectionResult, error) {
	if s == nil {
		return PathSelectionResult{}, ErrPathSelectionInactive
	}
	if !generation.IsValid() || snapshot.Revision != generation.MapRevision {
		return PathSelectionResult{}, ErrInvalidPathSnapshot
	}
	next, err := buildPeerPathState(snapshot)
	if err != nil {
		return PathSelectionResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.canActivateLocked(generation); err != nil {
		return PathSelectionResult{}, err
	}
	if generation == s.active {
		if !equalPeerPathAuthority(s.peers, next) {
			return PathSelectionResult{}, ErrInvalidPathSnapshot
		}
		current := s.selectionsLocked()

		return s.resultLocked(current), nil
	}
	previous := s.selectionsLocked()
	s.active = generation
	s.latest = generation
	s.advancedAt = time.Time{}
	s.peers = next

	return s.resultLocked(previous), nil
}

// Deactivate removes all evidence and selected paths while retaining the
// latest generation as a rollback-prevention watermark.
func (s *PathSelector) Deactivate() PathSelectionResult {
	if s == nil {
		return PathSelectionResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.selectionsLocked()
	s.active = ProbeGeneration{}
	s.advancedAt = time.Time{}
	s.peers = nil

	return s.resultLocked(previous)
}

// Observe records one already-authenticated proof, expires older evidence,
// and deterministically re-evaluates affected selections.
func (s *PathSelector) Observe(
	observation PathObservation,
) (PathSelectionResult, error) {
	if s == nil {
		return PathSelectionResult{}, ErrPathSelectionInactive
	}
	if !validPathObservation(observation) {
		return PathSelectionResult{}, ErrInvalidPathObservation
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active.IsValid() {
		return PathSelectionResult{}, ErrPathSelectionInactive
	}
	if observation.Generation != s.active {
		return PathSelectionResult{}, ErrInvalidPathObservation
	}
	if !s.advancedAt.IsZero() && observation.ObservedAt.Before(s.advancedAt) {
		return PathSelectionResult{}, ErrPathTimeRegression
	}
	peer, exists := s.peers[observation.PeerID]
	if !exists {
		return PathSelectionResult{}, ErrInvalidPathObservation
	}
	state, authorized := peer.candidates[observation.RemoteEndpoint]
	if !authorized || (!state.confirmedAt.IsZero() &&
		observation.ObservedAt.Before(state.confirmedAt)) {
		return PathSelectionResult{}, ErrInvalidPathObservation
	}

	previous := s.selectionsLocked()
	s.expireLocked(observation.ObservedAt)
	state = peer.candidates[observation.RemoteEndpoint]
	if state.confirmedAt.IsZero() {
		state.roundTrip = observation.RoundTrip
	} else {
		state.roundTrip = smoothPathRoundTrip(
			state.roundTrip,
			observation.RoundTrip,
		)
	}
	state.observedLocal = observation.ObservedLocalEndpoint
	state.confirmedAt = observation.ObservedAt
	state.expiresAt = observation.ObservedAt.Add(s.trust)
	peer.candidates[observation.RemoteEndpoint] = state
	s.advancedAt = observation.ObservedAt
	s.selectPeerLocked(peer, observation.ObservedAt)

	return s.resultLocked(previous), nil
}

// Expire removes proof whose deadline has arrived and falls back to the best
// remaining authenticated candidate. Expiry at the exact deadline is final.
func (s *PathSelector) Expire(now time.Time) (PathSelectionResult, error) {
	if s == nil {
		return PathSelectionResult{}, ErrPathSelectionInactive
	}
	if now.IsZero() {
		return PathSelectionResult{}, ErrInvalidPathObservation
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active.IsValid() {
		return PathSelectionResult{}, ErrPathSelectionInactive
	}
	if !s.advancedAt.IsZero() && now.Before(s.advancedAt) {
		return PathSelectionResult{}, ErrPathTimeRegression
	}
	previous := s.selectionsLocked()
	s.expireLocked(now)
	s.advancedAt = now

	return s.resultLocked(previous), nil
}

// Selections returns a deterministic copy of current selections. Callers must
// first process the latest ExpiresAt deadline; this read does not advance time.
func (s *PathSelector) Selections() []PathSelection {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	selected := s.selectionsLocked()
	peerIDs := make([]uint64, 0, len(selected))
	for peerID := range selected {
		peerIDs = append(peerIDs, peerID)
	}
	slices.Sort(peerIDs)
	result := make([]PathSelection, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		result = append(result, selected[peerID])
	}

	return result
}

func (s *PathSelector) canActivateLocked(generation ProbeGeneration) error {
	if !s.latest.IsValid() {
		return nil
	}
	if generation.Scope != s.latest.Scope ||
		generation.MapRevision < s.latest.MapRevision ||
		generation.Socket.Generation < s.latest.Socket.Generation ||
		(generation.Socket.Generation == s.latest.Socket.Generation &&
			generation.Socket.Port != s.latest.Socket.Port) {
		return ErrInvalidPathSnapshot
	}

	return nil
}

func (s *PathSelector) expireLocked(now time.Time) {
	for _, peer := range s.peers {
		for endpoint, candidate := range peer.candidates {
			if candidate.confirmedAt.IsZero() || candidate.expiresAt.After(now) {
				continue
			}
			peer.candidates[endpoint] = pathCandidateState{}
		}
		s.selectPeerLocked(peer, now)
	}
}

func (s *PathSelector) selectPeerLocked(peer *peerPathState, now time.Time) {
	if peer == nil {
		return
	}
	best, bestState, found := bestPathCandidate(peer.candidates, now)
	if !found {
		peer.selected = netip.AddrPort{}

		return
	}
	currentState, currentExists := peer.candidates[peer.selected]
	if !currentExists || currentState.confirmedAt.IsZero() ||
		!currentState.expiresAt.After(now) {
		peer.selected = best

		return
	}
	if best == peer.selected || !shouldSwitchPath(
		best,
		bestState,
		peer.selected,
		currentState,
	) {
		return
	}
	peer.selected = best
}

func (s *PathSelector) selectionsLocked() map[uint64]PathSelection {
	selected := make(map[uint64]PathSelection)
	for peerID, peer := range s.peers {
		if peer == nil || !peer.selected.IsValid() {
			continue
		}
		candidate, exists := peer.candidates[peer.selected]
		if !exists || candidate.confirmedAt.IsZero() {
			continue
		}
		selected[peerID] = PathSelection{
			PeerID:                peerID,
			Generation:            s.active,
			RemoteEndpoint:        peer.selected,
			ObservedLocalEndpoint: candidate.observedLocal,
			RoundTrip:             candidate.roundTrip,
			ConfirmedAt:           candidate.confirmedAt,
			ExpiresAt:             candidate.expiresAt,
		}
	}

	return selected
}

func (s *PathSelector) resultLocked(
	previous map[uint64]PathSelection,
) PathSelectionResult {
	current := s.selectionsLocked()
	changes := pathChanges(previous, current)
	nextExpiry := time.Time{}
	for _, peer := range s.peers {
		for _, candidate := range peer.candidates {
			if candidate.confirmedAt.IsZero() ||
				(!s.advancedAt.IsZero() && !candidate.expiresAt.After(s.advancedAt)) {
				continue
			}
			if nextExpiry.IsZero() || candidate.expiresAt.Before(nextExpiry) {
				nextExpiry = candidate.expiresAt
			}
		}
	}

	return PathSelectionResult{
		Changes:   changes,
		ExpiresAt: nextExpiry,
	}
}

func buildPeerPathState(
	snapshot networkmap.Snapshot,
) (map[uint64]*peerPathState, error) {
	if snapshot.Self.ID == 0 || len(snapshot.Peers) > maxPathPeers {
		return nil, ErrInvalidPathSnapshot
	}
	seenPeerIDs := map[uint64]struct{}{snapshot.Self.ID: {}}
	peers := make(map[uint64]*peerPathState, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		if peer.ID == 0 || peer.Expired || !peer.MachineAuthorized ||
			len(peer.Endpoints) > maxPathCandidatesPerPeer {
			return nil, ErrInvalidPathSnapshot
		}
		if _, exists := seenPeerIDs[peer.ID]; exists {
			return nil, ErrInvalidPathSnapshot
		}
		seenPeerIDs[peer.ID] = struct{}{}
		if peer.DiscoveryKey == "" {
			continue
		}
		candidates := make(
			map[netip.AddrPort]pathCandidateState,
			len(peer.Endpoints),
		)
		for _, endpoint := range peer.Endpoints {
			if validateEndpoint(endpoint) != nil {
				return nil, ErrInvalidPathSnapshot
			}
			if _, exists := candidates[endpoint]; exists {
				return nil, ErrInvalidPathSnapshot
			}
			candidates[endpoint] = pathCandidateState{}
		}
		peers[peer.ID] = &peerPathState{
			nodeKey:      peer.PublicKey,
			discoveryKey: peer.DiscoveryKey,
			candidates:   candidates,
		}
	}

	return peers, nil
}

func equalPeerPathAuthority(
	left map[uint64]*peerPathState,
	right map[uint64]*peerPathState,
) bool {
	if len(left) != len(right) {
		return false
	}
	for peerID, leftPeer := range left {
		rightPeer, exists := right[peerID]
		if !exists || leftPeer == nil || rightPeer == nil ||
			leftPeer.nodeKey != rightPeer.nodeKey ||
			leftPeer.discoveryKey != rightPeer.discoveryKey ||
			len(leftPeer.candidates) != len(rightPeer.candidates) {
			return false
		}
		for endpoint := range leftPeer.candidates {
			if _, exists := rightPeer.candidates[endpoint]; !exists {
				return false
			}
		}
	}

	return true
}

func validPathObservation(observation PathObservation) bool {
	return observation.PeerID != 0 && observation.Generation.IsValid() &&
		validateEndpoint(observation.RemoteEndpoint) == nil &&
		validateEndpoint(observation.ObservedLocalEndpoint) == nil &&
		observation.RoundTrip >= 0 &&
		observation.RoundTrip < defaultProbeLifetime &&
		!observation.ObservedAt.IsZero()
}

func smoothPathRoundTrip(previous, current time.Duration) time.Duration {
	return (previous*3 + current) / 4
}

func bestPathCandidate(
	candidates map[netip.AddrPort]pathCandidateState,
	now time.Time,
) (netip.AddrPort, pathCandidateState, bool) {
	minimum := time.Duration(1<<63 - 1)
	for _, candidate := range candidates {
		if candidate.confirmedAt.IsZero() || !candidate.expiresAt.After(now) {
			continue
		}
		minimum = min(minimum, candidate.roundTrip)
	}
	if minimum == time.Duration(1<<63-1) {
		return netip.AddrPort{}, pathCandidateState{}, false
	}
	tolerance := max(
		minimumPathDifference,
		minimum*time.Duration(pathPreferencePercent)/100,
	)
	var best netip.AddrPort
	var bestState pathCandidateState
	for endpoint, candidate := range candidates {
		if candidate.confirmedAt.IsZero() || !candidate.expiresAt.After(now) ||
			candidate.roundTrip > minimum+tolerance {
			continue
		}
		if !best.IsValid() || preferredPath(endpoint, best) {
			best = endpoint
			bestState = candidate
		}
	}

	return best, bestState, true
}

func shouldSwitchPath(
	candidateEndpoint netip.AddrPort,
	candidate pathCandidateState,
	currentEndpoint netip.AddrPort,
	current pathCandidateState,
) bool {
	if candidate.roundTrip < current.roundTrip {
		improvement := current.roundTrip - candidate.roundTrip
		required := max(
			minimumPathDifference,
			current.roundTrip*time.Duration(pathSwitchPercent)/100,
		)
		if improvement >= required {
			return true
		}
	}
	difference := candidate.roundTrip - current.roundTrip
	if difference < 0 {
		difference = -difference
	}
	tolerance := max(
		minimumPathDifference,
		min(candidate.roundTrip, current.roundTrip)*
			time.Duration(pathPreferencePercent)/100,
	)

	return difference <= tolerance &&
		preferredPath(candidateEndpoint, currentEndpoint)
}

func preferredPath(left, right netip.AddrPort) bool {
	leftPrivate := left.Addr().IsPrivate()
	rightPrivate := right.Addr().IsPrivate()
	if leftPrivate != rightPrivate {
		return leftPrivate
	}
	leftIPv6 := left.Addr().Is6()
	rightIPv6 := right.Addr().Is6()
	if leftIPv6 != rightIPv6 {
		return leftIPv6
	}

	return left.Compare(right) < 0
}

func pathChanges(
	previous map[uint64]PathSelection,
	current map[uint64]PathSelection,
) []PathChange {
	peerIDs := make([]uint64, 0, len(previous)+len(current))
	seen := make(map[uint64]struct{}, len(previous)+len(current))
	for peerID := range previous {
		seen[peerID] = struct{}{}
		peerIDs = append(peerIDs, peerID)
	}
	for peerID := range current {
		if _, exists := seen[peerID]; exists {
			continue
		}
		peerIDs = append(peerIDs, peerID)
	}
	slices.Sort(peerIDs)
	changes := make([]PathChange, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		before := previous[peerID]
		after := current[peerID]
		if before.RemoteEndpoint == after.RemoteEndpoint {
			continue
		}
		changes = append(changes, PathChange{
			PeerID:   peerID,
			Previous: before,
			Current:  after,
		})
	}

	return changes
}
