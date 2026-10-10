package pathdiscovery

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	defaultCandidateRetention = 5*time.Minute + 10*time.Second
	maxTrackedPerAddress      = 6
	maxTrackedCandidates      = 64
)

type trackedCandidate struct {
	candidate Candidate
	expiresAt time.Time
}

// TrackingResult is one publication snapshot plus the exact next expiry.
type TrackingResult struct {
	Candidates Set
	Changed    bool
	ExpiresAt  time.Time
}

// Tracker retains recently observed server-reflexive candidates across
// transient discovery failures. Host, configured and port-mapped candidates
// always mirror the latest observation: the port mapper owns a mapping's
// lifetime, so a removed mapping must stop being published at once.
type Tracker struct {
	mu        sync.Mutex
	retention time.Duration
	stable    []Candidate
	tracked   map[Candidate]time.Time
	last      Set
}

// NewTracker creates a bounded candidate-history tracker.
func NewTracker() *Tracker {
	return newTracker(defaultCandidateRetention)
}

func newTracker(retention time.Duration) *Tracker {
	if retention <= 0 {
		panic("pathdiscovery: candidate retention must be positive")
	}

	return &Tracker{
		retention: retention,
		tracked:   make(map[Candidate]time.Time),
	}
}

// Update records one complete current observation and returns the candidates
// that should be published now.
func (t *Tracker) Update(now time.Time, current Set) (TrackingResult, error) {
	if t == nil {
		return TrackingResult{}, errors.New("pathdiscovery: tracker is not initialized")
	}
	if now.IsZero() {
		return TrackingResult{}, errors.New("pathdiscovery: tracker time is invalid")
	}
	validated, err := NewSet(current.Candidates())
	if err != nil || !validated.Equal(current) {
		return TrackingResult{}, errors.New("pathdiscovery: tracker candidates are invalid")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeExpiredLocked(now)
	t.stable = t.stable[:0]
	expiresAt := now.Add(t.retention)
	for _, candidate := range current.candidates {
		switch candidate.source {
		case SourceHost, SourceConfigured, SourcePortMapping:
			t.stable = append(t.stable, candidate)
		case SourceServerReflexive:
			t.tracked[candidate] = expiresAt
		}
	}
	t.pruneLocked()

	return t.resultLocked(now, current.candidates), nil
}

// Expire removes candidates whose deadline has arrived without treating old
// observations as fresh. Callers can schedule this at TrackingResult.ExpiresAt.
func (t *Tracker) Expire(now time.Time) (TrackingResult, error) {
	if t == nil {
		return TrackingResult{}, errors.New("pathdiscovery: tracker is not initialized")
	}
	if now.IsZero() {
		return TrackingResult{}, errors.New("pathdiscovery: tracker time is invalid")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeExpiredLocked(now)

	return t.resultLocked(now, t.stable), nil
}

// Reset drops all retained history and publishes only the supplied stable
// candidates. It is used when the shared socket or active peer set closes.
func (t *Tracker) Reset(now time.Time, current Set) (TrackingResult, error) {
	if t == nil {
		return TrackingResult{}, errors.New("pathdiscovery: tracker is not initialized")
	}
	if now.IsZero() {
		return TrackingResult{}, errors.New("pathdiscovery: tracker time is invalid")
	}
	validated, err := NewSet(current.Candidates())
	if err != nil || !validated.Equal(current) {
		return TrackingResult{}, errors.New("pathdiscovery: tracker candidates are invalid")
	}
	stable := make([]Candidate, 0, current.Len())
	for _, candidate := range current.candidates {
		if candidate.source != SourceHost && candidate.source != SourceConfigured {
			return TrackingResult{}, errors.New(
				"pathdiscovery: tracker reset candidates must be stable",
			)
		}
		stable = append(stable, candidate)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.tracked)
	t.stable = append(t.stable[:0], stable...)

	return t.resultLocked(now, stable), nil
}

func (t *Tracker) resultLocked(now time.Time, preferred []Candidate) TrackingResult {
	selected := make([]Candidate, 0, MaxCandidates)
	seen := make(map[netip.AddrPort]struct{}, MaxCandidates)
	appendCandidate := func(candidate Candidate) {
		if len(selected) == MaxCandidates {
			return
		}
		if _, exists := seen[candidate.endpoint]; exists {
			return
		}
		seen[candidate.endpoint] = struct{}{}
		selected = append(selected, candidate)
	}
	for _, candidate := range preferred {
		appendCandidate(candidate)
	}

	tracked := make([]trackedCandidate, 0, len(t.tracked))
	nextExpiry := time.Time{}
	for candidate, expiresAt := range t.tracked {
		if !expiresAt.After(now) {
			continue
		}
		tracked = append(tracked, trackedCandidate{
			candidate: candidate,
			expiresAt: expiresAt,
		})
		if nextExpiry.IsZero() || expiresAt.Before(nextExpiry) {
			nextExpiry = expiresAt
		}
	}
	slices.SortFunc(tracked, func(left, right trackedCandidate) int {
		if !left.expiresAt.Equal(right.expiresAt) {
			if left.expiresAt.After(right.expiresAt) {
				return -1
			}

			return 1
		}

		return compareCandidates(left.candidate, right.candidate)
	})
	for _, item := range tracked {
		appendCandidate(item.candidate)
	}
	slices.SortFunc(selected, compareCandidates)
	candidates := Set{candidates: selected}
	changed := !candidates.Equal(t.last)
	t.last = Set{candidates: slices.Clone(selected)}

	return TrackingResult{
		Candidates: candidates,
		Changed:    changed,
		ExpiresAt:  nextExpiry,
	}
}

func (t *Tracker) removeExpiredLocked(now time.Time) {
	for candidate, expiresAt := range t.tracked {
		if !expiresAt.After(now) {
			delete(t.tracked, candidate)
		}
	}
}

func (t *Tracker) pruneLocked() {
	tracked := make([]trackedCandidate, 0, len(t.tracked))
	for candidate, expiresAt := range t.tracked {
		tracked = append(tracked, trackedCandidate{
			candidate: candidate,
			expiresAt: expiresAt,
		})
	}
	slices.SortFunc(tracked, func(left, right trackedCandidate) int {
		if !left.expiresAt.Equal(right.expiresAt) {
			if left.expiresAt.Before(right.expiresAt) {
				return -1
			}

			return 1
		}

		return compareCandidates(left.candidate, right.candidate)
	})
	perAddress := make(map[netip.Addr]int)
	for _, item := range tracked {
		perAddress[item.candidate.endpoint.Addr()]++
	}
	for _, item := range tracked {
		address := item.candidate.endpoint.Addr()
		if perAddress[address] > maxTrackedPerAddress {
			delete(t.tracked, item.candidate)
			perAddress[address]--
		}
	}
	if len(t.tracked) <= maxTrackedCandidates {
		return
	}
	removeCount := len(t.tracked) - maxTrackedCandidates
	for _, item := range tracked {
		if removeCount == 0 {
			return
		}
		if _, exists := t.tracked[item.candidate]; !exists {
			continue
		}
		delete(t.tracked, item.candidate)
		removeCount--
	}
}
