package primaryelection

import (
	"cmp"
	"context"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
)

// Timing of a spread group's serving set (exit node design §16.3).
const (
	// OverloadedAfter is how long a member must report overload before it
	// leaves the serving set.
	OverloadedAfter = time.Minute
	// RecoveredAfter is how long a member that left overloaded must report
	// no overload before it joins again.
	RecoveredAfter = 5 * time.Minute
	// ServingChangeSpacing is the least time between two changes of one
	// group's serving set.
	ServingChangeSpacing = 30 * time.Second
)

// Reasons a serving set change records.
const (
	ServingElected    = "elected"
	ServingJoined     = "joined"
	ServingFailover   = "failover"
	ServingOverloaded = "overloaded"
	ServingRecovered  = "recovered"
	ServingNone       = "none"
)

// ServingCandidate is one member of a spread group as the serving election
// sees it.
type ServingCandidate struct {
	Device   node.ID
	Priority int
	Status   Status
	// UsableFor is how long it has been usable without a break.
	UsableFor time.Duration
	// Overloaded reports a member that has reported overload for
	// OverloadedAfter; Reporting one that reports it now.
	Overloaded, Reporting bool
	// HeldBack reports a member the last change took out overloaded, less
	// than RecoveredAfter ago: it does not join yet. Recovered reports one
	// it took out longer ago, so its joining is a recovery.
	HeldBack, Recovered bool
}

// ServingDecision is a serving set to record, made on ExpectedGeneration.
type ServingDecision struct {
	Group              string
	ExpectedGeneration int64
	// Devices in increasing order; empty when no member can serve.
	Devices []node.ID
	Reason  string
}

// ServingRecorder records a serving set; false when it was made on an older
// state.
type ServingRecorder interface {
	RecordServing(ctx context.Context, installation deployment.ID, decision ServingDecision) (bool, error)
}

// ElectServing returns a spread group's serving set and why it changed;
// current is the set now and changed reports a set other than current.
// Members that can serve now join once they have been usable for HoldDown
// and report no overload, unless held back after leaving overloaded;
// members of the current set stay while usable. Only the best priority tier
// serves; its overloaded members leave only while at least half the tier is
// not overloaded. When no member can serve, the members of the current set
// that failed or recover stay: all failing alike more likely means a probe
// is wrong, and a set kept costs no consumer anything.
func ElectServing(current []node.ID, candidates []ServingCandidate) (serving []node.ID, reason string, changed bool) {
	var eligible []ServingCandidate
	for _, candidate := range candidates {
		member := slices.Contains(current, candidate.Device)
		if candidate.Status == StatusUsable && (member || (candidate.UsableFor >= HoldDown && !candidate.Reporting &&
			!candidate.HeldBack)) {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) > 0 {
		tier := eligible[0].Priority
		for _, candidate := range eligible {
			tier = min(tier, candidate.Priority)
		}
		var inTier, healthy []node.ID
		for _, candidate := range eligible {
			if candidate.Priority != tier {
				continue
			}
			inTier = append(inTier, candidate.Device)
			if !candidate.Overloaded {
				healthy = append(healthy, candidate.Device)
			}
		}
		serving = inTier
		if len(healthy) > 0 && 2*len(healthy) >= len(inTier) {
			serving = healthy
		}
	} else {
		for _, candidate := range candidates {
			if slices.Contains(current, candidate.Device) &&
				(candidate.Status == StatusFailed || candidate.Status == StatusHoldDown) {
				serving = append(serving, candidate.Device)
			}
		}
	}
	slices.SortFunc(serving, compareDevices)
	sorted := slices.Clone(current)
	slices.SortFunc(sorted, compareDevices)
	if slices.Equal(serving, sorted) {
		return serving, "", false
	}
	return serving, servingReason(current, serving, candidates), true
}

func servingReason(current, serving []node.ID, candidates []ServingCandidate) string {
	switch {
	case len(serving) == 0:
		return ServingNone
	case len(current) == 0:
		return ServingElected
	}
	byDevice := make(map[node.ID]ServingCandidate, len(candidates))
	for _, candidate := range candidates {
		byDevice[candidate.Device] = candidate
	}
	removed, overloaded := false, false
	for _, device := range current {
		if !slices.Contains(serving, device) {
			removed = true
			overloaded = overloaded || byDevice[device].Overloaded
		}
	}
	switch {
	case overloaded:
		return ServingOverloaded
	case removed:
		return ServingFailover
	}
	for _, device := range serving {
		if !slices.Contains(current, device) && byDevice[device].Recovered {
			return ServingRecovered
		}
	}
	return ServingJoined
}

// compareDevices orders Devices as their canonical text, which sorts as the
// UUIDs do.
func compareDevices(first, second node.ID) int { return cmp.Compare(first.String(), second.String()) }
