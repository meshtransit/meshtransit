// Package election decides which router of a Site is its primary (design
// §6.2): a router stays primary while it can serve, another takes over only
// on clear evidence, and a router that failed must stay healthy for a while
// before it is chosen again.
package election

import (
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// Status is what one router can do for a Site now, from best to worst once
// it is no router the Site can use.
type Status int

const (
	// StatusUsable can serve the Site now.
	StatusUsable Status = iota + 1
	// StatusHoldDown recovered from a failure less than HoldDown ago.
	StatusHoldDown
	// StatusDraining was set to draining by an administrator.
	StatusDraining
	// StatusFailed reports the Site failed, or went silent past its grace.
	StatusFailed
	// StatusIneligible is no router of the Site at the authority level: its
	// Device is not live, not owned by the Workspace, or does not offer the
	// Site's prefixes. It is never chosen.
	StatusIneligible
)

// Reasons an election records.
const (
	ReasonElected  = "elected"
	ReasonFailover = "failover"
	ReasonFailback = "failback"
	// ReasonDegraded chose the best of routers none of which can serve.
	ReasonDegraded = "degraded"
	// ReasonNone found no router the Site can use at all.
	ReasonNone = "none"
)

// Timing of design §6.2.
const (
	// HoldDown is how long a router that failed must be healthy again.
	HoldDown = 30 * time.Second
	// FailbackAfter is how long a preferred router must be usable before a
	// Site with failback returns to it.
	FailbackAfter = 5 * time.Minute
	// SilenceGrace is how long a router that reported health may go without
	// a report before its silence counts as a failure.
	SilenceGrace = 120 * time.Second
)

// Candidate is one router of a Site as the election sees it, listed in
// priority order (a smaller priority first, then Device).
type Candidate struct {
	Device node.ID
	Status Status
	// Code is why a failed router failed, such as probe_failed.
	Code string
	// UsableFor is how long it has been usable without a break.
	UsableFor time.Duration
}

// Elect returns the Site's primary, zero when no router can be used, and
// why it changed; current is the primary now (zero: none or not elected
// yet). Candidates must be in priority order.
func Elect(current node.ID, candidates []Candidate, failback bool) (node.ID, string) {
	byDevice := make(map[node.ID]Candidate, len(candidates))
	for _, candidate := range candidates {
		byDevice[candidate.Device] = candidate
	}
	held, holds := byDevice[current]
	holds = holds && current.IsValid() && held.Status != StatusIneligible
	if holds && held.Status == StatusUsable {
		if failback {
			for _, candidate := range candidates {
				if candidate.Device == current {
					break
				}
				if candidate.Status == StatusUsable && candidate.UsableFor >= FailbackAfter {
					return candidate.Device, ReasonFailback
				}
			}
		}
		return current, ""
	}
	for _, candidate := range candidates {
		if candidate.Status == StatusUsable {
			if holds {
				return candidate.Device, ReasonFailover
			}
			return candidate.Device, ReasonElected
		}
	}
	// No router can serve: keep the best of the rest, the current one when
	// it is as good as any, so a Site does not move between broken routers.
	best := StatusIneligible
	for _, candidate := range candidates {
		best = min(best, candidate.Status)
	}
	if best == StatusIneligible {
		return node.ID{}, ReasonNone
	}
	if holds && held.Status == best {
		return current, ""
	}
	// Every router failing its probes alike most likely means a probe
	// target is down or wrong, not every router: keep the current one.
	if holds && best == StatusFailed && sameFailure(candidates) {
		return current, ""
	}
	for _, candidate := range candidates {
		if candidate.Status == best {
			return candidate.Device, ReasonDegraded
		}
	}
	return node.ID{}, ReasonNone
}

// sameFailure reports that every router the Site can use at the authority
// level failed its probes.
func sameFailure(candidates []Candidate) bool {
	seen := false
	for _, candidate := range candidates {
		if candidate.Status == StatusIneligible {
			continue
		}
		if candidate.Status != StatusFailed || candidate.Code != "probe_failed" {
			return false
		}
		seen = true
	}
	return seen
}
