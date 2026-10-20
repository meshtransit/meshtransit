// Package election decides which router of a Site is its primary (subnet
// router design §6.2), with the election package primaryelection shares
// with Exit Pools: a router stays primary while it can serve, another takes
// over only on clear evidence, and a router that failed must stay healthy
// for a while before it is chosen again.
package election

import (
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/primaryelection"
)

// Status is what one router can do for a Site now, from best to worst.
type Status = primaryelection.Status

// Router statuses.
const (
	StatusUsable     = primaryelection.StatusUsable
	StatusHoldDown   = primaryelection.StatusHoldDown
	StatusDraining   = primaryelection.StatusDraining
	StatusFailed     = primaryelection.StatusFailed
	StatusIneligible = primaryelection.StatusIneligible
)

// Reasons an election records.
const (
	ReasonElected  = primaryelection.ReasonElected
	ReasonFailover = primaryelection.ReasonFailover
	ReasonFailback = primaryelection.ReasonFailback
	ReasonDegraded = primaryelection.ReasonDegraded
	ReasonNone     = primaryelection.ReasonNone
)

// Timing of design §6.2.
const (
	HoldDown      = primaryelection.HoldDown
	FailbackAfter = primaryelection.FailbackAfter
	SilenceGrace  = primaryelection.SilenceGrace
)

// Candidate is one router of a Site as the election sees it.
type Candidate = primaryelection.Candidate

// Elect returns the Site's primary; see primaryelection.Elect.
func Elect(current node.ID, candidates []Candidate, failback bool) (node.ID, string) {
	return primaryelection.Elect(current, candidates, failback)
}
