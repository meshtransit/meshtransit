package kubecluster

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrNotRatcheted reports a replica that never proved a pod token: its
	// sessions need none, so there is nothing to suspend (K1d d2b).
	ErrNotRatcheted = errors.New("kubernetes cluster: the replica never proved a pod token")
	// ErrRatchetRateLimited reports a suspension after a person's tenth
	// suspension or resume within the hour; a resume is never refused.
	ErrRatchetRateLimited = errors.New("kubernetes cluster: too many ratchet changes")
)

// Bounds of a ratchet suspension (K1d §4.2): from 5 minutes to a day,
// never open ended.
const (
	MinimumRatchetSuspension = 5 * time.Minute
	MaximumRatchetSuspension = 24 * time.Hour
	MaximumRatchetChanges    = 10
)

// RatchetChange suspends a replica's pod token ratchet for Duration, or
// resumes it when Duration is zero (kubernetes_cluster.approve). Reason and
// ChangeRef go to the audit trail: a suspension lets the replica's sessions
// run without a pod token, so a copy of its Secret too.
type RatchetChange struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	DeviceID      node.ID
	Duration      time.Duration
	Reason        string
	ChangeRef     string
	CorrelationID publicid.ID
}

// Suspends reports a suspension, not a resume.
func (change RatchetChange) Suspends() bool { return change.Duration != 0 }

// RatchetChangeResult is what the change did: Changed false for a resume
// with nothing suspended; SuspendedUntil zero after a resume.
type RatchetChangeResult struct {
	Changed        bool
	SuspendedUntil time.Time
}

// ChangeTokenRatchet suspends or resumes a replica's pod token ratchet.
func (service *Service) ChangeTokenRatchet(ctx context.Context, change RatchetChange) (RatchetChangeResult,
	error) {
	if err := service.admit(ctx, change.Session, change.Scope); err != nil {
		return RatchetChangeResult{}, err
	}
	suspends := change.Suspends()
	if !change.ClusterID.IsValid() || !change.DeviceID.IsValid() || !change.CorrelationID.IsValid() ||
		suspends && (change.Duration < MinimumRatchetSuspension || change.Duration > MaximumRatchetSuspension ||
			change.Duration%time.Second != 0) ||
		!validRetireText(change.Reason, false) || !validRetireText(change.ChangeRef, !suspends) {
		return RatchetChangeResult{}, ErrInvalid
	}
	return service.store.ChangeTokenRatchet(ctx, change)
}
