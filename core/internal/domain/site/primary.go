package site

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// History page bounds.
const (
	DefaultHistoryPage = 10
	MaximumHistoryPage = 50
)

// Primary is the router Core elected for a Site.
type Primary struct {
	// Device is the elected router; zero when no router can serve the Site.
	Device     node.ID
	Generation int64
	// Reason is why it changed: elected, failover, failback, degraded or
	// none.
	Reason    string
	ElectedAt time.Time
}

// PrimaryChange is one change of a Site's primary, as audited.
type PrimaryChange struct {
	EventID    publicid.ID
	OccurredAt time.Time
	// Device and Previous are zero for none; a Device since removed keeps
	// its ID, as audited.
	Device, Previous node.ID
	Reason           string
	Generation       int64
}

// PrimaryHistory is one page of a Site's primary changes, newest first.
type PrimaryHistory struct {
	Changes []PrimaryChange
	HasMore bool
}

// IsValidReason reports a reason an election records.
func IsValidReason(reason string) bool {
	switch reason {
	case "elected", "failover", "failback", "degraded", "none":
		return true
	default:
		return false
	}
}

// IsValid reports a self-consistent primary.
func (primary Primary) IsValid() bool {
	return (primary.Device == node.ID{} || primary.Device.IsValid()) && primary.Generation > 0 &&
		IsValidReason(primary.Reason) && !primary.ElectedAt.IsZero()
}

// IsValid reports a self-consistent change.
func (change PrimaryChange) IsValid() bool {
	return change.EventID.IsValid() && !change.OccurredAt.IsZero() &&
		(change.Device == node.ID{} || change.Device.IsValid()) &&
		(change.Previous == node.ID{} || change.Previous.IsValid()) &&
		IsValidReason(change.Reason) && change.Generation > 0
}

// PrimaryChanges returns one page of a Site's primary changes, newest
// first, after the change after when it is set.
func (service *Service) PrimaryChanges(ctx context.Context, session accountsession.Session, scope network.Scope,
	site ID, after publicid.ID, limit int) (PrimaryHistory, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return PrimaryHistory{}, err
	}
	if !site.IsValid() || limit < 1 || limit > MaximumHistoryPage || (after != publicid.ID{} && !after.IsValid()) {
		return PrimaryHistory{}, ErrInvalid
	}
	history, err := service.store.PrimaryChanges(ctx, session, scope, site, after, limit)
	if err != nil {
		return PrimaryHistory{}, err
	}
	if len(history.Changes) > limit {
		return PrimaryHistory{}, ErrInvalid
	}
	for _, change := range history.Changes {
		if !change.IsValid() {
			return PrimaryHistory{}, ErrInvalid
		}
	}
	return history, nil
}
