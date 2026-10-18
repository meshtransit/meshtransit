// Package retirement retires the Device Resource of a removed Device.
//
// Traffic to such a Resource has already stopped: map readers require an
// active Device. Retiring deletes the Resource and supersedes its Device
// target so the name and the Device can be used again, and the Resource is
// no longer offered for sharing. A Resource whose shares are still open waits
// until they end.
package retirement

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/resource"
)

// Cursor is the last visited Resource in (queued at, Resource) keyset order.
// The zero cursor starts a new sweep.
type Cursor struct {
	At         time.Time
	ResourceID resource.ID
}

// IsZero reports the start of a sweep.
func (cursor Cursor) IsZero() bool {
	return cursor.At.IsZero() && cursor.ResourceID == (resource.ID{})
}

// IsValid accepts the zero cursor or a complete Resource position.
func (cursor Cursor) IsValid() bool {
	return cursor.IsZero() || !cursor.At.IsZero() && cursor.ResourceID.IsValid()
}

// After reports strict keyset order. Public IDs order like their bytes.
func (cursor Cursor) After(previous Cursor) bool {
	if previous.IsZero() {
		return !cursor.IsZero()
	}
	if !cursor.At.Equal(previous.At) {
		return cursor.At.After(previous.At)
	}
	return cursor.ResourceID.String() > previous.ResourceID.String()
}

// Candidate is a discovery hint for one queued Resource. It grants nothing;
// the retirer rechecks the removal and state under locks.
type Candidate struct {
	ResourceID resource.ID
	At         time.Time
}

// Page holds at most one bounded batch of candidates in keyset order.
type Page struct {
	Items []Candidate
	Next  Cursor
	Done  bool
}

// IsValid rejects pages that stall, repeat or reorder candidates.
func (page Page) IsValid(after Cursor, limit int) bool {
	if !after.IsValid() || limit < 1 || limit > maximumBatchSize || len(page.Items) > limit || !page.Next.IsValid() {
		return false
	}
	previous := after
	for _, item := range page.Items {
		position := Cursor{At: item.At, ResourceID: item.ResourceID}
		if !item.ResourceID.IsValid() || item.At.IsZero() || !position.After(previous) {
			return false
		}
		previous = position
	}
	if page.Done {
		return true
	}
	return len(page.Items) == limit && page.Next == previous
}

// Candidates discovers one finite page without holding a write transaction.
type Candidates interface {
	List(ctx context.Context, installation deployment.ID, after Cursor, limit int) (Page, error)
}

// Retirer retires one Resource in its own bounded transaction. It returns
// false when the Resource is already gone, its Device was not removed, a
// concurrent writer holds it, or a share of it is still open.
type Retirer interface {
	Retire(ctx context.Context, installation deployment.ID, id resource.ID) (bool, error)
}
