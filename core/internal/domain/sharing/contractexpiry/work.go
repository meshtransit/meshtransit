// Package contractexpiry finalizes Trust Contracts that can no longer carry
// traffic: those past their expiry, and those whose provider Device was
// removed.
//
// Traffic through such a share has already stopped. Finalizing moves the
// contract and everything that names it to a terminal state so both sides see
// the share ended and the consumer's access name is released for a new share.
// An ended share is never renewed.
package contractexpiry

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/sharing"
)

// Cursor is the last visited contract in (instant, contract) keyset order:
// the instant is the expiry for expired contracts and the removal for
// contracts of removed Devices. The zero cursor starts a new sweep.
type Cursor struct {
	At         time.Time
	ContractID sharing.ContractID
}

// IsZero reports the start of a sweep.
func (cursor Cursor) IsZero() bool {
	return cursor.At.IsZero() && cursor.ContractID == (sharing.ContractID{})
}

// IsValid accepts the zero cursor or a complete contract position.
func (cursor Cursor) IsValid() bool {
	return cursor.IsZero() || !cursor.At.IsZero() && cursor.ContractID.IsValid()
}

// After reports strict keyset order. Public IDs order like their bytes.
func (cursor Cursor) After(previous Cursor) bool {
	if previous.IsZero() {
		return !cursor.IsZero()
	}
	if !cursor.At.Equal(previous.At) {
		return cursor.At.After(previous.At)
	}
	return cursor.ContractID.String() > previous.ContractID.String()
}

// Candidate is a discovery hint for one open contract to end. It grants
// nothing; the finalizer rechecks the reason and state under locks.
type Candidate struct {
	ContractID sharing.ContractID
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
		position := Cursor{At: item.At, ContractID: item.ContractID}
		if !item.ContractID.IsValid() || item.At.IsZero() || !position.After(previous) {
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

// Finalizer ends one contract in its own bounded transaction. It returns
// false when the contract is no longer open, no longer has a reason to end,
// is held by a concurrent writer, or is published through a gateway.
type Finalizer interface {
	End(ctx context.Context, installation deployment.ID, contract sharing.ContractID) (bool, error)
}
