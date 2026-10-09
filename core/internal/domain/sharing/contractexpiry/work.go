// Package contractexpiry finalizes Trust Contracts whose expiry has passed.
//
// Traffic through a share already stops at expiry. Finalizing moves the
// contract and everything that names it to a terminal state so the consumer's
// access name is released and a new share can reserve it again. An expired
// share is never renewed.
package contractexpiry

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

// Cursor is the last visited contract in (expiry, contract) keyset order. The
// zero cursor starts a new sweep.
type Cursor struct {
	ExpiresAt  time.Time
	ContractID sharing.ContractID
}

// IsZero reports the start of a sweep.
func (cursor Cursor) IsZero() bool {
	return cursor.ExpiresAt.IsZero() && cursor.ContractID == (sharing.ContractID{})
}

// IsValid accepts the zero cursor or a complete contract position.
func (cursor Cursor) IsValid() bool {
	return cursor.IsZero() || !cursor.ExpiresAt.IsZero() && cursor.ContractID.IsValid()
}

// After reports strict keyset order. Public IDs order like their bytes.
func (cursor Cursor) After(previous Cursor) bool {
	if previous.IsZero() {
		return !cursor.IsZero()
	}
	if !cursor.ExpiresAt.Equal(previous.ExpiresAt) {
		return cursor.ExpiresAt.After(previous.ExpiresAt)
	}
	return cursor.ContractID.String() > previous.ContractID.String()
}

// Candidate is a discovery hint for one open contract already past expiry. It
// grants nothing; the finalizer rechecks expiry and state under locks.
type Candidate struct {
	ContractID sharing.ContractID
	ExpiresAt  time.Time
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
		position := Cursor{ExpiresAt: item.ExpiresAt, ContractID: item.ContractID}
		if !item.ContractID.IsValid() || item.ExpiresAt.IsZero() || !position.After(previous) {
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

// Finalizer expires one contract in its own bounded transaction. It returns
// false when the contract is no longer open, not yet expired, held by a
// concurrent writer, or published through a gateway.
type Finalizer interface {
	Expire(ctx context.Context, installation deployment.ID, contract sharing.ContractID) (bool, error)
}
