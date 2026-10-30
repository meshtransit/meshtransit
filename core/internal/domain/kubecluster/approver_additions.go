package kubecluster

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
)

// MaximumApproverAdditions bounds the count a reader sees.
const MaximumApproverAdditions = 10

// ApproverAdditions says when someone was last given the right to approve a
// cluster's replicas within the last 24 hours, and how many such grants
// there were (at most 10); zero LatestAt when none (K1d Q150, Q177). It
// never names who.
type ApproverAdditions struct {
	LatestAt time.Time
	Count    int
}

// Valid reports a reading the database may give.
func (additions ApproverAdditions) Valid() bool {
	return additions.Count >= 0 && additions.Count <= MaximumApproverAdditions &&
		additions.LatestAt.IsZero() == (additions.Count == 0)
}

// ReadApproverAdditions reads a cluster's recent approver grants
// (network.read).
func (service *Service) ReadApproverAdditions(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID) (ApproverAdditions, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return ApproverAdditions{}, err
	}
	if !clusterID.IsValid() {
		return ApproverAdditions{}, ErrInvalid
	}
	return service.store.ReadApproverAdditions(ctx, session, scope, clusterID)
}
