package kubecluster

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// ErrNoActiveReplica: the cluster has no active replica to explain through.
var ErrNoActiveReplica = errors.New("kubernetes cluster: no active replica")

// ReadExplainReplica returns the active replica with the lowest ordinal, the
// one Explain answers a question about the cluster through: every rule to a
// cluster reaches all its replicas alike (K1d d4c, Q179). network.read.
func (service *Service) ReadExplainReplica(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID) (node.ID, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return node.ID{}, err
	}
	if !clusterID.IsValid() {
		return node.ID{}, ErrInvalid
	}
	return service.store.ReadExplainReplica(ctx, session, scope, clusterID)
}
