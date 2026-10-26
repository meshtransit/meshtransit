package kubecluster

import (
	"errors"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/node"
)

// ErrEdgeBudget reports a replica that would give a Device more rule edges
// than its map takes, through the rules to its cluster (MTD06 on approval,
// MTK11 on completion, which the replica retries).
var ErrEdgeBudget = errors.New("kubernetes cluster: a Device would exceed its rule edge limit")

// EdgeBudgetError is ErrEdgeBudget naming the source Device that would
// exceed the limit; zero when it is the new replica itself.
type EdgeBudgetError struct{ SourceDeviceID node.ID }

func (failure *EdgeBudgetError) Error() string { return ErrEdgeBudget.Error() }

// Is matches ErrEdgeBudget.
func (failure *EdgeBudgetError) Is(target error) bool { return target == ErrEdgeBudget }

// PolicyGroup is the system Device Group through which rules reach every
// active replica of one cluster (K1a2a). Its members change only with the
// cluster's replicas; rules name it on TCP 443 as a destination only.
type PolicyGroup struct {
	ClusterID ID
	Name      Name
	GroupID   devicegroup.ID
}

// IsValid reports a cluster, its name and its group.
func (group PolicyGroup) IsValid() bool {
	_, err := ParseName(group.Name.String())
	return group.ClusterID.IsValid() && err == nil && group.GroupID.IsValid()
}
