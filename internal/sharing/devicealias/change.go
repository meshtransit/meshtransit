// Package devicealias owns client-only alias lifecycle intents.
package devicealias

import (
	"context"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// ChangeMode separates durable allocation from packet readiness publication.
type ChangeMode string

// Supported lifecycle changes separate allocation and packet readiness.
const (
	Reserve ChangeMode = "reserve"
	Ready   ChangeMode = "ready"
)

// ChangeIntent pins the exact endpoint and both currently observed key epochs.
// It cannot request arbitrary scope, addresses, expiry, packet rules or revisions.
type ChangeIntent struct {
	DeploymentID       deployment.ID
	EndpointID         sharing.PrivateEndpointID
	ConsumerID         node.ID
	EndpointGeneration int64
	ProviderNodeEpoch  int64
	ConsumerNodeEpoch  int64
	Mode               ChangeMode
}

// IsValid rejects incomplete authority selectors before any durable effect.
func (intent ChangeIntent) IsValid() bool {
	return intent.DeploymentID.IsValid() && intent.EndpointID.IsValid() && intent.ConsumerID.IsValid() &&
		intent.EndpointGeneration > 0 && intent.ProviderNodeEpoch > 0 && intent.ConsumerNodeEpoch > 0 &&
		(intent.Mode == Reserve || intent.Mode == Ready)
}

// Changes performs one guarded change with complete bilateral evidence. A false
// result reports an exact idempotent replay, never an additional packet grant.
type Changes interface {
	Change(context.Context, ChangeIntent) (bool, error)
}
