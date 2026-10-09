// Package devicealias owns client-only alias lifecycle intents.
package devicealias

import (
	"context"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

// ChangeMode separates durable allocation from packet readiness publication.
type ChangeMode string

// Supported lifecycle changes separate allocation and packet readiness.
const (
	Reserve            ChangeMode = "reserve"
	Ready              ChangeMode = "ready"
	Withdraw           ChangeMode = "withdraw"
	QuarantineConsumer ChangeMode = "quarantine_consumer"
	QuarantineResource ChangeMode = "quarantine_resource"
)

// ChangeIntent pins the exact endpoint; grant operations also pin both current key epochs.
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
	return intent.DeploymentID.IsValid() && intent.EndpointID.IsValid() && (intent.ConsumerID.IsValid() || intent.Mode == QuarantineResource && intent.ConsumerID == (node.ID{})) &&
		intent.EndpointGeneration > 0 && intent.Mode.IsValid() &&
		(intent.Mode.Withdraws() || intent.ProviderNodeEpoch > 0 && intent.ConsumerNodeEpoch > 0)
}

// Changes performs one guarded change with complete bilateral evidence. A false
// result reports an exact idempotent replay, never an additional packet grant.
type Changes interface {
	Change(context.Context, ChangeIntent) (bool, error)
}

// IsValid recognizes the bounded grant and no-grant lifecycle commands.
func (mode ChangeMode) IsValid() bool {
	return mode == Reserve || mode == Ready || mode == Withdraw || mode == QuarantineConsumer || mode == QuarantineResource
}

// Withdraws distinguishes operations that cannot create packet authority.
func (mode ChangeMode) Withdraws() bool {
	return mode == Withdraw || mode == QuarantineConsumer || mode == QuarantineResource
}
