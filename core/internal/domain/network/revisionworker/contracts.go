// Package revisionworker delivers durable Network-revision outbox facts as
// low-latency, best-effort coordination wakeups.
package revisionworker

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

// Outbox is the durable delivery boundary consumed by Dispatcher.
type Outbox interface {
	ReadNetworkRevisionBacklog(context.Context) (Backlog, error)
	ClaimNetworkRevisions(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error)
	LoadNetworkRevision(context.Context, network.RevisionClaim) (network.RevisionAdvanced, error)
	MarkRevisionDelivered(context.Context, network.RevisionClaim) error
	RetryNetworkRevision(context.Context, network.RevisionClaim, string, time.Duration) error
}

// Publisher is the best-effort coordination boundary consumed by Dispatcher.
type Publisher interface {
	PublishNetworkRevisionAdvanced(context.Context, network.RevisionAdvanced) error
}
