// Package revisionfeed fans out best-effort Network revision wakeups to local consumers.
package revisionfeed

import (
	"context"

	"meshtransit.net/core/internal/domain/network"
)

// Subscription is one caller-owned stream of validated revision wakeups.
// Close must be concurrency-safe and idempotent so shutdown can interrupt a
// blocking Receive while the receive owner performs the same final cleanup.
type Subscription interface {
	Receive(context.Context) (network.RevisionAdvanced, error)
	Close() error
}

// SubscribeFunc opens one process-owned revision subscription. The context
// bounds establishment only and must not be retained by the implementation.
type SubscribeFunc func(context.Context) (Subscription, error)
