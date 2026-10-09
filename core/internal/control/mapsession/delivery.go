package mapsession

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

// DeliveryTouchInterval bounds how often a live stream refreshes the time a
// Device was last seen; presence renews far more often.
const DeliveryTouchInterval = time.Minute

// Delivery is what one Device last received over its map stream: the Network
// revision, and the policy revision it carried, of the last state-changing
// frame written and flushed to it.
type Delivery struct {
	NodeID            node.ID
	SessionGeneration int64
	NetworkRevision   int64
	PolicyRevision    int64
	DeliveredAt       time.Time
}

// IsValid reports a complete delivery observation.
func (delivery Delivery) IsValid() bool {
	return delivery.NodeID.IsValid() && delivery.SessionGeneration > 0 &&
		delivery.NetworkRevision > 0 && delivery.PolicyRevision >= 0 && !delivery.DeliveredAt.IsZero()
}

func deliveryOf(snapshot Snapshot, at time.Time) Delivery {
	return Delivery{
		NodeID:            snapshot.NodeID(),
		SessionGeneration: snapshot.SessionGeneration(),
		NetworkRevision:   snapshot.NetworkRevision(),
		PolicyRevision:    snapshot.PacketPolicy().Revision(),
		DeliveredAt:       at.UTC(),
	}
}

// DeliveryRecorder keeps, per Device, the last delivered revision and when the
// Device was last seen, so operators can see who runs the current policy.
// Recording is best effort: the implementation counts its own failures, and a
// failure never ends or delays the stream.
type DeliveryRecorder interface {
	RecordDelivery(context.Context, Delivery) error
	TouchDelivery(ctx context.Context, nodeID node.ID, sessionGeneration int64, seenAt time.Time) error
}

// WithDeliveryRecorder returns a service that also records deliveries. Call it
// once while composing, before any stream is served.
func (service *StreamService) WithDeliveryRecorder(recorder DeliveryRecorder) (*StreamService, error) {
	if service == nil || isNilDependency(recorder) {
		return nil, ErrInvalidStreamService
	}
	recorded, err := NewStreamService(service.snapshots, service.presence, service.revisions,
		service.connectivity, service.options)
	if err != nil {
		return nil, err
	}
	recorded.delivery = recorder
	return recorded, nil
}

// recordDelivery notes a frame that was written and flushed. Errors are
// deliberately dropped: the recorder counts them, and distribution status
// must never cost a Device its map.
func (service *StreamService) recordDelivery(ctx context.Context, snapshot Snapshot) {
	if service.delivery == nil {
		return
	}
	recordCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	_ = service.delivery.RecordDelivery(recordCtx, deliveryOf(snapshot, time.Now()))
}

func (service *StreamService) touchDelivery(ctx context.Context, snapshot Snapshot, at time.Time) {
	if service.delivery == nil {
		return
	}
	touchCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	_ = service.delivery.TouchDelivery(touchCtx, snapshot.NodeID(), snapshot.SessionGeneration(), at.UTC())
}
