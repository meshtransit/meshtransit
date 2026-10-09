package mapsession

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// DeliveryTouchInterval bounds how often a live stream refreshes the time a
// Device was last seen; presence renews far more often.
const DeliveryTouchInterval = time.Minute

// Delivery is what one Device last received over its map stream: the Network
// revision, and the policy revision it carried, of the last state-changing
// frame written and flushed to it, and the digest of its packet filter when
// the adapter computes one. NodeKey and MachineFingerprint identify the
// session, so a later enforcement report can be tied to it.
type Delivery struct {
	NodeID             node.ID
	NodeKey            node.Key
	MachineFingerprint [32]byte
	SessionGeneration  int64
	NetworkRevision    int64
	PolicyRevision     int64
	DeliveredAt        time.Time
	Filter             FilterDigest
}

// IsValid reports a complete delivery observation.
func (delivery Delivery) IsValid() bool {
	return delivery.NodeID.IsValid() && delivery.NodeKey.IsValid() && delivery.MachineFingerprint != [32]byte{} &&
		delivery.SessionGeneration > 0 &&
		delivery.NetworkRevision > 0 && delivery.PolicyRevision >= 0 && !delivery.DeliveredAt.IsZero()
}

func deliveryOf(snapshot Snapshot, filter FilterDigest, at time.Time) Delivery {
	return Delivery{
		NodeID:             snapshot.NodeID(),
		NodeKey:            snapshot.NodeKey(),
		MachineFingerprint: snapshot.MachineKey().Fingerprint(),
		SessionGeneration:  snapshot.SessionGeneration(),
		NetworkRevision:    snapshot.NetworkRevision(),
		PolicyRevision:     snapshot.PacketPolicy().Revision(),
		DeliveredAt:        at.UTC(),
		Filter:             filter,
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
	recorded.enforcement = service.enforcement
	return recorded, nil
}

// recordDelivery notes a frame that was written and flushed. Errors are
// deliberately dropped: the recorder counts them, and distribution status
// must never cost a Device its map.
func (service *StreamService) recordDelivery(ctx context.Context, snapshot Snapshot, filter FilterDigest) {
	if service.delivery == nil {
		return
	}
	recordCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	_ = service.delivery.RecordDelivery(recordCtx, deliveryOf(snapshot, filter, time.Now()))
}

// filterDigest returns the digest of the filter snapshot sends, or the zero
// value when no digester is composed or the filter cannot be digested; the
// Device then shows no enforcement comparison rather than losing its map.
func (service *StreamService) filterDigest(snapshot Snapshot) FilterDigest {
	if service.delivery == nil || service.options.FilterDigest == nil {
		return FilterDigest{}
	}
	filter, err := service.options.FilterDigest(snapshot)
	if err != nil {
		return FilterDigest{}
	}
	return filter
}

func (service *StreamService) touchDelivery(ctx context.Context, snapshot Snapshot, at time.Time) {
	if service.delivery == nil {
		return
	}
	touchCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	_ = service.delivery.TouchDelivery(touchCtx, snapshot.NodeID(), snapshot.SessionGeneration(), at.UTC())
}
