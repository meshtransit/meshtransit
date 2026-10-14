package mapsession

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// A Device's peers see at most one change of its endpoints, disco key or
// preferred relay per announce interval, whatever its sessions and replicas
// (mtcp-v1 §8.1): every change wakes the map stream of each peer, so a
// Device changing them in a loop would otherwise cost its Network one delta
// per peer per change. The first change of a quiet Device is announced at
// once and the latest of the changes that follow is announced when the
// interval ends; none is dropped.
const (
	DefaultEndpointAnnounceInterval = 5 * time.Second
	minimumEndpointAnnounceInterval = time.Second
	maximumEndpointAnnounceInterval = 30 * time.Second
)

// EndpointAnnouncement says how an accepted endpoint observation reached
// the Device's peers.
type EndpointAnnouncement struct {
	// Deferred reports a change stored but not announced yet, because the
	// Device announced another one within the interval. RetryAfter is when
	// FlushEndpoints can announce it.
	Deferred   bool
	RetryAfter time.Duration
}

var (
	// ErrEndpointStore reports an endpoint observation the transient store
	// could not take now; the caller may retry it. Any other observation
	// error is final for that observation.
	ErrEndpointStore = errors.New("map session: endpoint store unavailable")
	// ErrEndpointFlush reports a deferred endpoint change that could not be
	// announced now; the caller may retry it.
	ErrEndpointFlush = errors.New("map session: endpoint flush failed")
)

var errEndpointAnnouncement = errors.New("map session: invalid endpoint announcement")

func (announcement EndpointAnnouncement) valid() bool {
	if announcement.Deferred {
		return announcement.RetryAfter > 0 && announcement.RetryAfter <= maximumEndpointAnnounceInterval
	}
	return announcement.RetryAfter == 0
}

// FlushSessionEndpoints announces the deferred endpoint change of the
// Device of snapshot, if its interval ended; it answers Deferred while it
// has not.
func (service *Service) FlushSessionEndpoints(ctx context.Context, snapshot Snapshot) (EndpointAnnouncement, error) {
	if ctx == nil || service == nil || !snapshot.IsValid() {
		return EndpointAnnouncement{}, ErrInvalidRequest
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.EndpointTimeout)
	defer cancel()
	announcement, err := service.endpoints.FlushEndpoints(operationCtx, snapshot.Scope(), snapshot.NodeID(),
		snapshot.SessionGeneration(), service.options.endpointAnnounceInterval())
	if err != nil {
		return EndpointAnnouncement{}, fmt.Errorf("%w: %w", ErrEndpointFlush, err)
	}
	if !announcement.valid() {
		return EndpointAnnouncement{}, errEndpointAnnouncement
	}
	return announcement, nil
}
