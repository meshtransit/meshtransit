package mtcptest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	// reportSpacing keeps endpoint reports more than a second apart: Core
	// drops one that follows the last accepted report within a second
	// (mtcp-v1 §8.1).
	reportSpacing = 1200 * time.Millisecond
	// maxReconnectDelay bounds how long a Lifecycle RECONNECT before the
	// first map delays the next attempt.
	maxReconnectDelay = 5 * time.Second
)

// MapStream owns one established session of the registered Device and its
// map state. Next, ReportEndpoints and Close may be called from one
// goroutine; Close is also safe concurrently and idempotent.
type MapStream struct {
	client     *Client
	session    *session
	state      *mapState
	lastReport time.Time
}

// OpenMapStream opens a map session, reports the client's connectivity and
// reads until the map's self entry carries it, so the returned map is
// converged for the current report.
func (client *Client) OpenMapStream(ctx context.Context) (*MapStream, MapUpdate, error) {
	stream, initial, err := client.openStream(ctx)
	if err != nil {
		return nil, MapUpdate{}, err
	}
	converged, err := stream.converge(ctx, initial)
	if err != nil {
		return nil, MapUpdate{}, errors.Join(err, stream.Close())
	}
	return stream, converged, nil
}

// FetchFullMap opens a map session, waits for the map converged for the
// client's connectivity and closes the session. MTCP has no one-shot map
// request (mtcp-v1 §7); this is its equivalent.
func (client *Client) FetchFullMap(ctx context.Context) (_ FullMap, resultErr error) {
	stream, converged, err := client.OpenMapStream(ctx)
	if err != nil {
		return FullMap{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, stream.Close()) }()
	return converged.Map, nil
}

// FetchInitialStreamMap opens a map session and returns the snapshot Core
// sends when it starts the stream, before the session reports anything, then
// closes the session.
func (client *Client) FetchInitialStreamMap(ctx context.Context) (_ FullMap, resultErr error) {
	stream, initial, err := client.openStream(ctx)
	if err != nil {
		return FullMap{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, stream.Close()) }()
	return initial.Map, nil
}

// openStream establishes a session with a Ping and reads its KeyUpdate and
// first snapshot (mtcp-v1 §5, §11). A Lifecycle RECONNECT before the
// snapshot, sent while Core still ends the Device's previous stream, is
// retried after its delay until ctx ends.
func (client *Client) openStream(ctx context.Context) (*MapStream, MapUpdate, error) {
	if ctx == nil || client == nil {
		return nil, MapUpdate{}, ErrInvalidClient
	}
	for {
		stream, initial, retryAfter, err := client.tryOpenStream(ctx)
		if err == nil || retryAfter == 0 {
			return stream, initial, err
		}
		timer := time.NewTimer(min(retryAfter, maxReconnectDelay))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, MapUpdate{}, errors.Join(ErrMap, err, ctx.Err())
		case <-timer.C:
		}
	}
}

func (client *Client) tryOpenStream(ctx context.Context) (*MapStream, MapUpdate, time.Duration, error) {
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	nodePublic := client.node.Public()
	s, err := client.openSession(operationCtx, nodePublic[:])
	if err != nil {
		return nil, MapUpdate{}, 0, errors.Join(ErrMap, err)
	}
	stream := &MapStream{client: client, session: s, state: newMapState()}
	if err := s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
		return nil, MapUpdate{}, 0, errors.Join(ErrMap, fmt.Errorf("establish session: %w", err), stream.Close())
	}
	for {
		message, err := s.receive(operationCtx)
		if err != nil {
			return nil, MapUpdate{}, 0, errors.Join(ErrMap, fmt.Errorf("read first map: %w", err), stream.Close())
		}
		if lifecycle, ok := message.(*mtcpv1.Lifecycle); ok && lifecycle.GetState() == mtcpv1.Lifecycle_RECONNECT {
			retryAfter := max(time.Duration(lifecycle.GetRetryAfterMs())*time.Millisecond, 100*time.Millisecond)
			return nil, MapUpdate{}, retryAfter, errors.Join(ErrMap, errors.New("control asked to reconnect"),
				stream.Close())
		}
		update, delivered, err := stream.apply(message)
		if err != nil {
			return nil, MapUpdate{}, 0, errors.Join(err, stream.Close())
		}
		if delivered {
			if !update.Snapshot {
				return nil, MapUpdate{}, 0, errors.Join(ErrMap, errors.New("stream did not start with a snapshot"),
					stream.Close())
			}
			return stream, update, 0, nil
		}
	}
}

// converge reports the client's connectivity and reads until the self
// entry carries it. A snapshot that already carries it, because Core kept
// an earlier report, is converged at once.
func (stream *MapStream) converge(ctx context.Context, initial MapUpdate) (MapUpdate, error) {
	if err := stream.ReportEndpoints(ctx); err != nil {
		return MapUpdate{}, err
	}
	update := initial
	for !carries(update.Map, stream.client.Connectivity()) {
		next, err := stream.Next(ctx)
		if err != nil {
			return MapUpdate{}, fmt.Errorf("converge on reported endpoints: %w", err)
		}
		update = next
	}
	return update, nil
}

func carries(full FullMap, connectivity Connectivity) bool {
	return full.DiscoveryKey == connectivity.DiscoveryKey && slices.Equal(full.Endpoints, connectivity.Endpoints)
}

// Next returns the next map message applied to the stream's state. A
// Lifecycle or Error from Core ends the stream with an error.
func (stream *MapStream) Next(ctx context.Context) (MapUpdate, error) {
	if ctx == nil || stream == nil || stream.session == nil {
		return MapUpdate{}, ErrInvalidClient
	}
	for {
		message, err := stream.session.receive(ctx)
		if err != nil {
			return MapUpdate{}, errors.Join(ErrMap, fmt.Errorf("read map stream: %w", err))
		}
		update, delivered, err := stream.apply(message)
		if err != nil {
			return MapUpdate{}, err
		}
		if delivered {
			return update, nil
		}
	}
}

// apply handles one message from Core. It reports whether the message
// changed the map, which it then acknowledges. The test client
// acknowledges every map message: it reads few, so the once-per-second
// pacing of mtcp-v1 §7.2 never matters.
func (stream *MapStream) apply(message proto.Message) (MapUpdate, bool, error) {
	var (
		update  MapUpdate
		applied bool
		err     error
	)
	switch m := message.(type) {
	case *mtcpv1.MapSnapshot:
		update, err = stream.state.applySnapshot(m)
		applied = err == nil
	case *mtcpv1.MapDelta:
		update, applied, err = stream.state.applyDelta(m)
	case *mtcpv1.KeyUpdate:
		if err := stream.session.acknowledgeKeys(m); err != nil {
			return MapUpdate{}, false, errors.Join(ErrMap, err)
		}
		return MapUpdate{}, false, nil
	case *mtcpv1.Lifecycle:
		return MapUpdate{}, false, fmt.Errorf("%w: control sent lifecycle %v", ErrMap, m.GetState())
	case *mtcpv1.Error:
		return MapUpdate{}, false, errors.Join(ErrMap, errorMessage(m))
	default:
		// RelayTicket, Pong, Notice and a repeated RegisterResponse need
		// nothing from this client.
		return MapUpdate{}, false, nil
	}
	if err != nil || !applied {
		return MapUpdate{}, false, err
	}
	if err := stream.session.send(sharedmtcp.MessageMapAck, &mtcpv1.MapAck{View: stream.state.view()}); err != nil {
		return MapUpdate{}, false, errors.Join(ErrMap, fmt.Errorf("acknowledge map: %w", err))
	}
	return update, true, nil
}

// ReportEndpoints sends the client's current connectivity as an
// EndpointReport, waiting first so that Core does not drop it as too
// frequent (mtcp-v1 §8.1).
func (stream *MapStream) ReportEndpoints(ctx context.Context) error {
	if ctx == nil || stream == nil || stream.session == nil {
		return ErrInvalidClient
	}
	if err := stream.AwaitReportSpacing(ctx); err != nil {
		return err
	}
	connectivity := stream.client.Connectivity()
	report := &mtcpv1.EndpointReport{DiscoKey: connectivity.DiscoveryKey[:], ObservedMs: time.Now().UnixMilli()}
	for _, endpoint := range connectivity.Endpoints {
		report.Endpoints = append(report.Endpoints, &mtcpv1.Endpoint{
			Ip: endpoint.Addr().AsSlice(), Port: uint32(endpoint.Port()), Kind: mtcpv1.Endpoint_SERVER_REFLEXIVE,
		})
	}
	if err := stream.session.send(sharedmtcp.MessageEndpointReport, report); err != nil {
		return errors.Join(ErrMap, fmt.Errorf("send endpoint report: %w", err))
	}
	stream.lastReport = time.Now()
	return nil
}

// AwaitReportSpacing waits until ReportEndpoints would send at once, so a
// caller can time a report from when it leaves.
func (stream *MapStream) AwaitReportSpacing(ctx context.Context) error {
	if ctx == nil || stream == nil {
		return ErrInvalidClient
	}
	wait := time.Until(stream.lastReport.Add(reportSpacing))
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errors.Join(ErrMap, ctx.Err())
	case <-timer.C:
		return nil
	}
}

// Close ends the session.
func (stream *MapStream) Close() error {
	if stream == nil || stream.session == nil {
		return nil
	}
	return stream.session.close()
}
