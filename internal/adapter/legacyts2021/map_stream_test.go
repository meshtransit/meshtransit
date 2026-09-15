package legacyts2021

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
)

func TestMapSessionHandlerStreamsInitialSnapshotAndKeepAlive(t *testing.T) {
	t.Parallel()

	snapshot := mapSnapshotFixture(t)
	streams := &recordingMapStreamService{snapshot: snapshot}
	handler := newMapSessionHandlerWithStreams(
		t,
		&recordingMapSessionService{snapshot: snapshot},
		streams,
	)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	body := strings.Replace(mapRequestBody, `"Stream":false`, `"Stream":true`, 1)
	response := serveMap(t, authenticated, body)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != mapResponseContentType ||
		response.Header().Get("Content-Length") != "" || !response.Flushed {
		t.Fatalf("stream response = (%d, %v, flushed=%t)", response.Code, response.Header(), response.Flushed)
	}
	frames := decodeMapStreamFrames(t, response.Body.Bytes())
	if len(frames) != 2 || frames[0].Node == nil || frames[0].KeepAlive ||
		!frames[1].KeepAlive || frames[1].Node != nil {
		t.Fatalf("stream frames = %+v, want initial snapshot then keepalive", frames)
	}
	if streams.calls != 1 || !streams.sawValid || !streams.sawSink {
		t.Fatalf("stream service calls = (%d,%t,%t), want one valid invocation", streams.calls, streams.sawValid, streams.sawSink)
	}
	metrics := gatherControlMetrics(t, handler.telemetry)
	for _, metric := range []string{
		`meshtransit_control_map_requests_total{result="stream_closed"} 1`,
		`meshtransit_control_map_requests_active 0`,
		`meshtransit_control_map_streams_active 0`,
	} {
		if !strings.Contains(metrics, metric) {
			t.Fatalf("stream metrics missing %q: %s", metric, metrics)
		}
	}
}

func TestMapSessionHandlerStreamsUncompressedFramesForMeshD(t *testing.T) {
	t.Parallel()

	snapshot := mapSnapshotFixture(t)
	streams := &recordingMapStreamService{snapshot: snapshot}
	handler := newMapSessionHandlerWithStreams(
		t,
		&recordingMapSessionService{snapshot: snapshot},
		streams,
	)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	// meshd@659d9e7 omits Compress and reads each framed payload as JSON.
	body := strings.Replace(mapRequestBody, `  "Compress":"zstd",`+"\n", "", 1)
	body = strings.Replace(body, `"Stream":false`, `"Stream":true`, 1)
	response := serveMap(t, authenticated, body)
	frames := decodeUncompressedMapStreamFrames(t, response.Body.Bytes())
	if response.Code != http.StatusOK || len(frames) != 2 || frames[0].Node == nil ||
		frames[0].KeepAlive || !frames[1].KeepAlive || frames[1].Node != nil {
		t.Fatalf(
			"uncompressed stream = (status=%d, frames=%+v), want snapshot then keepalive",
			response.Code,
			frames,
		)
	}
}

func TestMapSessionHandlerStreamsPeerAndPolicyAtomicallyAfterSnapshotAdvance(t *testing.T) {
	t.Parallel()

	initial, advanced, peer := mapAuthorityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewAuthorityDelta(initial, advanced)
	if err != nil {
		t.Fatalf("mapsession.NewAuthorityDelta() error = %v", err)
	}
	streams := &authorityDeltaMapStreamService{initial: initial, delta: delta}
	handler := newMapSessionHandlerWithStreams(
		t,
		&recordingMapSessionService{snapshot: initial},
		streams,
	)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	// meshd@659d9e7 omits Compress and atomically applies PeersChanged plus
	// PacketFilter from one JSON frame through its candidate accumulator.
	body := strings.Replace(mapRequestBody, `  "Compress":"zstd",`+"\n", "", 1)
	body = strings.Replace(body, `"Stream":false`, `"Stream":true`, 1)
	response := serveMap(t, authenticated, body)
	frames := decodeUncompressedMapStreamFrames(t, response.Body.Bytes())
	if len(frames) != 2 || len(frames[0].Peers) != 0 || len(frames[0].PacketFilter) != 0 ||
		frames[1].Peers != nil || len(frames[1].PeersChanged) != 1 ||
		frames[1].PeersChanged[0].ID != tailcfg.NodeID(peer.NumericNodeID()) ||
		len(frames[1].PacketFilter) != 2 || frames[1].PeersRemoved != nil {
		t.Fatalf(
			"stream frames = %+v, want full initial state then atomic peer+policy delta",
			frames,
		)
	}
}

func TestMapSessionHandlerStreamsNetworkNameAfterRevisionAdvance(t *testing.T) {
	t.Parallel()

	// meshd@659d9e7 applies MapResponse.Domain and increments its semantic
	// netmap revision only when that client-visible value changes.
	initial := mapSnapshotFixture(t)
	advancedParams := mapSnapshotParams(initial)
	advancedParams.NetworkRevision++
	advancedName, err := network.ParseDisplayName("Development Mesh Live")
	if err != nil {
		t.Fatalf("network.ParseDisplayName() error = %v", err)
	}
	advancedParams.NetworkName = advancedName
	advanced, err := mapsession.NewSnapshot(advancedParams)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot(advanced) error = %v", err)
	}
	streams := &advancingMapStreamService{snapshots: []mapsession.Snapshot{initial, advanced}}
	handler := newMapSessionHandlerWithStreams(
		t,
		&recordingMapSessionService{snapshot: initial},
		streams,
	)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	body := strings.Replace(mapRequestBody, `  "Compress":"zstd",`+"\n", "", 1)
	body = strings.Replace(body, `"Stream":false`, `"Stream":true`, 1)
	response := serveMap(t, authenticated, body)
	frames := decodeUncompressedMapStreamFrames(t, response.Body.Bytes())
	if response.Code != http.StatusOK || len(frames) != 2 ||
		frames[0].Domain != "Development Mesh" || frames[1].Domain != "Development Mesh Live" {
		t.Fatalf(
			"network names = (status=%d, frames=%+v), want ordered full projections",
			response.Code,
			frames,
		)
	}
}

func TestMapSessionHandlerStreamsSameRevisionConnectivityDelta(t *testing.T) {
	t.Parallel()

	initial, next, _ := mapConnectivityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewConnectivityDelta(initial, next)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityDelta() error = %v", err)
	}
	streams := &connectivityDeltaMapStreamService{initial: initial, delta: delta}
	handler := newMapSessionHandlerWithStreams(
		t,
		&recordingMapSessionService{snapshot: initial},
		streams,
	)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	body := strings.Replace(mapRequestBody, `"Stream":false`, `"Stream":true`, 1)
	response := serveMap(t, authenticated, body)
	frames := decodeMapStreamFrames(t, response.Body.Bytes())
	if len(frames) != 2 || frames[0].Node == nil || len(frames[0].Peers) != 1 ||
		frames[1].Node != nil || frames[1].Peers != nil || frames[1].PacketFilter != nil ||
		len(frames[1].PeersChanged) != 1 || frames[1].PeersChanged[0].ID != 702 {
		t.Fatalf(
			"stream frames = %+v, want full initial snapshot then peer connectivity delta",
			frames,
		)
	}
}

func TestMapSessionHandlerStreamsTerminalAuthorityWithdrawal(t *testing.T) {
	t.Parallel()

	snapshot := mapSnapshotWithCandidateFixture(t)
	streams := &authorityWithdrawalMapStreamService{snapshot: snapshot}
	handler := newMapSessionHandlerWithStreams(
		t,
		&recordingMapSessionService{snapshot: snapshot},
		streams,
	)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	body := strings.Replace(mapRequestBody, `  "Compress":"zstd",`+"\n", "", 1)
	body = strings.Replace(body, `"Stream":false`, `"Stream":true`, 1)
	response := serveMap(t, authenticated, body)
	frames := decodeUncompressedMapStreamFrames(t, response.Body.Bytes())
	if response.Code != http.StatusOK || len(frames) != 2 || frames[0].Node == nil ||
		frames[1].Node == nil || frames[1].Node.ID != frames[0].Node.ID ||
		frames[1].Node.Key != frames[0].Node.Key || !frames[1].Node.Expired ||
		frames[1].Node.MachineAuthorized || frames[1].Peers == nil ||
		len(frames[1].Peers) != 0 || frames[1].PacketFilter == nil ||
		len(frames[1].PacketFilter) != 0 {
		t.Fatalf("stream frames = %+v, want snapshot then terminal withdrawal", frames)
	}
	metrics := gatherControlMetrics(t, handler.telemetry)
	if !strings.Contains(
		metrics,
		`meshtransit_control_map_requests_total{result="authority_changed"} 1`,
	) {
		t.Fatalf("authority withdrawal metrics are incomplete: %s", metrics)
	}
}

func TestMapStreamSinkRejectsDeltaBeforeInitialSnapshot(t *testing.T) {
	t.Parallel()

	current, next, _ := mapConnectivityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewConnectivityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityDelta() error = %v", err)
	}
	response := httptest.NewRecorder()
	sink := newMapStreamSink(response, 142, mapResponseCompressionZstd)
	if err := sink.SendConnectivityDelta(t.Context(), delta); !errors.Is(err, ErrMapStreamWrite) {
		t.Fatalf("SendConnectivityDelta(before snapshot) error = %v, want ErrMapStreamWrite", err)
	}
	if sink.started() || response.Body.Len() != 0 {
		t.Fatal("rejected initial delta committed an HTTP response")
	}
}

func TestMapStreamSinkRejectsAuthorityDeltaBeforeInitialSnapshot(t *testing.T) {
	t.Parallel()

	current, next, _ := mapAuthorityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewAuthorityDelta() error = %v", err)
	}
	response := httptest.NewRecorder()
	sink := newMapStreamSink(response, 142, mapResponseCompressionZstd)
	if err := sink.SendAuthorityDelta(t.Context(), delta); !errors.Is(err, ErrMapStreamWrite) {
		t.Fatalf("SendAuthorityDelta(before snapshot) error = %v, want ErrMapStreamWrite", err)
	}
	if sink.started() || response.Body.Len() != 0 {
		t.Fatal("rejected initial authority delta committed an HTTP response")
	}
}

func TestMapStreamSinkRejectsAuthorityWithdrawalBeforeInitialSnapshot(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	sink := newMapStreamSink(response, 142, mapResponseCompressionZstd)
	if err := sink.SendAuthorityWithdrawal(
		t.Context(),
		mapSnapshotFixture(t),
	); !errors.Is(err, ErrMapStreamWrite) {
		t.Fatalf("SendAuthorityWithdrawal(before snapshot) error = %v, want ErrMapStreamWrite", err)
	}
	if sink.started() || response.Body.Len() != 0 {
		t.Fatal("rejected initial authority withdrawal committed an HTTP response")
	}
}

func decodeMapStreamFrames(t *testing.T, encoded []byte) []tailcfg.MapResponse {
	t.Helper()
	frames := make([]tailcfg.MapResponse, 0, 2)
	for len(encoded) > 0 {
		if len(encoded) < 5 {
			t.Fatalf("map stream has truncated frame header: %d bytes", len(encoded))
		}
		length := int(encoded[0]) |
			int(encoded[1])<<8 |
			int(encoded[2])<<16 |
			int(encoded[3])<<24
		if length <= 0 || length > len(encoded)-4 {
			t.Fatalf("map stream frame length = %d with %d available", length, len(encoded)-4)
		}
		document, err := zstdframe.AppendDecode(
			nil,
			encoded[4:4+length],
			zstdframe.MaxDecodedSize(maxMapResponseBytes),
		)
		if err != nil {
			t.Fatalf("decode map stream frame: %v", err)
		}
		var response tailcfg.MapResponse
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&response); err != nil {
			t.Fatalf("decode map stream document: %v", err)
		}
		frames = append(frames, response)
		encoded = encoded[4+length:]
	}
	return frames
}

func decodeUncompressedMapStreamFrames(t *testing.T, encoded []byte) []tailcfg.MapResponse {
	t.Helper()
	frames := make([]tailcfg.MapResponse, 0, 2)
	for len(encoded) > 0 {
		if len(encoded) < 5 {
			t.Fatalf("map stream has truncated frame header: %d bytes", len(encoded))
		}
		length := int(binary.LittleEndian.Uint32(encoded[:4]))
		if length <= 0 || length > len(encoded)-4 {
			t.Fatalf("map stream frame length = %d with %d available", length, len(encoded)-4)
		}
		var response tailcfg.MapResponse
		decoder := json.NewDecoder(bytes.NewReader(encoded[4 : 4+length]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&response); err != nil {
			t.Fatalf("decode uncompressed map stream document: %v", err)
		}
		frames = append(frames, response)
		encoded = encoded[4+length:]
	}
	return frames
}

type recordingMapStreamService struct {
	snapshot mapsession.Snapshot
	calls    int
	sawValid bool
	sawSink  bool
}

type advancingMapStreamService struct {
	snapshots []mapsession.Snapshot
}

type connectivityDeltaMapStreamService struct {
	initial mapsession.Snapshot
	delta   mapsession.ConnectivityDelta
}

type authorityDeltaMapStreamService struct {
	initial mapsession.Snapshot
	delta   mapsession.AuthorityDelta
}

type authorityWithdrawalMapStreamService struct {
	snapshot mapsession.Snapshot
}

func (service *advancingMapStreamService) Serve(
	ctx context.Context,
	_ control.AuthenticatedMachine,
	_ mapsession.Request,
	sink mapsession.StreamSink,
) error {
	for _, snapshot := range service.snapshots {
		if err := sink.SendSnapshot(ctx, snapshot); err != nil {
			return err
		}
	}
	return context.Canceled
}

func (service *connectivityDeltaMapStreamService) Serve(
	ctx context.Context,
	_ control.AuthenticatedMachine,
	_ mapsession.Request,
	sink mapsession.StreamSink,
) error {
	if err := sink.SendSnapshot(ctx, service.initial); err != nil {
		return err
	}
	if err := sink.SendConnectivityDelta(ctx, service.delta); err != nil {
		return err
	}
	return context.Canceled
}

func (service *authorityDeltaMapStreamService) Serve(
	ctx context.Context,
	_ control.AuthenticatedMachine,
	_ mapsession.Request,
	sink mapsession.StreamSink,
) error {
	if err := sink.SendSnapshot(ctx, service.initial); err != nil {
		return err
	}
	if err := sink.SendAuthorityDelta(ctx, service.delta); err != nil {
		return err
	}
	return context.Canceled
}

func (service *authorityWithdrawalMapStreamService) Serve(
	ctx context.Context,
	_ control.AuthenticatedMachine,
	_ mapsession.Request,
	sink mapsession.StreamSink,
) error {
	if err := sink.SendSnapshot(ctx, service.snapshot); err != nil {
		return err
	}
	if err := sink.SendAuthorityWithdrawal(ctx, service.snapshot); err != nil {
		return err
	}
	return mapsession.ErrUnauthorized
}

func (service *recordingMapStreamService) Serve(
	ctx context.Context,
	machine control.AuthenticatedMachine,
	request mapsession.Request,
	sink mapsession.StreamSink,
) error {
	service.calls++
	service.sawValid = ctx != nil && machine.IsValid() && request.IsValid()
	service.sawSink = sink != nil
	if err := sink.SendSnapshot(ctx, service.snapshot); err != nil {
		return err
	}
	if err := sink.SendKeepAlive(ctx); err != nil {
		return err
	}
	return context.Canceled
}

func TestMapSessionHandlerFailsBeforeCommittingRejectedStream(t *testing.T) {
	t.Parallel()

	snapshot := mapSnapshotFixture(t)
	streams := &failingMapStreamService{err: mapsession.ErrPresenceConflict}
	handler := newMapSessionHandlerWithStreams(
		t,
		&recordingMapSessionService{snapshot: snapshot},
		streams,
	)
	authenticated, err := handler.Handler(authenticatedMachine(t))
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}
	body := strings.Replace(mapRequestBody, `"Stream":false`, `"Stream":true`, 1)
	response := serveMap(t, authenticated, body)
	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), streams.err.Error()) {
		t.Fatalf("rejected stream response = (%d, %q)", response.Code, response.Body.String())
	}
	metrics := gatherControlMetrics(t, handler.telemetry)
	if !strings.Contains(
		metrics,
		`meshtransit_control_map_requests_total{result="coordination_lost"} 1`,
	) {
		t.Fatalf("stream rejection metrics are incomplete: %s", metrics)
	}
}

type failingMapStreamService struct{ err error }

func (service *failingMapStreamService) Serve(
	context.Context,
	control.AuthenticatedMachine,
	mapsession.Request,
	mapsession.StreamSink,
) error {
	if service.err == nil {
		return errors.New("controlled stream failure")
	}
	return service.err
}
