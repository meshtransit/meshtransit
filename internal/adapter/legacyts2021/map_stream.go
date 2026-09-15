package legacyts2021

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
)

// ErrMapStreamWrite classifies a failed framed stream response.
var ErrMapStreamWrite = errors.New("legacyts2021: map stream write failed")

type mapStreamSink struct {
	response          http.ResponseWriter
	capabilityVersion int
	compression       mapResponseCompression
	responseStarted   bool
	hasSnapshot       bool
}

func newMapStreamSink(
	response http.ResponseWriter,
	capabilityVersion int,
	compression mapResponseCompression,
) *mapStreamSink {
	return &mapStreamSink{
		response:          response,
		capabilityVersion: capabilityVersion,
		compression:       compression,
	}
}

func (sink *mapStreamSink) SendSnapshot(ctx context.Context, snapshot mapsession.Snapshot) error {
	if err := sink.validate(ctx); err != nil {
		return err
	}
	encoded, err := encodeFullMapResponse(
		snapshot,
		sink.capabilityVersion,
		sink.compression,
	)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := sink.write(encoded); err != nil {
		return err
	}
	sink.hasSnapshot = true
	return nil
}

func (sink *mapStreamSink) SendConnectivityDelta(
	ctx context.Context,
	delta mapsession.ConnectivityDelta,
) error {
	if err := sink.validate(ctx); err != nil {
		return err
	}
	if !sink.hasSnapshot {
		return ErrMapStreamWrite
	}
	encoded, err := encodeConnectivityDeltaMapResponse(
		delta,
		sink.capabilityVersion,
		sink.compression,
	)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return sink.write(encoded)
}

func (sink *mapStreamSink) SendAuthorityDelta(
	ctx context.Context,
	delta mapsession.AuthorityDelta,
) error {
	if err := sink.validate(ctx); err != nil {
		return err
	}
	if !sink.hasSnapshot {
		return ErrMapStreamWrite
	}
	encoded, err := encodeAuthorityDeltaMapResponse(
		delta,
		sink.capabilityVersion,
		sink.compression,
	)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return sink.write(encoded)
}

func (sink *mapStreamSink) SendKeepAlive(ctx context.Context) error {
	if err := sink.validate(ctx); err != nil {
		return err
	}
	if !sink.hasSnapshot {
		return ErrMapStreamWrite
	}
	encoded, err := encodeKeepAliveMapResponse(sink.compression)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return sink.write(encoded)
}

func (sink *mapStreamSink) validate(ctx context.Context) error {
	if ctx == nil || sink == nil || sink.response == nil ||
		sink.capabilityVersion != supportedCapabilityVersion ||
		sink.compression == mapResponseCompressionInvalid {
		return ErrMapStreamWrite
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrMapStreamWrite, err)
	}
	return nil
}

func (sink *mapStreamSink) write(encoded []byte) error {
	if len(encoded) == 0 {
		return ErrMapStreamWrite
	}
	if !sink.responseStarted {
		sink.response.Header().Set("Content-Type", mapResponseContentType)
		sink.response.WriteHeader(http.StatusOK)
		sink.responseStarted = true
	}
	written, err := sink.response.Write(encoded)
	if err != nil || written != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return errors.Join(ErrMapStreamWrite, err)
	}
	if err := http.NewResponseController(sink.response).Flush(); err != nil {
		return errors.Join(ErrMapStreamWrite, err)
	}
	return nil
}

func (sink *mapStreamSink) started() bool {
	return sink != nil && sink.responseStarted
}

var _ mapsession.StreamSink = (*mapStreamSink)(nil)
