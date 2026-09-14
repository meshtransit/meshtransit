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
	responseStarted   bool
}

func newMapStreamSink(response http.ResponseWriter, capabilityVersion int) *mapStreamSink {
	return &mapStreamSink{response: response, capabilityVersion: capabilityVersion}
}

func (sink *mapStreamSink) SendSnapshot(ctx context.Context, snapshot mapsession.Snapshot) error {
	if err := sink.validate(ctx); err != nil {
		return err
	}
	encoded, err := EncodeFullMapResponse(snapshot, sink.capabilityVersion)
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
	encoded, err := EncodeKeepAliveMapResponse()
	if err != nil {
		return err
	}
	defer clear(encoded)
	return sink.write(encoded)
}

func (sink *mapStreamSink) validate(ctx context.Context) error {
	if ctx == nil || sink == nil || sink.response == nil ||
		sink.capabilityVersion != supportedCapabilityVersion {
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
