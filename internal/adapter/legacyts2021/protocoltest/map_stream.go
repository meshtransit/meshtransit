//go:build integration

package protocoltest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MapStream owns one authenticated session and streaming response body. Reads
// are single-caller; Close is concurrency-safe and idempotent.
type MapStream struct {
	body    io.ReadCloser
	session *session

	closeOnce sync.Once
	closeErr  error
}

// OpenMapStream opens a streaming request and validates its initial complete snapshot.
func (client *Client) OpenMapStream(
	ctx context.Context,
) (*MapStream, FullMap, error) {
	if ctx == nil || client == nil || client.tlsConfig == nil {
		return nil, FullMap{}, ErrInvalidClient
	}
	controlKey, err := client.discoverControlKey(ctx)
	if err != nil {
		return nil, FullMap{}, errors.Join(ErrMap, err)
	}
	protocolSession, err := client.openSession(ctx, controlKey)
	if err != nil {
		return nil, FullMap{}, errors.Join(ErrMap, err)
	}
	response, err := client.requestMap(ctx, protocolSession, true)
	if err != nil {
		return nil, FullMap{}, errors.Join(ErrMap, err, protocolSession.Close())
	}
	if err := validateMapResponse(response); err != nil {
		var bodyErr error
		if response != nil && response.Body != nil {
			bodyErr = response.Body.Close()
		}
		return nil, FullMap{}, errors.Join(ErrMap, err, bodyErr, protocolSession.Close())
	}
	stream := &MapStream{body: response.Body, session: protocolSession}
	initial, err := stream.NextFullMap()
	if err != nil {
		return nil, FullMap{}, errors.Join(ErrMap, err, stream.Close())
	}
	return stream, initial, nil
}

// FetchInitialStreamMap validates one initial snapshot and immediately closes
// its HTTP/2 stream and authenticated session.
func (client *Client) FetchInitialStreamMap(ctx context.Context) (_ FullMap, resultErr error) {
	stream, initial, err := client.OpenMapStream(ctx)
	if err != nil {
		return FullMap{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, stream.Close()) }()
	return initial, nil
}

// NextFullMap reads and validates exactly one complete framed snapshot.
func (stream *MapStream) NextFullMap() (FullMap, error) {
	if stream == nil || stream.body == nil || stream.session == nil {
		return FullMap{}, ErrInvalidClient
	}
	frame, err := readMapFrame(stream.body)
	if err != nil {
		return FullMap{}, fmt.Errorf("read stream map: %w", err)
	}
	defer clear(frame)
	return decodeFullMap(frame)
}

// Close releases the response body and authenticated session exactly once.
func (stream *MapStream) Close() error {
	if stream == nil {
		return nil
	}
	stream.closeOnce.Do(func() {
		var bodyErr, sessionErr error
		if stream.body != nil {
			bodyErr = stream.body.Close()
		}
		if stream.session != nil {
			sessionErr = stream.session.Close()
		}
		stream.closeErr = errors.Join(bodyErr, sessionErr)
	})
	return stream.closeErr
}
