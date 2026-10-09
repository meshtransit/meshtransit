package stream

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/coder/websocket"

	"meshtransit.net/shared/mtrp"
)

var errFrameSize = errors.New("stream: frame length out of range")

// rawFramer carries frames on a TLS connection as `u16 length || frame`
// (mtrp-v1 §1). A zero or oversized length closes the connection.
type rawFramer struct {
	conn         net.Conn
	r            *bufio.Reader
	idle, writes time.Duration
	in           [mtrp.MaxStreamFrame]byte // owned by the reader goroutine
	out          []byte                    // owned by the writer goroutine
}

func newRawFramer(c net.Conn, idle, writes time.Duration) *rawFramer {
	return &rawFramer{conn: c, r: bufio.NewReaderSize(c, mtrp.MaxStreamFrame+2), idle: idle, writes: writes}
}

func (f *rawFramer) ReadFrame() ([]byte, error) {
	buf := f.in[:]
	if err := f.conn.SetReadDeadline(time.Now().Add(f.idle)); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(f.r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > mtrp.MaxStreamFrame || n > len(buf) {
		return nil, errFrameSize
	}
	if _, err := io.ReadFull(f.r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (f *rawFramer) WriteFrame(frame []byte) error {
	if len(frame) == 0 || len(frame) > mtrp.MaxStreamFrame {
		return errFrameSize
	}
	f.out = binary.BigEndian.AppendUint16(f.out[:0], uint16(len(frame))) //nolint:gosec // bounded by MaxStreamFrame
	f.out = append(f.out, frame...)
	if err := f.conn.SetWriteDeadline(time.Now().Add(f.writes)); err != nil {
		return err
	}
	_, err := f.conn.Write(f.out)
	return err
}

func (f *rawFramer) Close() error { return f.conn.Close() }

// wsFramer carries one frame per binary WebSocket message.
type wsFramer struct {
	c            *websocket.Conn
	idle, writes time.Duration
}

func (f *wsFramer) ReadFrame() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), f.idle)
	defer cancel()
	typ, data, err := f.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary || len(data) == 0 || len(data) > mtrp.MaxStreamFrame {
		return nil, errFrameSize
	}
	return data, nil
}

func (f *wsFramer) WriteFrame(frame []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), f.writes)
	defer cancel()
	return f.c.Write(ctx, websocket.MessageBinary, frame)
}

// Close drops the connection without waiting for a close handshake: the
// peer may be gone, and MTRP has its own SESSION_CLOSE.
func (f *wsFramer) Close() error { return f.c.CloseNow() }
