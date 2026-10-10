// Package mtcp serves MTCP v1 (docs/protocol/mtcp-v1.md), the MeshTransit
// control protocol, on Core's control listener: control key discovery, the
// HTTP upgrade and its WebSocket fallback, admission before any Noise work,
// the Noise handshake, established sessions and their messages. Protocol
// codecs live in shared/mtcp; this package translates sessions into the
// protocol-independent map session application.
package mtcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"

	sharedmtcp "meshtransit.net/shared/mtcp"
)

// recordConn carries MTCP records over one transport. ReadRecord's body is
// valid until the next call; WriteRecord is safe for concurrent use.
type recordConn interface {
	ReadRecord(deadline time.Time) (sharedmtcp.RecordType, []byte, error)
	WriteRecord(t sharedmtcp.RecordType, body []byte, deadline time.Time) error
	Close() error
}

// streamConn is an upgraded HTTP/1.1 connection carrying length-prefixed
// records.
type streamConn struct {
	conn    net.Conn
	reader  *sharedmtcp.RecordReader
	writeMu sync.Mutex
	buf     []byte
}

func newStreamConn(conn net.Conn, buffered *bufio.Reader) *streamConn {
	var source io.Reader = conn
	if buffered != nil {
		source = buffered
	}
	return &streamConn{conn: conn, reader: sharedmtcp.NewRecordReader(source)}
}

func (c *streamConn) ReadRecord(deadline time.Time) (sharedmtcp.RecordType, []byte, error) {
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return 0, nil, err
	}
	return c.reader.Next()
}

func (c *streamConn) WriteRecord(t sharedmtcp.RecordType, body []byte, deadline time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	record, err := sharedmtcp.AppendRecord(c.buf[:0], t, body)
	if err != nil {
		return err
	}
	c.buf = record
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err = c.conn.Write(record)
	return err
}

func (c *streamConn) Close() error { return c.conn.Close() }

// webSocketConn carries one record per binary message (mtcp-v1 §2.3).
type webSocketConn struct {
	conn    *websocket.Conn
	ctx     context.Context
	writeMu sync.Mutex
	buf     []byte
}

func (c *webSocketConn) ReadRecord(deadline time.Time) (sharedmtcp.RecordType, []byte, error) {
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	defer cancel()
	kind, message, err := c.conn.Read(ctx)
	if err != nil {
		return 0, nil, err
	}
	if kind != websocket.MessageBinary {
		return 0, nil, errors.New("mtcp: text message on the WebSocket fallback")
	}
	return sharedmtcp.ParseMessageRecord(message)
}

func (c *webSocketConn) WriteRecord(t sharedmtcp.RecordType, body []byte, deadline time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	message, err := sharedmtcp.AppendMessageRecord(c.buf[:0], t, body)
	if err != nil {
		return err
	}
	c.buf = message
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageBinary, message)
}

func (c *webSocketConn) Close() error { return c.conn.CloseNow() }
