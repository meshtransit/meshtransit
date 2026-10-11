package mtcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// AppendRecord appends one stream record: u16 length (type and body), type,
// body (mtcp-v1 §4.1).
func AppendRecord(dst []byte, t RecordType, body []byte) ([]byte, error) {
	if err := checkRecord(t, len(body)); err != nil {
		return nil, err
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(1+len(body))) //nolint:gosec // bounded by checkRecord
	dst = append(dst, byte(t))
	return append(dst, body...), nil
}

// AppendMessageRecord appends one WebSocket record: type, body (no length).
func AppendMessageRecord(dst []byte, t RecordType, body []byte) ([]byte, error) {
	if err := checkRecord(t, len(body)); err != nil {
		return nil, err
	}
	dst = append(dst, byte(t))
	return append(dst, body...), nil
}

// ParseMessageRecord splits one WebSocket binary message into its type and
// body. The body aliases message.
func ParseMessageRecord(message []byte) (RecordType, []byte, error) {
	if len(message) == 0 {
		return 0, nil, ErrMalformed
	}
	t := RecordType(message[0])
	if err := checkRecord(t, len(message)-1); err != nil {
		return 0, nil, err
	}
	return t, message[1:], nil
}

func checkRecord(t RecordType, bodyLength int) error {
	switch t {
	case RecordInit, RecordResponse:
		if bodyLength > MaxHandshakeRecord {
			return ErrTooLarge
		}
	case RecordTransport:
		if bodyLength > MaxRecord-1 {
			return ErrTooLarge
		}
	default:
		return ErrMalformed
	}
	if bodyLength == 0 {
		return ErrMalformed
	}
	return nil
}

// RecordReader reads stream records. It allocates one buffer of MaxRecord
// bytes; the body returned by Next is valid until the following call.
type RecordReader struct {
	r   io.Reader
	buf []byte
}

// initialRecordBuffer fits every record an idle session exchanges (pings,
// acknowledgements, endpoint reports); the buffer grows to a larger record
// only when one arrives, so a server holding many idle sessions does not
// keep MaxRecord bytes for each.
const initialRecordBuffer = 1024

// NewRecordReader reads records from r.
func NewRecordReader(r io.Reader) *RecordReader {
	return &RecordReader{r: r, buf: make([]byte, initialRecordBuffer)}
}

// Next reads one record. A malformed or oversized record is an error, after
// which the stream must be closed.
func (rr *RecordReader) Next() (RecordType, []byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(rr.r, length[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n == 0 {
		return 0, nil, ErrMalformed
	}
	if n > len(rr.buf) {
		// Grow by doubling (bounded by MaxRecord): a peer sending large
		// records reallocates a few times, not on every record.
		size := len(rr.buf)
		for size < n {
			size *= 2
		}
		rr.buf = make([]byte, min(size, MaxRecord))
	}
	if _, err := io.ReadFull(rr.r, rr.buf[:n]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, fmt.Errorf("mtcp: read record: %w", err)
	}
	t := RecordType(rr.buf[0])
	if err := checkRecord(t, n-1); err != nil {
		return 0, nil, err
	}
	return t, rr.buf[1:n], nil
}
