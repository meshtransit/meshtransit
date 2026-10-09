// Package wire holds the checked integer conversions shared by the protocol
// codecs. Every conversion between Go integers and fixed-width wire fields
// goes through here, so range checks live in one audited place.
package wire

import (
	"encoding/binary"
	"math"
)

// AppendMillis appends a non-negative Unix-millisecond time as a u64.
func AppendMillis(dst []byte, ms int64) ([]byte, bool) {
	if ms < 0 {
		return dst, false
	}
	return binary.BigEndian.AppendUint64(dst, uint64(ms)), true
}

// Millis reads a u64 Unix-millisecond time; values above MaxInt64 are invalid.
func Millis(b []byte) (int64, bool) {
	if len(b) < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(b)
	if v > math.MaxInt64 {
		return 0, false
	}
	return int64(v), true
}

// Len8 converts a length to a u8 field.
func Len8(n int) (byte, bool) {
	if n < 0 || n > math.MaxUint8 {
		return 0, false
	}
	return byte(n), true
}

// Len16 converts a length to a u16 field.
func Len16(n int) (uint16, bool) {
	if n < 0 || n > math.MaxUint16 {
		return 0, false
	}
	return uint16(n), true
}
