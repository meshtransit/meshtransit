// Package publicid owns the canonical UUIDv7 representation used for public
// MeshTransit identities. Domain packages wrap ID in distinct named types so
// identifiers from different trust boundaries cannot be exchanged by mistake.
package publicid

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	// ErrInvalid reports an absent or non-canonical UUIDv7 value.
	ErrInvalid = errors.New("publicid: invalid uuidv7")
	// ErrTimeOutOfRange reports a timestamp that cannot be represented by UUIDv7.
	ErrTimeOutOfRange = errors.New("publicid: timestamp out of range")
)

// ID is the validated binary representation of a canonical UUIDv7 public ID.
// Its zero value is invalid.
type ID [16]byte

// New creates a UUIDv7 public ID using the current UTC time and operating-system
// cryptographic entropy.
func New() (ID, error) {
	return newAt(time.Now().UTC(), rand.Reader)
}

// FromBytes validates and returns a UUIDv7 public ID.
func FromBytes(value [16]byte) (ID, error) {
	id := ID(value)
	if !id.IsValid() {
		return ID{}, ErrInvalid
	}
	return id, nil
}

// Parse validates a lowercase canonical UUIDv7 string.
func Parse(value string) (ID, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' ||
		value[18] != '-' || value[23] != '-' {
		return ID{}, ErrInvalid
	}

	var encoded [32]byte
	encodedIndex := 0
	for index := range len(value) {
		switch index {
		case 8, 13, 18, 23:
			continue
		}
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return ID{}, ErrInvalid
		}
		encoded[encodedIndex] = character
		encodedIndex++
	}

	var raw [16]byte
	if _, err := hex.Decode(raw[:], encoded[:]); err != nil {
		return ID{}, ErrInvalid
	}
	return FromBytes(raw)
}

// Bytes returns a copy of the binary UUID representation.
func (id ID) Bytes() [16]byte {
	return [16]byte(id)
}

// String returns the lowercase canonical UUID representation.
func (id ID) String() string {
	var encoded [36]byte
	hex.Encode(encoded[0:8], id[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], id[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], id[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], id[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], id[10:16])
	return string(encoded[:])
}

// IsValid reports whether the ID has the UUIDv7 version and RFC 4122 variant.
func (id ID) IsValid() bool {
	return id[6]>>4 == 7 && id[8]&0xc0 == 0x80
}

func newAt(timestamp time.Time, entropy io.Reader) (ID, error) {
	milliseconds := timestamp.UnixMilli()
	if milliseconds < 0 || milliseconds > 1<<48-1 {
		return ID{}, ErrTimeOutOfRange
	}

	var id ID
	if _, err := io.ReadFull(entropy, id[6:]); err != nil {
		return ID{}, fmt.Errorf("generate public id entropy: %w", err)
	}
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], uint64(milliseconds))
	copy(id[0:6], timestampBytes[2:])
	id[6] = id[6]&0x0f | 0x70
	id[8] = id[8]&0x3f | 0x80
	return id, nil
}
