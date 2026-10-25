// Package kubejoin computes the code that ties a Kubernetes gateway
// replica's request to join a cluster to the replica that made it (K1a1
// plan §4.2). Core computes it from the keys it received, the replica from
// its own keys; the replica prints it and an administrator types it to
// approve. A request made with other keys has another code, so an
// administrator who reads the code from the real pod cannot approve an
// impostor by mistake.
//
// The code is a fingerprint, not a secret: anyone may read it. It protects
// an honest administrator from approving the wrong request; it does not
// stop one who approves without looking.
//
// The package is pure computation; it performs no I/O.
package kubejoin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrInvalid reports missing inputs or text that is not a code.
var ErrInvalid = errors.New("kubejoin: invalid")

const (
	label = "meshtransit/kube-join-code/v1"
	// Length is a code's characters, without the hyphen: 50 bits.
	Length = 10
)

// Inputs are what the code binds: the replica's machine and node keys, the
// cluster's public ID and the nonce Core chose for the request.
type Inputs struct {
	MachineKey   [32]byte
	NodeKey      [32]byte
	ClusterID    [16]byte
	RequestNonce [32]byte
}

// Code is one join code, ten base32 characters.
type Code struct {
	text string
}

// Compute derives the code:
//
//	digest = SHA-256(label || 0x00 || machine key || node key || cluster ID || nonce)
//	code   = the first 50 bits of digest in RFC 4648 base32, upper case
//
// Every input must be non-zero.
func Compute(inputs Inputs) (Code, error) {
	if inputs.MachineKey == ([32]byte{}) || inputs.NodeKey == ([32]byte{}) ||
		inputs.ClusterID == ([16]byte{}) || inputs.RequestNonce == ([32]byte{}) {
		return Code{}, ErrInvalid
	}
	hash := sha256.New()
	hash.Write([]byte(label))
	hash.Write([]byte{0})
	hash.Write(inputs.MachineKey[:])
	hash.Write(inputs.NodeKey[:])
	hash.Write(inputs.ClusterID[:])
	hash.Write(inputs.RequestNonce[:])
	digest := hash.Sum(nil)
	return Code{text: base32.StdEncoding.EncodeToString(digest)[:Length]}, nil
}

// Parse reads a code as a person typed it: case, spaces and hyphens are
// ignored; the rest must be ten characters of the base32 alphabet.
func Parse(typed string) (Code, error) {
	compact := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(typed))
	if len(compact) != Length {
		return Code{}, ErrInvalid
	}
	for index := range len(compact) {
		character := compact[index]
		if (character < 'A' || character > 'Z') && (character < '2' || character > '7') {
			return Code{}, ErrInvalid
		}
	}
	return Code{text: compact}, nil
}

// String returns the code as it is printed, "XXXXX-XXXXX", or empty for
// the zero Code.
func (code Code) String() string {
	if len(code.text) != Length {
		return ""
	}
	return code.text[:Length/2] + "-" + code.text[Length/2:]
}

// Equal compares two codes in constant time; the zero Code equals nothing.
func (code Code) Equal(other Code) bool {
	if len(code.text) != Length || len(other.text) != Length {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(code.text), []byte(other.text)) == 1
}

// Bits returns the code's 50 bits as an integer, first character in the
// highest bits: the value Core's database compares (bytes 0 to 5 of the
// digest and the top two bits of byte 6). The zero Code has no bits.
func (code Code) Bits() (uint64, bool) {
	if len(code.text) != Length {
		return 0, false
	}
	var bits uint64
	for index := range Length {
		character := code.text[index]
		var value byte
		if character >= 'A' && character <= 'Z' {
			value = character - 'A'
		} else {
			value = character - '2' + 26
		}
		bits = bits<<5 | uint64(value)
	}
	return bits, true
}

// ErrInvalidClusterID reports a cluster ID that is not a canonical UUIDv7.
var ErrInvalidClusterID = errors.New("kubejoin: invalid cluster ID")

// ParseClusterID reads a cluster's public ID as Core sends it: a canonical
// lowercase UUIDv7.
func ParseClusterID(value string) ([16]byte, error) {
	var id [16]byte
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return id, ErrInvalidClusterID
	}
	digits := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36]
	for _, r := range digits {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return id, ErrInvalidClusterID
		}
	}
	if _, err := hex.Decode(id[:], []byte(digits)); err != nil || id[6]>>4 != 7 || id[8]>>6 != 2 {
		return [16]byte{}, ErrInvalidClusterID
	}
	return id, nil
}
