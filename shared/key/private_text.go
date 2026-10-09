package key

import "encoding/hex"

// privatePrefix is the text form of private keys in configuration files
// (keys.md). It is never printed by String, logged or put in URLs.
const privatePrefix = "privkey:"

// ParseRelayPrivateText parses "privkey:<64 lowercase hex>", as written by
// RelayPrivate.PrivateText into a key file with restrictive permissions.
func ParseRelayPrivateText(text string) (RelayPrivate, error) {
	var raw [Size]byte
	defer clear(raw[:])
	if err := parsePublic(privatePrefix, text, raw[:]); err != nil {
		return RelayPrivate{}, err
	}
	return RelayPrivateFromBytes(raw[:])
}

// ParseRelayPrivateBytes is ParseRelayPrivateText for a key file's bytes,
// without making an uncleared string copy of the secret. Surrounding
// whitespace is ignored.
func ParseRelayPrivateBytes(b []byte) (RelayPrivate, error) {
	b = trimSpace(b)
	if len(b) != len(privatePrefix)+2*Size || string(b[:len(privatePrefix)]) != privatePrefix {
		return RelayPrivate{}, ErrInvalid
	}
	var raw [Size]byte
	defer clear(raw[:])
	body := b[len(privatePrefix):]
	for _, c := range body {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return RelayPrivate{}, ErrInvalid
		}
	}
	if _, err := hex.Decode(raw[:], body); err != nil || isZero(raw[:]) {
		return RelayPrivate{}, ErrInvalid
	}
	return RelayPrivateFromBytes(raw[:])
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// PrivateText returns the key file form of k. Callers write it only to a
// file readable by the relay's user; it must never reach logs or output.
func (k RelayPrivate) PrivateText() string {
	if k.private == nil {
		return ""
	}
	raw := k.private.Bytes()
	defer clear(raw)
	return privatePrefix + hex.EncodeToString(raw)
}
