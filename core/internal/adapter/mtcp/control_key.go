package mtcp

import (
	"encoding/hex"
	"errors"
	"strings"

	"meshtransit.net/shared/key"
)

// controlKeyFilePrefix starts the text form of the control key file the
// TS2021 listener already reads; MTCP reuses the same key (P4 decision: no
// re-enrollment), so both protocols answer with one control public key.
const controlKeyFilePrefix = "privkey:"

// ErrInvalidControlKey reports a control key file that is not exactly one
// canonical non-zero key.
var ErrInvalidControlKey = errors.New("mtcp: invalid control key")

// ParseControlKey reads the canonical text form "privkey:" followed by 64
// lowercase hexadecimal digits.
func ParseControlKey(text string) (key.ControlPrivate, error) {
	encoded, found := strings.CutPrefix(text, controlKeyFilePrefix)
	if !found || len(encoded) != 2*key.Size || strings.ToLower(encoded) != encoded {
		return key.ControlPrivate{}, ErrInvalidControlKey
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return key.ControlPrivate{}, ErrInvalidControlKey
	}
	defer clear(raw)
	private, err := key.ControlPrivateFromBytes(raw)
	if err != nil || private.IsZero() || private.Public().IsZero() {
		return key.ControlPrivate{}, ErrInvalidControlKey
	}
	return private, nil
}
