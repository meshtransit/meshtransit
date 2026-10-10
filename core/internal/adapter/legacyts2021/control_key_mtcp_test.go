package legacyts2021

import (
	"encoding/hex"
	"testing"

	"tailscale.com/types/key"

	"meshtransit.net/core/internal/adapter/mtcp"
)

// MTCP reuses the TS2021 control key file: both protocols must derive the
// same control public key from it, so a node migrating between them pins
// one key.
func TestControlKeyFileGivesMTCPTheSamePublicKey(t *testing.T) {
	t.Parallel()
	for range 16 {
		legacy := key.NewMachine()
		text, err := legacy.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseControlPrivateKey(string(text)); err != nil {
			t.Fatal(err)
		}
		private, err := mtcp.ParseControlKey(string(text))
		if err != nil {
			t.Fatal(err)
		}
		public := private.Public()
		legacyPublic, err := legacy.Public().MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if "mkey:"+hex.EncodeToString(public[:]) != string(legacyPublic) {
			t.Fatal("MTCP derived a different control public key from the TS2021 key file")
		}
	}
}
