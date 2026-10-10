package ts2021

import (
	"testing"

	"tailscale.com/types/key"

	"meshtransit.net/client/internal/controlplane"
)

// Profiles move between TS2021 and MTCP without registering again: the
// protocol-neutral key helpers must read and pin the same keys.
func TestControlplaneKeysMatchTS2021(t *testing.T) {
	t.Parallel()
	for range 16 {
		control := key.NewMachine().Public()
		text, err := control.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := controlplane.ParseControlPublicKey(text)
		if err != nil || controlplane.ControlKeyFingerprint(raw) != controlKeyFingerprint(control) {
			t.Fatalf("fingerprints differ: %v", err)
		}
		generated, err := controlplane.GenerateNodePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		var nodeKey key.NodePrivate
		if err := nodeKey.UnmarshalText(generated); err != nil {
			t.Fatalf("TS2021 cannot read a generated node key: %v", err)
		}
		parsed, err := controlplane.NodePrivateRaw(controlplane.KeyMaterial{NodePrivateKey: generated})
		if err != nil || parsed != nodeKey.Raw32() {
			t.Fatalf("node key bytes differ: %v", err)
		}
	}
}
