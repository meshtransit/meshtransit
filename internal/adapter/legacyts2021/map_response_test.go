package legacyts2021

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"
)

func TestEncodeFullMapResponseClearsInheritedAuthority(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeFullMapResponse(mapSnapshotFixture(t), 142)
	if err != nil {
		t.Fatalf("EncodeFullMapResponse() error = %v", err)
	}
	if len(encoded) < 5 || int(binary.LittleEndian.Uint32(encoded[:4])) != len(encoded)-4 {
		t.Fatalf("encoded frame length = %d with header %v", len(encoded), encoded[:min(len(encoded), 4)])
	}
	document, err := zstdframe.AppendDecode(nil, encoded[4:], zstdframe.MaxDecodedSize(maxMapResponseBytes))
	if err != nil {
		t.Fatalf("decode zstd map response: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatalf("decode map response fields: %v", err)
	}
	for _, name := range []string{"Node", "Peers", "PacketFilter"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("map response omitted required field %q: %s", name, document)
		}
	}
	if string(fields["Peers"]) != "[]" || string(fields["PacketFilter"]) != "[]" {
		t.Fatalf("map response did not explicitly clear peers and policy: %s", document)
	}

	var response tailcfg.MapResponse
	if err := json.Unmarshal(document, &response); err != nil {
		t.Fatalf("decode typed map response: %v", err)
	}
	if response.Node == nil || response.Node.ID != 701 ||
		string(response.Node.StableID) != "01890f00-0000-7000-8000-000000000701" ||
		response.Node.Name != "node-one.example." || !response.Node.MachineAuthorized ||
		response.Node.Cap != 142 || len(response.Node.Addresses) != 1 ||
		len(response.Node.AllowedIPs) != 1 {
		t.Fatalf("map response Node = %+v, want authoritative self Node", response.Node)
	}
}

func TestEncodeFullMapResponseRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := EncodeFullMapResponse(mapSnapshotFixture(t), 0); err == nil {
		t.Fatal("EncodeFullMapResponse(zero capability) error = nil")
	}
}
