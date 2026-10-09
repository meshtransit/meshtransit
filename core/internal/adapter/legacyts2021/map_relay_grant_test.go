package legacyts2021

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/shared/mtrp"
)

func TestRelayGrantRidesOnSelfNode(t *testing.T) {
	t.Parallel()

	current, _, _ := mapConnectivityDeltaSnapshotsFixture(t)
	payload := []byte(`{"version":1,"ticket":"AA=="}`)
	grant, err := mapsession.NewRelayGrant(mapsession.RelayGrantRequest{}, payload, time.Now().Add(15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	granted := current.WithRelayGrant(grant)

	self, err := fullMapNode(granted, supportedCapabilityVersion)
	if err != nil {
		t.Fatal(err)
	}
	values := self.CapMap[tailcfg.NodeCapability(mtrp.InterchangeCapability)]
	if len(values) != 1 || string(values[0]) != string(payload) {
		t.Fatalf("self CapMap = %v", self.CapMap)
	}
	if plain, err := fullMapNode(current, supportedCapabilityVersion); err != nil || plain.CapMap != nil {
		t.Fatalf("node without a grant carries CapMap %v (%v)", plain.CapMap, err)
	}

	encoded, err := encodeRelayGrantMapResponse(granted, supportedCapabilityVersion, mapResponseCompressionZstd)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < 5 || int(binary.LittleEndian.Uint32(encoded[:4])) != len(encoded)-4 {
		t.Fatalf("frame length = %d", len(encoded))
	}
	document, err := zstdframe.AppendDecode(nil, encoded[4:], zstdframe.MaxDecodedSize(maxMapResponseBytes))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(document, &fields); err != nil || len(fields) != 1 || fields["Node"] == nil {
		t.Fatalf("grant-only response fields = %v (%v)", fields, err)
	}
	if _, err := encodeRelayGrantMapResponse(current, supportedCapabilityVersion, mapResponseCompressionZstd); err == nil {
		t.Fatal("encoded a grant-only response without a grant")
	}
}
