package ts2021

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

//go:embed testdata/core_direct_sharing/*.json
var coreDirectSharingFixtures embed.FS

func TestCoreDirectSharingFramesPreserveDirectionAndBoundedPeers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		policyCount int
	}{
		{"provider-full", 1}, {"consumer-full", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			accumulator := newMapAccumulator()
			snapshot, changed, err := accumulator.apply(coreDirectSharingFrame(t, test.name), coreDirectSharingTime())
			if err != nil || !changed {
				t.Fatalf("Core frame apply: changed=%t, err=%v", changed, err)
			}
			if len(snapshot.Peers) != 1 || len(snapshot.Policy) != test.policyCount {
				t.Fatal("sharing direction changed in client decoder")
			}
			peer := snapshot.Peers[0]
			if !peer.KeyExpiry.Equal(coreDirectSharingTime().Add(30*time.Minute)) ||
				len(peer.Addresses) != 2 || !slices.Equal(peer.Addresses, peer.AllowedIPs) {
				t.Fatal("client widened host routes or sharing deadline")
			}
			if len(snapshot.Policy) != 0 && !slices.Equal(snapshot.Policy[0].Protocols, []uint8{1, 58}) {
				t.Fatal("dual-stack ICMP translation changed")
			}
		})
	}
}

func TestCoreDirectSharingFramesClearPeerAndPolicyAtomically(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"provider-removed-full", "provider-removed-delta"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			accumulator := newMapAccumulator()
			if _, _, err := accumulator.apply(coreDirectSharingFrame(t, "provider-full"), coreDirectSharingTime()); err != nil {
				t.Fatal(err)
			}
			snapshot, changed, err := accumulator.apply(coreDirectSharingFrame(t, name), coreDirectSharingTime())
			if err != nil || !changed || len(snapshot.Peers) != 0 || len(snapshot.Policy) != 0 {
				t.Fatalf("withdrawal: changed=%t, peers=%d, policy=%d, err=%v", changed, len(snapshot.Peers), len(snapshot.Policy), err)
			}
		})
	}
}

func TestCoreDirectSharingTerminalFrameRevokesSelf(t *testing.T) {
	t.Parallel()
	accumulator := newMapAccumulator()
	if _, _, err := accumulator.apply(coreDirectSharingFrame(t, "provider-full"), coreDirectSharingTime()); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := accumulator.apply(coreDirectSharingFrame(t, "provider-terminal-withdrawal"), coreDirectSharingTime()); changed || !errors.Is(err, ErrNetmapAuthorityRevoked) {
		t.Fatalf("terminal sharing frame: changed=%t, err=%v", changed, err)
	}
}

func coreDirectSharingFrame(t *testing.T, name string) tailcfg.MapResponse {
	t.Helper()
	document, err := coreDirectSharingFixtures.ReadFile("testdata/core_direct_sharing/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var response tailcfg.MapResponse
	if err := json.Unmarshal(document, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func coreDirectSharingTime() time.Time {
	return time.Date(2026, time.September, 14, 4, 0, 0, 0, time.UTC)
}

func TestCoreDirectSharingFixtureProvenance(t *testing.T) {
	t.Parallel()
	document, err := coreDirectSharingFixtures.ReadFile("testdata/core_direct_sharing/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		SourceRepository  string            `json:"source_repository"`
		SourceRevision    string            `json:"source_revision"`
		CapabilityVersion int               `json:"capability_version"`
		Files             map[string]string `json:"files"`
	}
	if err := json.Unmarshal(document, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SourceRepository != "https://github.com/meshtransit/meshtransit.git" ||
		manifest.SourceRevision != "368122f9b3d74ce68e94e1feec8666b0e3d2b362" || manifest.CapabilityVersion != 142 || len(manifest.Files) != 5 {
		t.Fatal("Core fixture producer changed without qualification")
	}
	for name, expected := range manifest.Files {
		document, err := coreDirectSharingFixtures.ReadFile("testdata/core_direct_sharing/" + name)
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(document)
		if hex.EncodeToString(actual[:]) != expected {
			t.Fatalf("Core fixture digest mismatch: %s", name)
		}
	}
}
